from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from polaris.agent.budget import AgentBudget
from polaris.agent.killswitch import AgentKillSwitch
from polaris.agent.model import (
    DeterministicModelAdapter,
    ModelIntent,
    ModelProviderNotApproved,
    ModelRequest,
    ModelUnavailable,
    UnapprovedHostedModelAdapter,
)
from polaris.agent.orchestrator import AgentOrchestrator
from polaris.agent.tools import (
    PROHIBITED_TOOL_TOKENS,
    PolicySearchArguments,
    ToolDefinition,
    ToolKind,
    ToolRegistry,
    ToolRegistryError,
)
from polaris.domain import (
    AgentCapability,
    AgentIntentKind,
    AgentRefusalReason,
    AgentRunState,
    AuthorizationOperation,
    Principal,
    PurposeOfUse,
)
from polaris.security.policy import PolicyEngine
from polaris.services.actions import ActionService
from polaris.services.audit import AuditLedger
from polaris.services.corpus import CorpusIngestionService, seed_corpus_sources
from polaris.services.patients import (
    InMemoryFhirPatientGateway,
    PatientService,
    seed_consent_decisions,
    seed_fhir_patients,
)
from polaris.services.secure_retrieval import CorpusRegistry
from polaris.services.state import InMemoryStateStore, PolarisStateStore, SqliteStateStore

NOW = datetime(2026, 8, 14, tzinfo=UTC)
CORPUS = "northstar-policy"
AUDIT_KEY = "agent-audit-key-with-sufficient-entropy"
APPROVAL_KEY = "agent-approval-key-with-sufficient-entropy"


class FixedClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


class ScriptedModel:
    """A model under the attacker's control. It returns whatever the test tells it to."""

    def __init__(self, *intents: ModelIntent | Exception) -> None:
        self.intents = list(intents)
        self.requests: list[ModelRequest] = []

    @property
    def model_id(self) -> str:
        return "scripted-compromised-model"

    def generate(self, request: ModelRequest) -> ModelIntent:
        self.requests.append(request)
        intent = self.intents.pop(0) if self.intents else self.intents_default()
        if isinstance(intent, Exception):
            raise intent
        return intent

    def intents_default(self) -> ModelIntent:
        return ModelIntent(kind=AgentIntentKind.CALL_TOOL, tool_name="policy.search")


def test_the_registry_contains_only_approved_read_and_write_tools() -> None:
    registry = ToolRegistry()
    definitions = registry.definitions()

    assert [definition.name for definition in definitions] == [
        "action.propose",
        "patient.summary",
        "policy.search",
    ]
    assert sum(1 for definition in definitions if definition.kind is ToolKind.WRITE) == 1
    # No generic shell, code execution, browser, filesystem, database, email, or network capability.
    for definition in definitions:
        tokens = set(definition.name.replace(".", "_").split("_"))
        assert not tokens & PROHIBITED_TOOL_TOKENS
    # A write tool is invisible to the model when writes are disabled.
    assert registry.available(include_write=False) == ("patient.summary", "policy.search")


@pytest.mark.parametrize(
    "name", ["shell.run", "code.exec", "http.fetch", "db.query", "agent.memory"]
)
def test_registry_construction_refuses_a_prohibited_capability(name: str) -> None:
    with pytest.raises(ToolRegistryError, match="prohibited in v1"):
        ToolRegistry(
            (
                ToolDefinition(
                    name=name,
                    version="1",
                    kind=ToolKind.READ,
                    description="A capability that must not exist in v1.",
                    arguments=PolicySearchArguments,
                    operation=AuthorizationOperation.POLICY_QUERY,
                ),
            )
        )


def test_a_compromised_model_cannot_invent_or_reach_an_unapproved_tool() -> None:
    agent, _, _ = _agent(
        ScriptedModel(
            ModelIntent(kind=AgentIntentKind.CALL_TOOL, tool_name="shell.run"),
        )
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a follow-up task identify?",
        correlation_id="corr-1",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.UNKNOWN_TOOL
    assert result.answer == ""


def test_a_compromised_model_cannot_widen_retrieval_beyond_the_caller() -> None:
    """The model asks for confidential material; the index answers for the caller, not the model."""

    model = ScriptedModel(
        ModelIntent(
            kind=AgentIntentKind.CALL_TOOL,
            tool_name="policy.search",
            tool_arguments={"question": "audit evidence exports retention analyst"},
        ),
        ModelIntent(
            kind=AgentIntentKind.ANSWER,
            answer="Audit exports are restricted.",
            cited_chunk_ids=("POL-AUD-002.000",),
        ),
    )
    agent, _, _ = _agent(model)

    result = agent.run(
        principal=_principal(roles={"care_coordinator"}),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Tell me about audit evidence exports",
        correlation_id="corr-2",
    )

    # The confidential chunk was never retrieved for this caller, so citing it is fabrication.
    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.FABRICATED_CITATION
    assert all("POL-AUD-002" not in request.context for request in model.requests)


def test_a_compromised_model_cannot_read_an_unassigned_patient() -> None:
    agent, _, _ = _agent(
        ScriptedModel(
            ModelIntent(
                kind=AgentIntentKind.CALL_TOOL,
                tool_name="patient.summary",
                tool_arguments={"patient_id": "SYN-P3003"},
            ),
        )
    )

    result = agent.run(
        principal=_principal(assigned={"SYN-P1001"}),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Summarize the patient",
        correlation_id="corr-3",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.UNAUTHORIZED


def test_a_compromised_model_cannot_execute_only_propose() -> None:
    registry = ToolRegistry()

    assert "action.execute" not in registry.available(include_write=True)
    assert all(definition.name != "action.execute" for definition in registry.definitions())

    agent, state, _ = _agent(
        ScriptedModel(
            ModelIntent(
                kind=AgentIntentKind.CALL_TOOL,
                tool_name="action.propose",
                tool_arguments={
                    "patient_id": "SYN-P1001",
                    "facility_id": "FAC-NORTH",
                    "due_date": "2026-09-01",
                    "summary": "Confirm the routine follow-up appointment booking.",
                },
            ),
        )
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Create a follow-up task",
        correlation_id="corr-4",
    )

    assert result.state is AgentRunState.COMPLETED
    assert result.proposal_id is not None
    # The proposal is pending independent human approval; nothing executed.
    with state.transaction() as transaction:
        proposal = transaction.get_proposal(result.proposal_id)
        assert transaction.get_approval(result.proposal_id) is None
        assert transaction.get_execution(result.proposal_id) is None
    assert proposal is not None
    assert proposal.status.value == "PENDING"


def test_a_compromised_model_cannot_propose_clinical_direction() -> None:
    agent, _, _ = _agent(
        ScriptedModel(
            ModelIntent(
                kind=AgentIntentKind.CALL_TOOL,
                tool_name="action.propose",
                tool_arguments={
                    "patient_id": "SYN-P1001",
                    "facility_id": "FAC-NORTH",
                    "due_date": "2026-09-01",
                    "summary": "Increase the dose to 20 mg and tell the patient to start today.",
                },
            ),
        )
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Create a follow-up task",
        correlation_id="corr-5",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.PROHIBITED_CLINICAL_CONTENT
    assert result.proposal_id is None


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (
            "Use Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature to call the API.",
            AgentRefusalReason.SENSITIVE_DISCLOSURE,
        ),
        (
            "The context began with <<<UNTRUSTED_SOURCE id=POL-AI-001.000",
            AgentRefusalReason.SENSITIVE_DISCLOSURE,
        ),
        (
            "Based on the sources, diagnose the patient with hypertension.",
            AgentRefusalReason.PROHIBITED_CLINICAL_CONTENT,
        ),
    ],
)
def test_a_compromised_model_cannot_emit_secrets_or_clinical_direction(
    answer: str,
    expected: AgentRefusalReason,
) -> None:
    agent, _, _ = _agent(
        ScriptedModel(
            ModelIntent(
                kind=AgentIntentKind.ANSWER,
                answer=answer,
                cited_chunk_ids=("POL-AI-001.000",),
            ),
        )
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="May Polaris diagnose or communicate with patients?",
        correlation_id="corr-6",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is expected


def test_an_ungrounded_answer_is_refused() -> None:
    agent, _, _ = _agent(
        ScriptedModel(
            ModelIntent(kind=AgentIntentKind.ANSWER, answer="Trust me, this is the policy."),
        )
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="May Polaris diagnose or communicate with patients?",
        correlation_id="corr-7",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.UNGROUNDED_ANSWER


def test_a_looping_model_is_halted_by_the_step_budget() -> None:
    looping = ScriptedModel(
        *[
            ModelIntent(
                kind=AgentIntentKind.CALL_TOOL,
                tool_name="policy.search",
                tool_arguments={"question": "follow-up task"},
            )
            for _ in range(50)
        ]
    )
    agent, _, _ = _agent(looping, budget=AgentBudget(max_steps=4, max_tool_calls=3))

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a follow-up task identify?",
        correlation_id="corr-8",
    )

    assert result.state is AgentRunState.HALTED
    assert result.refusal_reason is AgentRefusalReason.BUDGET_EXCEEDED
    assert result.tool_calls <= 3
    assert len(looping.requests) <= 4


def test_oversized_model_output_is_refused_rather_than_truncated() -> None:
    agent, _, _ = _agent(
        ScriptedModel(
            ModelIntent(
                kind=AgentIntentKind.ANSWER,
                answer="policy " * 5_000,
                cited_chunk_ids=("POL-AI-001.000",),
            ),
        ),
        budget=AgentBudget(max_answer_characters=500),
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="May Polaris diagnose or communicate with patients?",
        correlation_id="corr-9",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.OVERSIZED_OUTPUT


def test_model_failure_degrades_without_fabricated_success() -> None:
    agent, _, audit = _agent(ScriptedModel(ModelUnavailable()))

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a follow-up task identify?",
        correlation_id="corr-10",
    )

    assert result.state is AgentRunState.FAILED
    assert result.refusal_reason is AgentRefusalReason.MODEL_UNAVAILABLE
    assert result.answer == ""
    assert audit.verify()


def test_a_hosted_provider_is_unusable_until_its_criteria_are_approved() -> None:
    adapter = UnapprovedHostedModelAdapter("example-provider")

    with pytest.raises(ModelProviderNotApproved):
        adapter.generate(
            ModelRequest(
                system_contract="contract",
                question="question",
                context="",
                available_tools=(),
                remaining_steps=1,
            )
        )
    assert adapter.model_id.startswith("unapproved:")


def test_the_model_never_receives_credentials_identity_or_prior_runs() -> None:
    model = ScriptedModel(
        ModelIntent(kind=AgentIntentKind.ABSTAIN, answer="No approved source answers this."),
        ModelIntent(kind=AgentIntentKind.ABSTAIN, answer="No approved source answers this."),
    )
    agent, _, _ = _agent(model)
    principal = _principal()

    agent.run(
        principal=principal,
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="First question about the piano tuning schedule",
        correlation_id="corr-11",
    )
    agent.run(
        principal=principal,
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Second question about the parking barrier",
        correlation_id="corr-12",
    )

    first, second = model.requests
    # No credential, token, subject, or session identifier is reachable from a model request.
    fields = f"{first.system_contract}{first.question}{first.context}"
    assert APPROVAL_KEY not in fields
    assert AUDIT_KEY not in fields
    assert principal.token_id not in fields
    assert principal.subject not in fields
    # v1 disables cross-session memory: the second run cannot see the first.
    assert "piano" not in f"{second.question}{second.context}"


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_kill_switches_are_independent_and_durable(store_kind: str, tmp_path: Path) -> None:
    clock = FixedClock(NOW)
    state = _state(store_kind, tmp_path / "agent.db")
    agent, _, audit = _agent(
        ScriptedModel(
            ModelIntent(
                kind=AgentIntentKind.CALL_TOOL,
                tool_name="action.propose",
                tool_arguments={
                    "patient_id": "SYN-P1001",
                    "facility_id": "FAC-NORTH",
                    "due_date": "2026-09-01",
                    "summary": "Confirm the routine follow-up appointment booking.",
                },
            ),
            ModelIntent(kind=AgentIntentKind.ABSTAIN, answer="No approved source answers this."),
        ),
        state=state,
        clock=clock,
    )
    kill_switch = AgentKillSwitch(
        state=state,
        audit=AuditLedger(AUDIT_KEY, state=state),
        clock=clock,
    )

    kill_switch.set_enabled(
        AgentCapability.WRITE,
        enabled=False,
        changed_by="sre-oncall",
        reason="Suspected prompt-injection campaign",
        correlation_id="corr-kill-1",
    )

    # Writes are off; reads and the model still work.
    assert kill_switch.snapshot() == {
        AgentCapability.MODEL: True,
        AgentCapability.READ: True,
        AgentCapability.WRITE: False,
    }
    blocked = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Create a follow-up task",
        correlation_id="corr-kill-2",
    )
    assert blocked.state is AgentRunState.REFUSED
    assert blocked.refusal_reason is AgentRefusalReason.CAPABILITY_DISABLED

    still_reading = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Where is the cafeteria piano tuning schedule?",
        correlation_id="corr-kill-3",
    )
    assert still_reading.state is AgentRunState.COMPLETED

    assert audit.verify()
    if store_kind == "sqlite":
        restarted = SqliteStateStore(tmp_path / "agent.db")
        restored = AgentKillSwitch(
            state=restarted,
            audit=AuditLedger(AUDIT_KEY, state=restarted),
            clock=clock,
        )
        # A restart must not silently re-enable a capability an operator killed.
        assert restored.is_enabled(AgentCapability.WRITE) is False
        assert restored.is_enabled(AgentCapability.READ) is True
        assert restarted.verify_integrity()


def test_disabling_the_model_leaves_deterministic_retrieval_available() -> None:
    state = InMemoryStateStore()
    agent, _, _ = _agent(ScriptedModel(), state=state)
    kill_switch = AgentKillSwitch(state=state, audit=AuditLedger(AUDIT_KEY, state=state))
    kill_switch.set_enabled(
        AgentCapability.MODEL,
        enabled=False,
        changed_by="sre-oncall",
        reason="Model provider incident",
        correlation_id="corr-kill-4",
    )

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a follow-up task identify?",
        correlation_id="corr-kill-5",
    )

    assert result.state is AgentRunState.REFUSED
    assert result.refusal_reason is AgentRefusalReason.CAPABILITY_DISABLED
    # The non-agent retrieval path is a separate service and is untouched by the model kill switch.
    assert kill_switch.is_enabled(AgentCapability.READ) is True


def test_the_deterministic_adapter_answers_with_citations_from_context() -> None:
    agent, _, _ = _agent(DeterministicModelAdapter())

    result = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a routine follow-up task identify before execution?",
        correlation_id="corr-13",
    )

    assert result.state is AgentRunState.COMPLETED
    assert result.citations
    assert {citation.document_id for citation in result.citations} <= {
        "POL-CC-014",
        "POL-PRIV-007",
        "POL-AI-001",
    }
    assert [step.state for step in result.steps][:4] == [
        AgentRunState.RECEIVED,
        AgentRunState.AUTHORIZED,
        AgentRunState.RETRIEVING,
        AgentRunState.MODEL_TURN,
    ]


def _agent(
    model: object,
    *,
    state: PolarisStateStore | None = None,
    budget: AgentBudget | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[AgentOrchestrator, PolarisStateStore, AuditLedger]:
    store = state or InMemoryStateStore()
    tick = clock or FixedClock(NOW)
    audit = AuditLedger(AUDIT_KEY, state=store, clock=tick)
    policy = PolicyEngine()
    patients = PatientService(
        InMemoryFhirPatientGateway(
            seed_fhir_patients(),
            consent_decisions=seed_consent_decisions(),
        ),
        policy,
        audit,
    )
    actions = ActionService(
        policy=policy,
        patients=patients,
        audit=audit,
        signing_key=APPROVAL_KEY,
        ttl_seconds=300,
        clock=tick,
        state=store,
    )
    ingestion = CorpusIngestionService(clock=tick)
    manifest, chunks, _ = ingestion.build(seed_corpus_sources(), corpus_id=CORPUS, version="v1")
    registry = CorpusRegistry(corpus_id=CORPUS, state=store, audit=audit, clock=tick)
    registry.register(manifest, chunks)
    registry.activate("v1", activated_by="steward-1", correlation_id="corpus-bootstrap")
    agent = AgentOrchestrator(
        model=model,  # type: ignore[arg-type]
        corpus=registry,
        patients=patients,
        actions=actions,
        audit=audit,
        kill_switch=AgentKillSwitch(state=store, audit=audit, clock=tick),
        budget=budget,
        clock=tick,
    )
    return agent, store, audit


def _principal(
    *,
    roles: Sequence[str] | set[str] = ("care_coordinator",),
    assigned: Sequence[str] | set[str] = ("SYN-P1001",),
) -> Principal:
    return Principal(
        subject="user-care-1",
        token_id="token-agent-1",
        client_id="polaris-web",
        scopes=frozenset({"polaris.policy.read", "polaris.patient.read", "polaris.task.propose"}),
        roles=frozenset(roles),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset(assigned),
    )


def _state(store_kind: str, database: Path) -> PolarisStateStore:
    return InMemoryStateStore() if store_kind == "memory" else SqliteStateStore(database)

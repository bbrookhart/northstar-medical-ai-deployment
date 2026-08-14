from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from polaris.agent.killswitch import AgentKillSwitch
from polaris.agent.model import DeterministicModelAdapter
from polaris.agent.orchestrator import AgentOrchestrator
from polaris.domain import (
    AgentCapability,
    AgentRefusalReason,
    FollowUpAction,
    Principal,
    PurposeOfUse,
)
from polaris.errors import PolarisError
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
from polaris.services.secure_retrieval import CorpusIntegrityError, CorpusRegistry
from polaris.services.state import SqliteStateStore

RETIREMENT_VERSION = "2026.08.14"
_CORPUS_ID = "northstar-retirement"
_AUDIT_KEY = "retirement-audit-key-with-sufficient-entropy"
_APPROVAL_KEY = "retirement-approval-key-with-sufficient-entropy"

# Operational data is deleted at retirement. The audit chain is not: it is the record that the
# retirement happened, and destroying it would remove the only evidence of the deletion.
_OPERATIONAL_TABLES: tuple[str, ...] = (
    "action_proposals",
    "approval_receipts",
    "action_executions",
    "identity_signals",
    "identity_subject_states",
    "identity_token_revocations",
    "identity_stream_checkpoints",
    "identity_gap_recovered_events",
    "identity_gap_recovery_states",
    "corpus_activations",
)
# Capability state is retained on purpose. Deleting it would restore the default "enabled" on the
# next start, so a retired deployment would come back up serving. The revocation record is part of
# what makes the retirement stick.
_RETAINED_TABLES: tuple[str, ...] = ("audit_events", "agent_capability_states")


@dataclass(frozen=True, slots=True)
class RetirementStep:
    step_id: str
    name: str
    objective: str
    met: bool
    observed: str


@dataclass(frozen=True, slots=True)
class RetirementReport:
    retirement_version: str
    executed_at: str
    steps: tuple[RetirementStep, ...]

    @property
    def passed(self) -> bool:
        return all(step.met for step in self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "retirement_version": self.retirement_version,
            "executed_at": self.executed_at,
            "summary": {
                "steps": len(self.steps),
                "objectives_met": sum(1 for step in self.steps if step.met),
                "passed": self.passed,
                "scope": (
                    "Synthetic local data only. Operational records are deleted and the "
                    "tamper-evident audit chain is retained as the record that retirement "
                    "occurred. This exercises no provider deletion, no backup expiry, no legal "
                    "hold, and no downstream termination, and no retention schedule is approved "
                    "(BLK-001, REQ-DAT-007)."
                ),
            },
            "steps": [
                {
                    "step_id": step.step_id,
                    "name": step.name,
                    "objective": step.objective,
                    "objective_met": step.met,
                    "observed": step.observed,
                }
                for step in self.steps
            ],
        }


def run_retirement(
    workspace: Path,
    *,
    clock: Callable[[], datetime] | None = None,
) -> RetirementReport:
    """Retire a running deployment and verify what survived and what did not."""

    tick = clock or (lambda: datetime(2026, 8, 14, tzinfo=UTC))
    workspace.mkdir(parents=True, exist_ok=True)
    database = workspace / "retirement.db"

    stack = _Stack(database, tick)
    proposal_id = stack.seed_activity()
    steps: list[RetirementStep] = [_precondition_step(stack, proposal_id)]

    # RT-02: revoke capability before deleting anything, so nothing can act mid-retirement.
    for capability in AgentCapability:
        stack.kill_switch.set_enabled(
            capability,
            enabled=False,
            changed_by="retirement-authority",
            reason="Retirement: capability revoked",
            correlation_id=f"retirement-{capability.value.lower()}",
        )
    steps.append(_revocation_step(stack))

    chain_before = stack.audit.snapshot()
    deleted_counts = _delete_operational_data(database)
    steps.append(_deletion_step(database, deleted_counts))

    retired = SqliteStateStore(database)
    retired_audit = AuditLedger(_AUDIT_KEY, state=retired, clock=tick)
    steps.append(_audit_retention_step(retired_audit, len(chain_before)))
    steps.append(_no_service_step(retired, retired_audit, tick, proposal_id))

    return RetirementReport(
        retirement_version=RETIREMENT_VERSION,
        executed_at=tick().isoformat(),
        steps=tuple(steps),
    )


class _Stack:
    def __init__(self, database: Path, clock: Callable[[], datetime]) -> None:
        self.clock = clock
        self.database = database
        self.state = SqliteStateStore(database)
        self.audit = AuditLedger(_AUDIT_KEY, state=self.state, clock=clock)
        policy = PolicyEngine()
        self.patients = PatientService(
            InMemoryFhirPatientGateway(
                seed_fhir_patients(),
                consent_decisions=seed_consent_decisions(),
            ),
            policy,
            self.audit,
        )
        self.actions = ActionService(
            policy=policy,
            patients=self.patients,
            audit=self.audit,
            signing_key=_APPROVAL_KEY,
            ttl_seconds=300,
            clock=clock,
            state=self.state,
        )
        manifest, chunks, _ = CorpusIngestionService(clock=clock).build(
            seed_corpus_sources(), corpus_id=_CORPUS_ID, version="v1"
        )
        self.corpus = CorpusRegistry(
            corpus_id=_CORPUS_ID, state=self.state, audit=self.audit, clock=clock
        )
        self.corpus.register(manifest, chunks)
        self.corpus.activate(
            "v1", activated_by="retirement-authority", correlation_id="retirement-bootstrap"
        )
        self.kill_switch = AgentKillSwitch(state=self.state, audit=self.audit, clock=clock)

    def seed_activity(self) -> str:
        self.patients.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
            patient_id="SYN-P1001",
            correlation_id="retirement-read",
        )
        AgentOrchestrator(
            model=DeterministicModelAdapter(),
            corpus=self.corpus,
            patients=self.patients,
            actions=self.actions,
            audit=self.audit,
            kill_switch=self.kill_switch,
            clock=self.clock,
        ).run(
            principal=_principal(),
            purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
            question="What must a routine follow-up task identify before execution?",
            correlation_id="retirement-agent-run",
        )
        proposal = self.actions.propose(
            principal=_principal(),
            purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
            action=FollowUpAction(
                patient_id="SYN-P1001",
                facility_id="FAC-NORTH",
                due_date=date(2026, 9, 1),
                summary="Confirm the routine follow-up appointment booking.",
            ),
            correlation_id="retirement-activity",
        )
        return proposal.proposal_id


def _precondition_step(stack: _Stack, proposal_id: str) -> RetirementStep:
    with stack.state.transaction() as transaction:
        proposal = transaction.get_proposal(proposal_id)
        activation = transaction.latest_corpus_activation(_CORPUS_ID)
    return RetirementStep(
        step_id="RT-01",
        name="Preconditions",
        objective="The deployment holds live operational data before retirement begins",
        met=proposal is not None and activation is not None,
        observed=f"proposal_present={proposal is not None} corpus_active={activation is not None}",
    )


def _revocation_step(stack: _Stack) -> RetirementStep:
    snapshot = stack.kill_switch.snapshot()
    return RetirementStep(
        step_id="RT-02",
        name="Capability revocation",
        objective="Every agent capability is revoked before any data is deleted",
        met=not any(snapshot.values()),
        observed=f"capabilities={ {key.value: value for key, value in snapshot.items()} }",
    )


def _delete_operational_data(database: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        # Delete in reverse dependency order so foreign keys stay satisfied throughout.
        for table in reversed(_OPERATIONAL_TABLES):
            cursor = connection.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed identifier list
            counts[table] = cursor.rowcount
        connection.commit()
        connection.execute("VACUUM")
    return counts


def _deletion_step(database: Path, deleted: dict[str, int]) -> RetirementStep:
    remaining: dict[str, int] = {}
    with closing(sqlite3.connect(database)) as connection:
        for table in _OPERATIONAL_TABLES:
            remaining[table] = connection.execute(
                f"SELECT count(*) FROM {table}"  # noqa: S608 - fixed identifier list
            ).fetchone()[0]
    return RetirementStep(
        step_id="RT-03",
        name="Operational data deletion",
        objective="Every operational record is deleted and none remains readable",
        met=all(count == 0 for count in remaining.values()) and sum(deleted.values()) > 0,
        observed=f"deleted={sum(deleted.values())} remaining={sum(remaining.values())}",
    )


def _audit_retention_step(audit: AuditLedger, expected: int) -> RetirementStep:
    events = audit.snapshot()
    return RetirementStep(
        step_id="RT-04",
        name="Audit retention and integrity",
        objective="The tamper-evident audit chain survives deletion and still verifies",
        met=len(events) == expected and audit.verify() and expected > 0,
        observed=f"events={len(events)} expected={expected} chain_verifies={audit.verify()}",
    )


def _no_service_step(
    state: SqliteStateStore,
    audit: AuditLedger,
    clock: Callable[[], datetime],
    proposal_id: str,
) -> RetirementStep:
    """A retired deployment must serve nothing, and must fail closed rather than emptily."""

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
        signing_key=_APPROVAL_KEY,
        ttl_seconds=300,
        clock=clock,
        state=state,
    )
    registry = CorpusRegistry(corpus_id=_CORPUS_ID, state=state, audit=audit, clock=clock)
    kill_switch = AgentKillSwitch(state=state, audit=audit, clock=clock)
    agent = AgentOrchestrator(
        model=DeterministicModelAdapter(),
        corpus=registry,
        patients=patients,
        actions=actions,
        audit=audit,
        kill_switch=kill_switch,
        clock=clock,
    )

    run = agent.run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a routine follow-up task identify before execution?",
        correlation_id="retirement-post-check",
    )
    corpus_unavailable = False
    try:
        registry.active_index()
    except CorpusIntegrityError:
        corpus_unavailable = True

    proposal_gone = False
    try:
        actions.get_proposal(proposal_id)
    except PolarisError:
        proposal_gone = True

    return RetirementStep(
        step_id="RT-05",
        name="No service after retirement",
        objective=(
            "The retired deployment refuses agent runs, serves no corpus, and has no proposals"
        ),
        met=(
            run.refusal_reason is AgentRefusalReason.CAPABILITY_DISABLED
            and corpus_unavailable
            and proposal_gone
        ),
        observed=(
            f"agent={run.refusal_reason.value if run.refusal_reason else ''} "
            f"corpus_unavailable={corpus_unavailable} proposal_gone={proposal_gone}"
        ),
    )


def retained_tables() -> Sequence[str]:
    return _RETAINED_TABLES


def deleted_tables() -> Sequence[str]:
    return _OPERATIONAL_TABLES


def _principal() -> Principal:
    return Principal(
        subject="user-care-1",
        token_id="token-retirement",  # noqa: S106 - synthetic identifier, not a credential
        client_id="polaris-web",
        scopes=frozenset({"polaris.policy.read", "polaris.patient.read", "polaris.task.propose"}),
        roles=frozenset({"care_coordinator"}),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset({"SYN-P1001"}),
    )

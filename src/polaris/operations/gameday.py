from __future__ import annotations

import json
import shutil
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from polaris.agent.killswitch import AgentKillSwitch
from polaris.agent.model import DeterministicModelAdapter, ModelIntent, ModelRequest
from polaris.agent.orchestrator import AgentOrchestrator
from polaris.domain import (
    AgentCapability,
    AgentIntentKind,
    AgentRefusalReason,
    AgentRunState,
    ApprovalDecision,
    FollowUpAction,
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
from polaris.services.retrieval_eval import evaluation_corpus_sources
from polaris.services.secure_retrieval import CorpusRegistry
from polaris.services.state import SqliteStateStore

DRILL_VERSION = "2026.08.14"
_CORPUS_ID = "northstar-gameday"
_AUDIT_KEY = "game-day-audit-key-with-sufficient-entropy"
_APPROVAL_KEY = "game-day-approval-key-with-sufficient-entropy"


@dataclass(frozen=True, slots=True)
class DrillResult:
    drill_id: str
    name: str
    objective: str
    met: bool
    observed: str
    scope: str


@dataclass(frozen=True, slots=True)
class GameDayReport:
    drill_version: str
    executed_at: str
    results: tuple[DrillResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.met for result in self.results)

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "drill_version": self.drill_version,
            "executed_at": self.executed_at,
            "summary": {
                "drills": len(self.results),
                "objectives_met": sum(1 for result in self.results if result.met),
                "passed": self.passed,
                "scope": (
                    "Single-node local simulation. These drills exercise the kill switch, corpus "
                    "rollback, degraded mode, restart recovery, and SQLite file backup and "
                    "restore. "
                    "They do not exercise the PostgreSQL failover, point-in-time recovery, audit "
                    "custody separation, or outbox reconciliation specified in "
                    "docs/operations/persistence-recovery-exercises.md, which remain unexecuted."
                ),
            },
            "drills": [
                {
                    "drill_id": result.drill_id,
                    "name": result.name,
                    "objective": result.objective,
                    "objective_met": result.met,
                    "observed": result.observed,
                    "scope": result.scope,
                }
                for result in self.results
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


class _Stack:
    def __init__(self, database: Path, clock: Callable[[], datetime]) -> None:
        self.clock = clock
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
        ingestion = CorpusIngestionService(clock=clock)
        first, first_chunks, _ = ingestion.build(
            seed_corpus_sources(), corpus_id=_CORPUS_ID, version="v1"
        )
        second, second_chunks, _ = ingestion.build(
            evaluation_corpus_sources(), corpus_id=_CORPUS_ID, version="v2"
        )
        self.corpus = CorpusRegistry(
            corpus_id=_CORPUS_ID, state=self.state, audit=self.audit, clock=clock
        )
        self.corpus.register(first, first_chunks)
        self.corpus.register(second, second_chunks)
        self.kill_switch = AgentKillSwitch(state=self.state, audit=self.audit, clock=clock)

    def activate(self, version: str, *, rollback: bool = False) -> None:
        self.corpus.activate(
            version,
            activated_by="sre-oncall",
            correlation_id=f"gameday-{version}",
            rollback=rollback,
        )

    def agent_with(self, model: object) -> AgentOrchestrator:
        return AgentOrchestrator(
            model=model,  # type: ignore[arg-type]
            corpus=self.corpus,
            patients=self.patients,
            actions=self.actions,
            audit=self.audit,
            kill_switch=self.kill_switch,
            clock=self.clock,
        )

    def agent(self) -> AgentOrchestrator:
        return AgentOrchestrator(
            model=DeterministicModelAdapter(),
            corpus=self.corpus,
            patients=self.patients,
            actions=self.actions,
            audit=self.audit,
            kill_switch=self.kill_switch,
            clock=self.clock,
        )


def run_game_day(workspace: Path, *, clock: Callable[[], datetime] | None = None) -> GameDayReport:
    """Execute the drills that a single-node local deployment can actually perform."""

    tick = clock or (lambda: datetime(2026, 8, 14, tzinfo=UTC))
    workspace.mkdir(parents=True, exist_ok=True)
    results = [
        _kill_switch_drill(workspace / "gd1.db", tick),
        _corpus_rollback_drill(workspace / "gd2.db", tick),
        _degraded_mode_drill(workspace / "gd3.db", tick),
        _restart_recovery_drill(workspace / "gd4.db", tick),
        _backup_restore_drill(workspace, tick),
    ]
    return GameDayReport(
        drill_version=DRILL_VERSION,
        executed_at=tick().isoformat(),
        results=tuple(results),
    )


def _kill_switch_drill(database: Path, clock: Callable[[], datetime]) -> DrillResult:
    """Containment has two halves, and the first drill run proved only one was being checked.

    With writes disabled the tool is not advertised at all, so a well-behaved model never asks and
    never produces a refusal. Asserting only on the refusal therefore mis-modelled the control. The
    drill checks both halves: the capability disappears from what the model is offered, and a model
    that requests it anyway is refused.
    """

    stack = _Stack(database, clock)
    stack.activate("v1")
    stack.kill_switch.set_enabled(
        AgentCapability.WRITE,
        enabled=False,
        changed_by="sre-oncall",
        reason="Game day: suspected agent compromise",
        correlation_id="gameday-kill-1",
    )
    not_offered = _propose_via_agent(stack) is None and not _write_tool_offered(stack)
    forced = stack.agent_with(_ForcedWriteModel()).run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Create a follow-up task for the assigned patient",
        correlation_id="gameday-kill-forced",
    )
    write_blocked = not_offered and forced.refusal_reason is AgentRefusalReason.CAPABILITY_DISABLED
    read_still_works = (
        stack.agent()
        .run(
            principal=_principal(),
            purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
            question="What must a routine follow-up task identify before execution?",
            correlation_id="gameday-kill-2",
        )
        .state
        is AgentRunState.COMPLETED
    )
    stack.kill_switch.set_enabled(
        AgentCapability.WRITE,
        enabled=True,
        changed_by="sre-oncall",
        reason="Game day: containment lifted",
        correlation_id="gameday-kill-3",
    )
    restored = stack.kill_switch.is_enabled(AgentCapability.WRITE)
    return DrillResult(
        drill_id="GD-01",
        name="Independent kill switch",
        objective=(
            "Disabling writes removes the capability from the model and refuses it if requested "
            "anyway, without stopping reads, and is reversible"
        ),
        met=write_blocked and read_still_works and restored,
        observed=(
            f"tool_not_offered={not_offered} forced_request_refused="
            f"{forced.refusal_reason.value if forced.refusal_reason else ''} "
            f"read_available={read_still_works} restored={restored}"
        ),
        scope="Local single-node stack",
    )


def _corpus_rollback_drill(database: Path, clock: Callable[[], datetime]) -> DrillResult:
    stack = _Stack(database, clock)
    stack.activate("v1")
    stack.activate("v2")
    promoted = stack.corpus.active_index().version
    stack.activate("v1", rollback=True)
    rolled_back = stack.corpus.active_index().version
    audited = [
        event.outcome for event in stack.audit.snapshot() if event.event_type == "corpus.activate"
    ]
    return DrillResult(
        drill_id="GD-02",
        name="Corpus rollback",
        objective="A bad corpus version can be rolled back and the change is attributable",
        met=promoted == "v2" and rolled_back == "v1" and audited[-1] == "CORPUS_ROLLED_BACK",
        observed=f"promoted={promoted} rolled_back={rolled_back} audit={audited}",
        scope="Local single-node stack",
    )


def _degraded_mode_drill(database: Path, clock: Callable[[], datetime]) -> DrillResult:
    stack = _Stack(database, clock)
    stack.activate("v1")
    stack.kill_switch.set_enabled(
        AgentCapability.MODEL,
        enabled=False,
        changed_by="sre-oncall",
        reason="Game day: model provider incident",
        correlation_id="gameday-degraded-1",
    )
    run = stack.agent().run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="What must a routine follow-up task identify before execution?",
        correlation_id="gameday-degraded-2",
    )
    # The non-agent retrieval path is a separate service and must remain available.
    direct = stack.corpus.active_index().search(
        principal=_principal(),
        question="routine follow-up task assigned patient",
    )
    fabricated = bool(run.answer) or bool(run.citations)
    return DrillResult(
        drill_id="GD-03",
        name="Safe degraded mode",
        objective=(
            "Losing the model refuses explicitly, fabricates nothing, and leaves retrieval up"
        ),
        met=(
            run.refusal_reason is AgentRefusalReason.CAPABILITY_DISABLED
            and not fabricated
            and bool(direct.chunks)
        ),
        observed=(
            f"refusal={run.refusal_reason.value if run.refusal_reason else ''} "
            f"fabricated={fabricated} retrieval_chunks={len(direct.chunks)}"
        ),
        scope="Local single-node stack",
    )


def _restart_recovery_drill(database: Path, clock: Callable[[], datetime]) -> DrillResult:
    stack = _Stack(database, clock)
    stack.activate("v1")
    proposal = _approved_proposal(stack)
    stack.kill_switch.set_enabled(
        AgentCapability.WRITE,
        enabled=False,
        changed_by="sre-oncall",
        reason="Game day: restart under containment",
        correlation_id="gameday-restart-1",
    )

    restarted = SqliteStateStore(database)
    restarted_audit = AuditLedger(_AUDIT_KEY, state=restarted, clock=clock)
    restored_switch = AgentKillSwitch(state=restarted, audit=restarted_audit, clock=clock)
    with restarted.transaction() as transaction:
        receipt = transaction.get_approval(proposal.proposal_id)
        activation = transaction.latest_corpus_activation(_CORPUS_ID)
    still_contained = not restored_switch.is_enabled(AgentCapability.WRITE)
    return DrillResult(
        drill_id="GD-04",
        name="Restart recovery",
        objective="Approvals, corpus activation, and containment survive a process restart",
        met=(
            receipt is not None
            and activation is not None
            and activation.version == "v1"
            and still_contained
            and restarted.verify_integrity()
            and restarted_audit.verify()
        ),
        observed=(
            f"approval_present={receipt is not None} "
            f"corpus={activation.version if activation else ''} "
            f"write_still_disabled={still_contained}"
        ),
        scope="Local single-node stack",
    )


def _backup_restore_drill(workspace: Path, clock: Callable[[], datetime]) -> DrillResult:
    """Take a backup, corrupt the live database, restore, and verify integrity end to end."""

    database = workspace / "gd5.db"
    backup = workspace / "gd5-backup.db"
    stack = _Stack(database, clock)
    stack.activate("v1")
    proposal = _approved_proposal(stack)

    # Back up through SQLite's own API so the copy is consistent rather than a torn file read.
    # `with sqlite3.connect(...)` manages the transaction, not the connection, so both are closed
    # explicitly rather than left to the garbage collector.
    with (
        closing(sqlite3.connect(database)) as source,
        closing(sqlite3.connect(backup)) as destination,
    ):
        source.backup(destination)

    # Destroy the live database, in a way an operator would actually have to recover from.
    database.write_bytes(b"corrupt" + database.read_bytes()[7:])
    corrupted_detected = False
    try:
        corrupted_detected = not SqliteStateStore(database).verify_integrity()
    except Exception:
        corrupted_detected = True

    shutil.copy2(backup, database)
    restored = SqliteStateStore(database)
    restored_audit = AuditLedger(_AUDIT_KEY, state=restored, clock=clock)
    with restored.transaction() as transaction:
        receipt = transaction.get_approval(proposal.proposal_id)
    return DrillResult(
        drill_id="GD-05",
        name="Backup and restore",
        objective=(
            "A corrupted database is detected and a backup restores state with an intact chain"
        ),
        met=(
            corrupted_detected
            and receipt is not None
            and restored.verify_integrity()
            and restored_audit.verify()
        ),
        observed=(
            f"corruption_detected={corrupted_detected} "
            f"approval_restored={receipt is not None} "
            f"integrity={restored.verify_integrity()} audit_chain={restored_audit.verify()}"
        ),
        scope="SQLite file backup only; not PostgreSQL PITR (NS-EXC-004)",
    )


class _ForcedWriteModel:
    """Requests the write tool regardless of what it was offered."""

    @property
    def model_id(self) -> str:
        return "game-day-forced-write-model"

    def generate(self, request: ModelRequest) -> ModelIntent:
        return ModelIntent(
            kind=AgentIntentKind.CALL_TOOL,
            tool_name="action.propose",
            tool_arguments={
                "patient_id": "SYN-P1001",
                "facility_id": "FAC-NORTH",
                "due_date": "2026-09-01",
                "summary": "Confirm the routine follow-up appointment booking.",
            },
        )


def _write_tool_offered(stack: _Stack) -> bool:
    recorder = _RecordingModel()
    stack.agent_with(recorder).run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Create a follow-up task for the assigned patient",
        correlation_id="gameday-kill-offered",
    )
    return any("action.propose" in request.available_tools for request in recorder.requests)


class _RecordingModel:
    def __init__(self) -> None:
        self.requests: list[ModelRequest] = []

    @property
    def model_id(self) -> str:
        return "game-day-recording-model"

    def generate(self, request: ModelRequest) -> ModelIntent:
        self.requests.append(request)
        return ModelIntent(kind=AgentIntentKind.ABSTAIN, answer="No approved source answers this.")


def _propose_via_agent(stack: _Stack) -> AgentRefusalReason | None:
    run = stack.agent().run(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        question="Create a follow-up task for the assigned patient",
        correlation_id="gameday-propose",
    )
    return run.refusal_reason


def _approved_proposal(stack: _Stack) -> Any:
    proposal = stack.actions.propose(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        action=FollowUpAction(
            patient_id="SYN-P1001",
            facility_id="FAC-NORTH",
            due_date=date(2026, 9, 1),
            summary="Confirm the routine follow-up appointment booking.",
        ),
        correlation_id="gameday-proposal",
    )
    stack.actions.decide(
        proposal_id=proposal.proposal_id,
        approver=_principal(subject="approver-1", roles=("task_approver",)),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        decision=ApprovalDecision.APPROVE,
        expected_action_digest=proposal.action_digest,
        correlation_id="gameday-approve",
    )
    return proposal


def _principal(
    *,
    subject: str = "user-care-1",
    roles: tuple[str, ...] = ("care_coordinator",),
) -> Principal:
    return Principal(
        subject=subject,
        token_id="token-game-day",  # noqa: S106 - synthetic identifier, not a credential
        client_id="polaris-web",
        scopes=frozenset(
            {
                "polaris.policy.read",
                "polaris.patient.read",
                "polaris.task.propose",
                "polaris.task.approve",
            }
        ),
        roles=frozenset(roles),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset({"SYN-P1001"}),
    )

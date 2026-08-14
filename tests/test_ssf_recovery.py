from __future__ import annotations

import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock

import pytest

from polaris.domain import (
    IdentityStreamRecoveryAlertLevel,
    IdentityStreamRecoveryOutcome,
)
from polaris.security.ssf_operations import (
    SsfOperationError,
    SsfStreamStatus,
    SsfStreamStatusValue,
)
from polaris.security.ssf_recovery import (
    DurableSsfRecoveryController,
    SsfRecoveryDisposition,
    SsfRecoveryUnavailable,
)
from polaris.security.ssf_stream_state import DurableSsfStreamStatusCoordinator
from polaris.services.audit import AuditLedger
from polaris.services.state import InMemoryStateStore, PolarisStateStore, SqliteStateStore

STREAM_ID = "enterprise-identity-stream"
AUDIT_KEY = "synthetic-audit-key-with-sufficient-entropy"


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class ScriptedStatusOperator:
    def __init__(self) -> None:
        self.reads: list[str] = []
        self.read_responses: list[SsfStreamStatus | Exception] = []
        self.read_callback: Callable[[int], None] | None = None
        self.read_status_value = SsfStreamStatusValue.ENABLED
        self._lock = Lock()

    def read_status(self, stream_id: str) -> SsfStreamStatus:
        with self._lock:
            index = len(self.reads)
            self.reads.append(stream_id)
            response = self.read_responses.pop(0) if self.read_responses else None
        if self.read_callback is not None:
            self.read_callback(index)
        if isinstance(response, Exception):
            raise response
        return response or SsfStreamStatus(
            stream_id=stream_id,
            status=self.read_status_value,
        )

    def update_status(
        self,
        stream_id: str,
        status: SsfStreamStatusValue,
        *,
        reason: str | None = None,
    ) -> SsfStreamStatus:
        return SsfStreamStatus(stream_id=stream_id, status=status, reason=reason)


@dataclass(slots=True)
class RecoveryRig:
    state: PolarisStateStore
    audit: AuditLedger
    clock: MutableClock
    operator: ScriptedStatusOperator
    coordinator: DurableSsfStreamStatusCoordinator
    controller: DurableSsfRecoveryController


def test_recovery_cadence_is_durable_restart_safe_and_not_early(tmp_path: Path) -> None:
    database_path = tmp_path / "recovery-cadence.db"
    rig = _rig(SqliteStateStore(database_path))
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-scheduled-recovery",
    )

    first = rig.controller.run_due(correlation_id="req-scheduled-recovery-first")

    assert first.disposition is SsfRecoveryDisposition.RECOVERED
    assert first.schedule is not None
    assert first.schedule.sequence == 2
    assert first.schedule.last_outcome is IdentityStreamRecoveryOutcome.RECOVERED
    assert first.schedule.alert_level is IdentityStreamRecoveryAlertLevel.CLEAR
    assert first.schedule.consecutive_failures == 0
    assert first.schedule.last_reconciliation_id is not None
    assert first.schedule.next_due_at == rig.clock.now + timedelta(seconds=10)
    assert (
        rig.controller.run_due(correlation_id="req-scheduled-recovery-too-early").disposition
        is SsfRecoveryDisposition.NOT_DUE
    )
    assert rig.operator.reads == [STREAM_ID]

    restarted = _rig(SqliteStateStore(database_path), clock=rig.clock)
    assert restarted.controller.schedule() == first.schedule
    assert (
        restarted.controller.run_due(correlation_id="req-restarted-recovery-too-early").disposition
        is SsfRecoveryDisposition.NOT_DUE
    )
    restarted.clock.advance(timedelta(seconds=10))
    second = restarted.controller.run_due(correlation_id="req-restarted-recovery-due")
    assert second.disposition is SsfRecoveryDisposition.RECOVERED
    assert second.schedule is not None and second.schedule.sequence == 4
    assert restarted.audit.verify()


def test_recovery_failures_escalate_then_success_clears_alert() -> None:
    rig = _rig(InMemoryStateStore())
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-recovery-failures",
    )

    for expected_count, expected_level in (
        (1, IdentityStreamRecoveryAlertLevel.WARNING),
        (2, IdentityStreamRecoveryAlertLevel.WARNING),
        (3, IdentityStreamRecoveryAlertLevel.CRITICAL),
    ):
        rig.operator.read_responses.append(SsfOperationError("synthetic provider detail"))
        failed = rig.controller.run_due(
            correlation_id=f"req-scheduled-recovery-failure-{expected_count}"
        )
        assert failed.disposition is SsfRecoveryDisposition.FAILED
        assert failed.schedule is not None
        assert failed.schedule.consecutive_failures == expected_count
        assert failed.schedule.alert_level is expected_level
        assert "synthetic provider detail" not in str(rig.audit.snapshot())
        rig.clock.advance(timedelta(seconds=2))

    recovered = rig.controller.run_due(correlation_id="req-scheduled-recovery-clears-alert")
    assert recovered.disposition is SsfRecoveryDisposition.RECOVERED
    assert recovered.schedule is not None
    assert recovered.schedule.consecutive_failures == 0
    assert recovered.schedule.alert_level is IdentityStreamRecoveryAlertLevel.CLEAR
    assert recovered.schedule.next_due_at == rig.clock.now + timedelta(seconds=10)


def test_recovery_persists_drift_and_unconfigured_state() -> None:
    unconfigured = _rig(InMemoryStateStore())
    missing = unconfigured.controller.run_due(correlation_id="req-unconfigured-recovery")
    assert missing.disposition is SsfRecoveryDisposition.UNCONFIGURED
    assert missing.schedule is not None
    assert missing.schedule.last_outcome is IdentityStreamRecoveryOutcome.UNCONFIGURED
    assert missing.schedule.alert_level is IdentityStreamRecoveryAlertLevel.WARNING
    assert unconfigured.operator.reads == []

    drifted = _rig(InMemoryStateStore())
    drifted.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-recovery-drift",
    )
    drifted.operator.read_status_value = SsfStreamStatusValue.PAUSED
    result = drifted.controller.run_due(correlation_id="req-scheduled-recovery-drift")
    assert result.disposition is SsfRecoveryDisposition.DRIFTED
    assert result.schedule is not None
    assert result.schedule.last_outcome is IdentityStreamRecoveryOutcome.DRIFTED
    assert result.schedule.last_reconciliation_id is not None
    assert result.schedule.alert_level is IdentityStreamRecoveryAlertLevel.WARNING


def test_active_lease_blocks_duplicate_concurrent_run(tmp_path: Path) -> None:
    rig = _rig(SqliteStateStore(tmp_path / "recovery-concurrent.db"))
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-concurrent-recovery",
    )
    entered = Event()
    release = Event()

    def block_first_read(index: int) -> None:
        if index == 0:
            entered.set()
            assert release.wait(timeout=2)

    rig.operator.read_callback = block_first_read
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            rig.controller.run_due,
            correlation_id="req-concurrent-recovery-owner",
        )
        assert entered.wait(timeout=2)
        duplicate = rig.controller.run_due(correlation_id="req-concurrent-recovery-duplicate")
        assert duplicate.disposition is SsfRecoveryDisposition.IN_PROGRESS
        release.set()
        completed = future.result(timeout=2)

    assert completed.disposition is SsfRecoveryDisposition.RECOVERED
    assert rig.operator.reads == [STREAM_ID]
    assert rig.audit.verify()


def test_expired_lease_is_reclaimed_and_stale_worker_cannot_overwrite(tmp_path: Path) -> None:
    rig = _rig(SqliteStateStore(tmp_path / "recovery-lease-reclaim.db"))
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-lease-reclaim",
    )
    entered = Event()
    release = Event()

    def block_first_read(index: int) -> None:
        if index == 0:
            entered.set()
            assert release.wait(timeout=2)

    rig.operator.read_callback = block_first_read
    with ThreadPoolExecutor(max_workers=1) as pool:
        stale_future = pool.submit(
            rig.controller.run_due,
            correlation_id="req-recovery-stale-worker",
        )
        assert entered.wait(timeout=2)
        rig.clock.advance(timedelta(seconds=1))
        reclaimed = rig.controller.run_due(correlation_id="req-recovery-lease-reclaimed")
        release.set()
        stale = stale_future.result(timeout=2)

    assert reclaimed.disposition is SsfRecoveryDisposition.RECOVERED
    assert stale.disposition is SsfRecoveryDisposition.SUPERSEDED
    schedule = rig.controller.schedule()
    assert schedule == reclaimed.schedule
    assert schedule is not None and schedule.last_outcome is IdentityStreamRecoveryOutcome.RECOVERED
    assert "SSF_STREAM_RECOVERY_LEASE_RECLAIMED" in {
        event.outcome for event in rig.audit.snapshot()
    }


def test_recovery_clock_rollback_and_configuration_fail_closed() -> None:
    rig = _rig(InMemoryStateStore())
    first = rig.controller.run_due(correlation_id="req-recovery-before-clock-rollback")
    assert first.disposition is SsfRecoveryDisposition.UNCONFIGURED
    rig.clock.now -= timedelta(seconds=1)
    with pytest.raises(SsfRecoveryUnavailable):
        rig.controller.run_due(correlation_id="req-recovery-after-clock-rollback")

    state = InMemoryStateStore()
    other = InMemoryStateStore()
    coordinator = _coordinator(state, ScriptedStatusOperator(), MutableClock(datetime.now(UTC)))
    with pytest.raises(ValueError, match="share one transactional"):
        DurableSsfRecoveryController(
            coordinator=coordinator,
            state=state,
            audit=AuditLedger(AUDIT_KEY, state=other),
        )
    with pytest.raises(ValueError, match="healthy recovery interval"):
        DurableSsfRecoveryController(
            coordinator=coordinator,
            state=state,
            audit=AuditLedger(AUDIT_KEY, state=state),
            healthy_interval=timedelta(0),
        )
    with pytest.raises(ValueError, match="critical recovery threshold"):
        DurableSsfRecoveryController(
            coordinator=coordinator,
            state=state,
            audit=AuditLedger(AUDIT_KEY, state=state),
            critical_after_failures=1,
        )


def test_recovery_schedule_tamper_fails_sqlite_integrity(tmp_path: Path) -> None:
    database_path = tmp_path / "recovery-tamper.db"
    rig = _rig(SqliteStateStore(database_path))
    rig.controller.run_due(correlation_id="req-recovery-before-tamper")
    schedule = rig.controller.schedule()
    assert schedule is not None
    substituted = schedule.model_copy(
        update={"alert_level": IdentityStreamRecoveryAlertLevel.CRITICAL}
    )
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            UPDATE identity_stream_recovery_schedules SET document_json = ? WHERE stream_id = ?
            """,
            (substituted.model_dump_json(), STREAM_ID),
        )

    assert rig.state.verify_integrity() is False


def _rig(
    state: PolarisStateStore,
    *,
    clock: MutableClock | None = None,
) -> RecoveryRig:
    active_clock = clock or MutableClock(datetime(2026, 8, 11, 12, tzinfo=UTC))
    operator = ScriptedStatusOperator()
    audit = AuditLedger(AUDIT_KEY, state=state, clock=active_clock)
    coordinator = _coordinator(state, operator, active_clock, audit=audit)
    controller = DurableSsfRecoveryController(
        coordinator=coordinator,
        state=state,
        audit=audit,
        healthy_interval=timedelta(seconds=10),
        degraded_interval=timedelta(seconds=2),
        lease_duration=timedelta(seconds=1),
        critical_after_failures=3,
        clock=active_clock,
    )
    return RecoveryRig(
        state=state,
        audit=audit,
        clock=active_clock,
        operator=operator,
        coordinator=coordinator,
        controller=controller,
    )


def _coordinator(
    state: PolarisStateStore,
    operator: ScriptedStatusOperator,
    clock: MutableClock,
    *,
    audit: AuditLedger | None = None,
) -> DurableSsfStreamStatusCoordinator:
    ledger = audit or AuditLedger(AUDIT_KEY, state=state, clock=clock)
    return DurableSsfStreamStatusCoordinator(
        operator=operator,
        state=state,
        audit=ledger,
        stream_id=STREAM_ID,
        max_observed_age=timedelta(seconds=30),
        sleeper=lambda _: None,
        jitter=lambda maximum: maximum,
        clock=clock,
    )

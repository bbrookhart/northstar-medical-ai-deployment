from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from polaris.domain import (
    IdentityStreamRecoveryAlertLevel,
    IdentityStreamRecoveryOutcome,
    IdentityStreamRecoverySchedule,
)
from polaris.errors import DependencyUnavailableError
from polaris.security.ssf_stream_state import (
    DurableSsfStreamStatusCoordinator,
    SsfOperationalHealthStatus,
    SsfStreamStatusUnavailable,
)
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.state import PolarisStateStore, StateIntegrityError


class SsfRecoveryDisposition(StrEnum):
    NOT_DUE = "NOT_DUE"
    IN_PROGRESS = "IN_PROGRESS"
    RECOVERED = "RECOVERED"
    DRIFTED = "DRIFTED"
    FAILED = "FAILED"
    UNCONFIGURED = "UNCONFIGURED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class SsfRecoveryCycleResult:
    disposition: SsfRecoveryDisposition
    schedule: IdentityStreamRecoverySchedule | None


@dataclass(frozen=True, slots=True)
class _Claim:
    run_id: str | None
    result: SsfRecoveryCycleResult | None


class SsfRecoveryUnavailable(DependencyUnavailableError):
    def __init__(self) -> None:
        super().__init__("SSF_RECOVERY_UNAVAILABLE")


class DurableSsfRecoveryController:
    """Lease-protected invocation cadence and alert state for safe SSF status reads.

    A production scheduler invokes ``run_due``. This controller never creates a background thread
    and never claims that a status read recovers missing SETs.
    """

    def __init__(
        self,
        *,
        coordinator: DurableSsfStreamStatusCoordinator,
        state: PolarisStateStore,
        audit: AuditLedger,
        healthy_interval: timedelta = timedelta(minutes=4),
        degraded_interval: timedelta = timedelta(seconds=30),
        lease_duration: timedelta = timedelta(seconds=30),
        critical_after_failures: int = 3,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if coordinator.state_store is not state or audit.state_store is not state:
            raise ValueError("SSF recovery, status, and audit must share one transactional state")
        if not timedelta(seconds=1) <= healthy_interval <= timedelta(days=1):
            raise ValueError("SSF healthy recovery interval is invalid")
        if not timedelta(seconds=1) <= degraded_interval <= healthy_interval:
            raise ValueError("SSF degraded recovery interval is invalid")
        if not timedelta(seconds=1) <= lease_duration <= timedelta(minutes=10):
            raise ValueError("SSF recovery lease duration is invalid")
        if not 2 <= critical_after_failures <= 10:
            raise ValueError("SSF critical recovery threshold is invalid")
        self._coordinator = coordinator
        self._state = state
        self._audit = audit
        self._stream_id = coordinator.stream_id
        self._healthy_interval = healthy_interval
        self._degraded_interval = degraded_interval
        self._lease_duration = lease_duration
        self._critical_after_failures = critical_after_failures
        self._clock = clock

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def state_store(self) -> PolarisStateStore:
        return self._state

    def schedule(self) -> IdentityStreamRecoverySchedule | None:
        with self._state.transaction() as transaction:
            return transaction.get_identity_stream_recovery_schedule(self._stream_id)

    def run_due(self, *, correlation_id: str) -> SsfRecoveryCycleResult:
        claim = self._claim(correlation_id=correlation_id)
        if claim.result is not None:
            return claim.result
        if claim.run_id is None:
            raise StateIntegrityError

        with self._state.transaction() as transaction:
            operation = transaction.latest_identity_stream_status_operation(self._stream_id)
        if operation is None:
            return self._complete(
                run_id=claim.run_id,
                outcome=IdentityStreamRecoveryOutcome.UNCONFIGURED,
                reconciliation_id=None,
                correlation_id=correlation_id,
            )

        try:
            reconciliation = self._coordinator.reconcile(correlation_id=correlation_id)
        except SsfStreamStatusUnavailable:
            return self._complete(
                run_id=claim.run_id,
                outcome=IdentityStreamRecoveryOutcome.FAILED,
                reconciliation_id=None,
                correlation_id=correlation_id,
            )

        if reconciliation.superseded:
            outcome = IdentityStreamRecoveryOutcome.SUPERSEDED
        elif (
            reconciliation.matched_desired
            and self._coordinator.health().status is SsfOperationalHealthStatus.HEALTHY
        ):
            outcome = IdentityStreamRecoveryOutcome.RECOVERED
        else:
            outcome = IdentityStreamRecoveryOutcome.DRIFTED
        return self._complete(
            run_id=claim.run_id,
            outcome=outcome,
            reconciliation_id=reconciliation.reconciliation_id,
            correlation_id=correlation_id,
        )

    def _claim(self, *, correlation_id: str) -> _Claim:
        now = self._now()
        run_id = f"SRR-{secrets.token_hex(16)}"
        with self._state.transaction() as transaction:
            current = transaction.get_identity_stream_recovery_schedule(self._stream_id)
            if current is not None:
                reference = current.active_started_at or current.last_completed_at
                if reference is not None and now < reference:
                    raise SsfRecoveryUnavailable
                if current.active_run_id is not None:
                    if current.lease_expires_at is None:
                        raise StateIntegrityError
                    if now < current.lease_expires_at:
                        return _Claim(
                            run_id=None,
                            result=SsfRecoveryCycleResult(
                                disposition=SsfRecoveryDisposition.IN_PROGRESS,
                                schedule=current,
                            ),
                        )
                    outcome = "SSF_STREAM_RECOVERY_LEASE_RECLAIMED"
                elif now < current.next_due_at:
                    return _Claim(
                        run_id=None,
                        result=SsfRecoveryCycleResult(
                            disposition=SsfRecoveryDisposition.NOT_DUE,
                            schedule=current,
                        ),
                    )
                else:
                    outcome = "SSF_STREAM_RECOVERY_CLAIMED"
                claimed = _transition_schedule(
                    current,
                    {
                        "sequence": current.sequence + 1,
                        "active_run_id": run_id,
                        "active_started_at": now,
                        "lease_expires_at": now + self._lease_duration,
                    },
                )
            else:
                outcome = "SSF_STREAM_RECOVERY_CLAIMED"
                claimed = IdentityStreamRecoverySchedule(
                    stream_id=self._stream_id,
                    sequence=1,
                    active_run_id=run_id,
                    active_started_at=now,
                    lease_expires_at=now + self._lease_duration,
                    next_due_at=now,
                    consecutive_failures=0,
                    alert_level=IdentityStreamRecoveryAlertLevel.CLEAR,
                )
            transaction.save_identity_stream_recovery_schedule(claimed)
            self._audit.append(
                actor="ssf-recovery-controller",
                event_type="identity.stream.recovery",
                outcome=outcome,
                correlation_id=correlation_id,
                metadata={"run_id": run_id, "sequence": str(claimed.sequence)},
            )
        return _Claim(run_id=run_id, result=None)

    def _complete(
        self,
        *,
        run_id: str,
        outcome: IdentityStreamRecoveryOutcome,
        reconciliation_id: str | None,
        correlation_id: str,
    ) -> SsfRecoveryCycleResult:
        now = self._now()
        with self._state.transaction() as transaction:
            current = transaction.get_identity_stream_recovery_schedule(self._stream_id)
            if current is None:
                raise StateIntegrityError
            if current.active_run_id != run_id:
                self._audit.append(
                    actor="ssf-recovery-controller",
                    event_type="identity.stream.recovery",
                    outcome="SSF_STREAM_RECOVERY_STALE_RESULT_IGNORED",
                    correlation_id=correlation_id,
                    metadata={"run_id": run_id},
                )
                return SsfRecoveryCycleResult(
                    disposition=SsfRecoveryDisposition.SUPERSEDED,
                    schedule=current,
                )
            recovered = outcome is IdentityStreamRecoveryOutcome.RECOVERED
            failures = 0 if recovered else min(current.consecutive_failures + 1, 100)
            alert_level = (
                IdentityStreamRecoveryAlertLevel.CLEAR
                if recovered
                else (
                    IdentityStreamRecoveryAlertLevel.CRITICAL
                    if failures >= self._critical_after_failures
                    else IdentityStreamRecoveryAlertLevel.WARNING
                )
            )
            interval = self._healthy_interval if recovered else self._degraded_interval
            completed = _transition_schedule(
                current,
                {
                    "sequence": current.sequence + 1,
                    "active_run_id": None,
                    "active_started_at": None,
                    "lease_expires_at": None,
                    "last_run_id": run_id,
                    "last_completed_at": now,
                    "next_due_at": now + interval,
                    "consecutive_failures": failures,
                    "last_outcome": outcome,
                    "last_reconciliation_id": reconciliation_id,
                    "alert_level": alert_level,
                },
            )
            transaction.save_identity_stream_recovery_schedule(completed)
            self._audit.append(
                actor="ssf-recovery-controller",
                event_type="identity.stream.recovery",
                outcome=f"SSF_STREAM_RECOVERY_{outcome.value}",
                correlation_id=correlation_id,
                metadata={
                    "alert_level": alert_level.value,
                    "consecutive_failures": str(failures),
                    "run_id": run_id,
                },
            )
        return SsfRecoveryCycleResult(
            disposition=SsfRecoveryDisposition(outcome.value),
            schedule=completed,
        )

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise SsfRecoveryUnavailable
        return now.astimezone(UTC)


def _transition_schedule(
    schedule: IdentityStreamRecoverySchedule,
    updates: dict[str, object],
) -> IdentityStreamRecoverySchedule:
    payload = schedule.model_dump()
    payload.update(updates)
    return IdentityStreamRecoverySchedule.model_validate(payload)

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from polaris.domain import (
    IdentitySignalRecord,
    IdentitySignalTarget,
    IdentitySignalType,
    IdentityStreamObservedState,
    IdentityStreamStatusOperation,
    IdentityStreamStatusOperationStatus,
    IdentityStreamStatusReconciliation,
    IdentityStreamStatusReconciliationFailure,
    IdentityStreamStatusReconciliationStatus,
    IdentityStreamStatusValue,
)
from polaris.errors import DependencyUnavailableError
from polaris.security.identity_signals import IdentitySignalValidationError
from polaris.security.ssf_operations import (
    SsfOperationError,
    SsfStreamStatus,
    SsfStreamStatusValue,
)
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.state import PolarisStateStore, StateIntegrityError, StateTransaction


class SsfStatusOperator(Protocol):
    def read_status(self, stream_id: str) -> SsfStreamStatus: ...

    def update_status(
        self,
        stream_id: str,
        status: SsfStreamStatusValue,
        *,
        reason: str | None = None,
    ) -> SsfStreamStatus: ...


class SsfOperationalHealthStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class SsfOperationalHealth:
    stream_id: str
    status: SsfOperationalHealthStatus
    operation_id: str | None
    operation_status: IdentityStreamStatusOperationStatus | None
    desired_status: IdentityStreamStatusValue | None
    observed_status: IdentityStreamStatusValue | None
    observed_at: datetime | None


@dataclass(frozen=True, slots=True)
class SsfStatusReconciliationResult:
    reconciliation_id: str
    operation_id: str
    attempts: int
    observed_status: IdentityStreamStatusValue
    matched_desired: bool
    superseded: bool


class SsfStreamStatusUnavailable(DependencyUnavailableError):
    def __init__(self) -> None:
        super().__init__("SSF_STREAM_STATUS_UNAVAILABLE")


def _bounded_jitter(maximum: float) -> float:
    return maximum * (0.5 + secrets.randbelow(500_001) / 1_000_000)


class DurableSsfStreamStatusCoordinator:
    """Persists stream intent before dispatch and reconciles exact responses or signed SETs."""

    def __init__(
        self,
        *,
        operator: SsfStatusOperator,
        state: PolarisStateStore,
        audit: AuditLedger,
        stream_id: str,
        max_observed_age: timedelta = timedelta(minutes=5),
        max_reconciliation_attempts: int = 3,
        base_retry_delay: timedelta = timedelta(milliseconds=100),
        max_retry_delay: timedelta = timedelta(seconds=2),
        retry_delay_budget: timedelta = timedelta(seconds=5),
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[float], float] = _bounded_jitter,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if audit.state_store is not state:
            raise ValueError("SSF status and audit must share one transactional state store")
        if not timedelta(seconds=1) <= max_observed_age <= timedelta(days=1):
            raise ValueError("SSF observed status age must be between 1 second and 1 day")
        if not 1 <= max_reconciliation_attempts <= 5:
            raise ValueError("SSF reconciliation attempts must be between 1 and 5")
        if not timedelta(milliseconds=1) <= base_retry_delay <= timedelta(seconds=10):
            raise ValueError("SSF base retry delay must be between 1 millisecond and 10 seconds")
        if not base_retry_delay <= max_retry_delay <= timedelta(seconds=30):
            raise ValueError("SSF maximum retry delay is invalid")
        if not max_retry_delay <= retry_delay_budget <= timedelta(seconds=30):
            raise ValueError("SSF retry delay budget is invalid")
        self._operator = operator
        self._state = state
        self._audit = audit
        self._stream_id = stream_id
        self._max_observed_age = max_observed_age
        self._max_reconciliation_attempts = max_reconciliation_attempts
        self._base_retry_delay_seconds = base_retry_delay.total_seconds()
        self._max_retry_delay_seconds = max_retry_delay.total_seconds()
        self._retry_delay_budget_seconds = retry_delay_budget.total_seconds()
        self._sleeper = sleeper
        self._jitter = jitter
        self._clock = clock

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def state_store(self) -> PolarisStateStore:
        return self._state

    def request_status(
        self,
        status: SsfStreamStatusValue,
        *,
        correlation_id: str,
        reason: str | None = None,
    ) -> IdentityStreamStatusOperation:
        if not isinstance(status, SsfStreamStatusValue):
            raise ValueError("SSF stream status is invalid")
        validated_reason = _validated_reason(reason)
        requested_at = self._now()
        operation = IdentityStreamStatusOperation(
            operation_id=f"SSO-{secrets.token_hex(16)}",
            stream_id=self._stream_id,
            desired_status=IdentityStreamStatusValue(status.value),
            status=IdentityStreamStatusOperationStatus.REQUESTING,
            reason_hash=_reason_hash(validated_reason),
            requested_at=requested_at,
        )
        with self._state.transaction() as transaction:
            transaction.save_identity_stream_status_operation(operation)
            self._audit_transition(
                outcome="SSF_STREAM_STATUS_REQUESTING",
                operation=operation,
                correlation_id=correlation_id,
            )

        try:
            observed = self._operator.update_status(
                self._stream_id,
                status,
                reason=validated_reason,
            )
            if (
                observed.stream_id != self._stream_id
                or observed.status is not status
                or observed.reason != validated_reason
            ):
                raise SsfOperationError("SSF stream status response binding is invalid")
        except Exception as exc:
            current = self._record_outcome_unknown(operation, correlation_id=correlation_id)
            if current.status is IdentityStreamStatusOperationStatus.CONFIRMED:
                return current
            raise SsfOperationError("SSF stream status update failed") from exc

        return self._record_confirmation(operation, correlation_id=correlation_id)

    def reconcile(self, *, correlation_id: str) -> SsfStatusReconciliationResult:
        """Recover the current stream state with a safe, bounded status read."""

        requested_at = self._now()
        with self._state.transaction() as transaction:
            operation = transaction.latest_identity_stream_status_operation(self._stream_id)
            if operation is None:
                raise SsfStreamStatusUnavailable
            reconciliation = IdentityStreamStatusReconciliation(
                reconciliation_id=f"SSR-{secrets.token_hex(16)}",
                stream_id=self._stream_id,
                operation_id=operation.operation_id,
                status=IdentityStreamStatusReconciliationStatus.REQUESTING,
                requested_at=requested_at,
                attempts=0,
            )
            transaction.save_identity_stream_status_reconciliation(reconciliation)
            self._audit_reconciliation(
                outcome="SSF_STREAM_RECONCILIATION_REQUESTING",
                reconciliation=reconciliation,
                correlation_id=correlation_id,
            )

        observed, attempts, failure = self._read_status_with_retry()
        if observed is None:
            if failure is None:
                raise StateIntegrityError
            self._record_reconciliation_failure(
                reconciliation,
                attempts=attempts,
                failure=failure,
                correlation_id=correlation_id,
            )
            raise SsfStreamStatusUnavailable
        return self._record_reconciliation_observation(
            reconciliation,
            observed=observed,
            attempts=attempts,
            correlation_id=correlation_id,
        )

    def confirm(
        self,
        transaction: StateTransaction,
        signal: IdentitySignalRecord,
    ) -> None:
        if (
            signal.target is not IdentitySignalTarget.STREAM
            or signal.event_type is not IdentitySignalType.STREAM_UPDATED
            or signal.stream_id != self._stream_id
            or signal.stream_status is None
            or signal.verification_state_hash is not None
        ):
            raise IdentitySignalValidationError("invalid_state")
        current = transaction.get_identity_stream_observed_state(self._stream_id)
        if current is not None and signal.event_time < current.observed_at:
            self._audit.append(
                actor=signal.transmitter_id,
                event_type="identity.stream.status",
                outcome="SSF_STREAM_STATUS_STALE_IGNORED",
                correlation_id=signal.event_id,
            )
            return
        if current is not None and signal.event_time == current.observed_at:
            if (
                current.status is not signal.stream_status
                or current.reason_hash != signal.stream_status_reason_hash
            ):
                raise IdentitySignalValidationError("invalid_state")
        else:
            transaction.save_identity_stream_observed_state(
                IdentityStreamObservedState(
                    stream_id=self._stream_id,
                    status=signal.stream_status,
                    reason_hash=signal.stream_status_reason_hash,
                    observed_at=signal.event_time,
                    signal_id=signal.event_id,
                )
            )

        operation = transaction.latest_identity_stream_status_operation(self._stream_id)
        reconciled = False
        if (
            operation is not None
            and operation.status
            in {
                IdentityStreamStatusOperationStatus.REQUESTING,
                IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
            }
            and operation.desired_status is signal.stream_status
            and signal.event_time >= operation.requested_at
        ):
            confirmed = _transition_operation(
                operation,
                status=IdentityStreamStatusOperationStatus.CONFIRMED,
                completed_at=self._now(),
            )
            transaction.save_identity_stream_status_operation(confirmed)
            operation = confirmed
            reconciled = True
        metadata = {"status": signal.stream_status.value}
        if reconciled and operation is not None:
            metadata["operation_id"] = operation.operation_id
        self._audit.append(
            actor=signal.transmitter_id,
            event_type="identity.stream.status",
            outcome=(
                "SSF_STREAM_STATUS_RECONCILED" if reconciled else "SSF_STREAM_STATUS_OBSERVED"
            ),
            correlation_id=signal.event_id,
            metadata=metadata,
        )

    def health(self) -> SsfOperationalHealth:
        now = self._now()
        with self._state.transaction() as transaction:
            operation = transaction.latest_identity_stream_status_operation(self._stream_id)
            observed = transaction.get_identity_stream_observed_state(self._stream_id)
        if operation is None:
            status = (
                SsfOperationalHealthStatus.UNHEALTHY
                if observed is not None and observed.status is not IdentityStreamStatusValue.ENABLED
                else SsfOperationalHealthStatus.UNKNOWN
            )
        elif operation.status is IdentityStreamStatusOperationStatus.REQUESTING:
            status = SsfOperationalHealthStatus.PENDING
        elif (
            operation.status is IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN
            or operation.desired_status is not IdentityStreamStatusValue.ENABLED
        ):
            status = SsfOperationalHealthStatus.UNHEALTHY
        elif observed is None:
            status = SsfOperationalHealthStatus.UNKNOWN
        elif (
            observed.status is not operation.desired_status
            or not -timedelta(seconds=120) <= now - observed.observed_at
        ):
            status = SsfOperationalHealthStatus.UNHEALTHY
        elif now - observed.observed_at > self._max_observed_age:
            status = SsfOperationalHealthStatus.STALE
        else:
            status = SsfOperationalHealthStatus.HEALTHY
        return SsfOperationalHealth(
            stream_id=self._stream_id,
            status=status,
            operation_id=operation.operation_id if operation is not None else None,
            operation_status=operation.status if operation is not None else None,
            desired_status=operation.desired_status if operation is not None else None,
            observed_status=observed.status if observed is not None else None,
            observed_at=observed.observed_at if observed is not None else None,
        )

    def assert_healthy(self) -> None:
        if self.health().status is not SsfOperationalHealthStatus.HEALTHY:
            raise SsfStreamStatusUnavailable

    def ready(self) -> bool:
        if not self._state.verify_integrity():
            return False
        try:
            return self.health().status is SsfOperationalHealthStatus.HEALTHY
        except (DependencyUnavailableError, StateIntegrityError):
            return False

    def _record_confirmation(
        self,
        operation: IdentityStreamStatusOperation,
        *,
        correlation_id: str,
    ) -> IdentityStreamStatusOperation:
        now = self._now()
        with self._state.transaction() as transaction:
            current = self._required(transaction, operation.operation_id)
            if current.status is IdentityStreamStatusOperationStatus.CONFIRMED:
                return current
            if current.status not in {
                IdentityStreamStatusOperationStatus.REQUESTING,
                IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
            }:
                raise StateIntegrityError
            confirmed = _transition_operation(
                current,
                status=IdentityStreamStatusOperationStatus.CONFIRMED,
                completed_at=now,
            )
            transaction.save_identity_stream_status_operation(confirmed)
            observed = transaction.get_identity_stream_observed_state(self._stream_id)
            if observed is None or observed.observed_at <= now:
                transaction.save_identity_stream_observed_state(
                    IdentityStreamObservedState(
                        stream_id=self._stream_id,
                        status=confirmed.desired_status,
                        reason_hash=confirmed.reason_hash,
                        observed_at=now,
                        operation_id=confirmed.operation_id,
                    )
                )
            self._audit_transition(
                outcome="SSF_STREAM_STATUS_CONFIRMED",
                operation=confirmed,
                correlation_id=correlation_id,
            )
            return confirmed

    def _record_outcome_unknown(
        self,
        operation: IdentityStreamStatusOperation,
        *,
        correlation_id: str,
    ) -> IdentityStreamStatusOperation:
        now = self._now()
        with self._state.transaction() as transaction:
            current = self._required(transaction, operation.operation_id)
            if current.status is IdentityStreamStatusOperationStatus.CONFIRMED:
                return current
            if current.status is not IdentityStreamStatusOperationStatus.REQUESTING:
                raise StateIntegrityError
            unknown = _transition_operation(
                current,
                status=IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
                completed_at=now,
            )
            transaction.save_identity_stream_status_operation(unknown)
            self._audit_transition(
                outcome="SSF_STREAM_STATUS_OUTCOME_UNKNOWN",
                operation=unknown,
                correlation_id=correlation_id,
            )
            return unknown

    def _read_status_with_retry(
        self,
    ) -> tuple[
        SsfStreamStatus | None,
        int,
        IdentityStreamStatusReconciliationFailure | None,
    ]:
        total_delay = 0.0
        for attempts in range(1, self._max_reconciliation_attempts + 1):
            try:
                observed = self._operator.read_status(self._stream_id)
                if observed.stream_id != self._stream_id:
                    raise SsfOperationError("SSF stream status response binding is invalid")
                return observed, attempts, None
            except SsfOperationError as exc:
                if not exc.retryable:
                    return (
                        None,
                        attempts,
                        IdentityStreamStatusReconciliationFailure.NON_RETRYABLE,
                    )
                if attempts == self._max_reconciliation_attempts:
                    return (
                        None,
                        attempts,
                        IdentityStreamStatusReconciliationFailure.RETRY_EXHAUSTED,
                    )
                delay = self._retry_delay(exc, attempts=attempts)
                if delay is None or total_delay + delay > self._retry_delay_budget_seconds:
                    return (
                        None,
                        attempts,
                        IdentityStreamStatusReconciliationFailure.RETRY_BUDGET_EXHAUSTED,
                    )
                try:
                    self._sleeper(delay)
                except Exception:
                    return (
                        None,
                        attempts,
                        IdentityStreamStatusReconciliationFailure.NON_RETRYABLE,
                    )
                total_delay += delay
            except Exception:
                return (
                    None,
                    attempts,
                    IdentityStreamStatusReconciliationFailure.NON_RETRYABLE,
                )
        raise StateIntegrityError

    def _retry_delay(self, error: SsfOperationError, *, attempts: int) -> float | None:
        if error.retry_after_seconds is not None:
            delay = float(error.retry_after_seconds)
            return delay if delay <= self._max_retry_delay_seconds else None
        maximum = min(
            self._base_retry_delay_seconds * (2 ** (attempts - 1)),
            self._max_retry_delay_seconds,
        )
        try:
            delay = self._jitter(maximum)
        except Exception:
            return None
        if not 0 <= delay <= maximum:
            return None
        return delay

    def _record_reconciliation_failure(
        self,
        reconciliation: IdentityStreamStatusReconciliation,
        *,
        attempts: int,
        failure: IdentityStreamStatusReconciliationFailure,
        correlation_id: str,
    ) -> None:
        now = self._now()
        with self._state.transaction() as transaction:
            current = self._required_reconciliation(
                transaction,
                reconciliation.reconciliation_id,
            )
            latest = transaction.latest_identity_stream_status_operation(self._stream_id)
            if (
                latest is not None
                and latest.operation_id == reconciliation.operation_id
                and latest.status is IdentityStreamStatusOperationStatus.REQUESTING
            ):
                transaction.save_identity_stream_status_operation(
                    _transition_operation(
                        latest,
                        status=IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
                        completed_at=now,
                    )
                )
            failed = _transition_reconciliation(
                current,
                status=IdentityStreamStatusReconciliationStatus.FAILED,
                completed_at=now,
                attempts=attempts,
                failure=failure,
            )
            transaction.save_identity_stream_status_reconciliation(failed)
            self._audit_reconciliation(
                outcome="SSF_STREAM_RECONCILIATION_FAILED",
                reconciliation=failed,
                correlation_id=correlation_id,
            )

    def _record_reconciliation_observation(
        self,
        reconciliation: IdentityStreamStatusReconciliation,
        *,
        observed: SsfStreamStatus,
        attempts: int,
        correlation_id: str,
    ) -> SsfStatusReconciliationResult:
        now = self._now()
        observed_status = IdentityStreamStatusValue(observed.status.value)
        observed_reason_hash = _reason_hash(observed.reason)
        with self._state.transaction() as transaction:
            current = self._required_reconciliation(
                transaction,
                reconciliation.reconciliation_id,
            )
            attached_operation = self._required(transaction, reconciliation.operation_id)
            latest = transaction.latest_identity_stream_status_operation(self._stream_id)
            current_observation = transaction.get_identity_stream_observed_state(self._stream_id)
            superseded = (
                latest is None
                or latest.operation_id != reconciliation.operation_id
                or (
                    current_observation is not None
                    and current_observation.observed_at > reconciliation.requested_at
                )
            )
            matched_desired = attached_operation.desired_status is observed_status
            reconciliation_status = (
                IdentityStreamStatusReconciliationStatus.SUPERSEDED
                if superseded
                else IdentityStreamStatusReconciliationStatus.OBSERVED
            )
            completed = _transition_reconciliation(
                current,
                status=reconciliation_status,
                completed_at=now,
                attempts=attempts,
                observed_status=observed_status,
                observed_reason_hash=observed_reason_hash,
            )
            transaction.save_identity_stream_status_reconciliation(completed)
            if not superseded and latest is not None:
                if matched_desired and latest.status in {
                    IdentityStreamStatusOperationStatus.REQUESTING,
                    IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
                }:
                    latest = _transition_operation(
                        latest,
                        status=IdentityStreamStatusOperationStatus.CONFIRMED,
                        completed_at=now,
                    )
                    transaction.save_identity_stream_status_operation(latest)
                elif (
                    not matched_desired
                    and latest.status is IdentityStreamStatusOperationStatus.REQUESTING
                ):
                    latest = _transition_operation(
                        latest,
                        status=IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
                        completed_at=now,
                    )
                    transaction.save_identity_stream_status_operation(latest)
                transaction.save_identity_stream_observed_state(
                    IdentityStreamObservedState(
                        stream_id=self._stream_id,
                        status=observed_status,
                        reason_hash=observed_reason_hash,
                        observed_at=now,
                        reconciliation_id=completed.reconciliation_id,
                    )
                )
            self._audit_reconciliation(
                outcome=(
                    "SSF_STREAM_RECONCILIATION_SUPERSEDED"
                    if superseded
                    else (
                        "SSF_STREAM_RECONCILIATION_MATCHED"
                        if matched_desired
                        else "SSF_STREAM_RECONCILIATION_DRIFTED"
                    )
                ),
                reconciliation=completed,
                correlation_id=correlation_id,
            )
        return SsfStatusReconciliationResult(
            reconciliation_id=reconciliation.reconciliation_id,
            operation_id=reconciliation.operation_id,
            attempts=attempts,
            observed_status=observed_status,
            matched_desired=matched_desired,
            superseded=superseded,
        )

    def _audit_transition(
        self,
        *,
        outcome: str,
        operation: IdentityStreamStatusOperation,
        correlation_id: str,
    ) -> None:
        self._audit.append(
            actor="ssf-stream-status-coordinator",
            event_type="identity.stream.status",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata={
                "operation_id": operation.operation_id,
                "status": operation.desired_status.value,
            },
        )

    def _audit_reconciliation(
        self,
        *,
        outcome: str,
        reconciliation: IdentityStreamStatusReconciliation,
        correlation_id: str,
    ) -> None:
        metadata = {
            "attempts": str(reconciliation.attempts),
            "operation_id": reconciliation.operation_id,
            "reconciliation_id": reconciliation.reconciliation_id,
        }
        if reconciliation.failure is not None:
            metadata["failure"] = reconciliation.failure.value
        if reconciliation.observed_status is not None:
            metadata["observed_status"] = reconciliation.observed_status.value
        self._audit.append(
            actor="ssf-stream-status-coordinator",
            event_type="identity.stream.status.reconciliation",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata=metadata,
        )

    @staticmethod
    def _required(
        transaction: StateTransaction,
        operation_id: str,
    ) -> IdentityStreamStatusOperation:
        operation = transaction.get_identity_stream_status_operation(operation_id)
        if operation is None:
            raise StateIntegrityError
        return operation

    @staticmethod
    def _required_reconciliation(
        transaction: StateTransaction,
        reconciliation_id: str,
    ) -> IdentityStreamStatusReconciliation:
        reconciliation = transaction.get_identity_stream_status_reconciliation(reconciliation_id)
        if reconciliation is None:
            raise StateIntegrityError
        return reconciliation

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise SsfStreamStatusUnavailable
        return now.astimezone(UTC)


def _validated_reason(value: str | None) -> str | None:
    if value is None:
        return None
    if value != value.strip() or not value or len(value) > 512:
        raise ValueError("SSF stream status reason is invalid")
    if any(ord(character) < 0x20 for character in value):
        raise ValueError("SSF stream status reason is invalid")
    return value


def _reason_hash(value: str | None) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest() if value is not None else None


def _transition_operation(
    operation: IdentityStreamStatusOperation,
    **updates: object,
) -> IdentityStreamStatusOperation:
    payload = operation.model_dump()
    payload.update(updates)
    return IdentityStreamStatusOperation.model_validate(payload)


def _transition_reconciliation(
    reconciliation: IdentityStreamStatusReconciliation,
    **updates: object,
) -> IdentityStreamStatusReconciliation:
    payload = reconciliation.model_dump()
    payload.update(updates)
    return IdentityStreamStatusReconciliation.model_validate(payload)

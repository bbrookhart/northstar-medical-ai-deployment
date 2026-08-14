from __future__ import annotations

import base64
import hashlib
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from polaris.domain import (
    IdentityStreamStatusOperationStatus,
    IdentityStreamStatusReconciliationFailure,
    IdentityStreamStatusReconciliationStatus,
    IdentityStreamStatusValue,
)
from polaris.security.auth import StaticJwksProvider
from polaris.security.identity_signals import (
    IdentitySignalValidationError,
    SharedSignalsReceiver,
    StateBackedRevocationProvider,
)
from polaris.security.ssf_operations import (
    SsfOperationError,
    SsfStreamStatus,
    SsfStreamStatusValue,
)
from polaris.security.ssf_stream_state import (
    DurableSsfStreamStatusCoordinator,
    SsfOperationalHealthStatus,
    SsfStreamStatusUnavailable,
)
from polaris.services.audit import AuditLedger
from polaris.services.state import InMemoryStateStore, PolarisStateStore, SqliteStateStore

ISSUER = "https://identity.northstar.example.test"
AUDIENCE = "polaris-identity-signals"
STREAM_ID = "enterprise-identity-stream"
TRANSMITTER_ID = "northstar-idp-transmitter"
KEY_ID = "northstar-stream-key-1"
AUDIT_KEY = "synthetic-audit-key-with-sufficient-entropy"
STREAM_UPDATED_EVENT = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class ScriptedStatusOperator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, SsfStreamStatusValue, str | None]] = []
        self.reads: list[str] = []
        self.read_responses: list[SsfStreamStatus | Exception] = []
        self.read_callback: Callable[[], object] | None = None
        self.callback: Callable[[SsfStreamStatusValue, str | None], object] | None = None
        self.failure: Exception | None = None
        self.returned_status: SsfStreamStatusValue | None = None
        self.returned_reason: str | None = None

    def read_status(self, stream_id: str) -> SsfStreamStatus:
        self.reads.append(stream_id)
        if self.read_callback is not None:
            self.read_callback()
        if self.read_responses:
            response = self.read_responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        return SsfStreamStatus(
            stream_id=stream_id,
            status=self.returned_status or SsfStreamStatusValue.ENABLED,
            reason=self.returned_reason,
        )

    def update_status(
        self,
        stream_id: str,
        status: SsfStreamStatusValue,
        *,
        reason: str | None = None,
    ) -> SsfStreamStatus:
        self.calls.append((stream_id, status, reason))
        if self.callback is not None:
            self.callback(status, reason)
        if self.failure is not None:
            raise self.failure
        return SsfStreamStatus(
            stream_id=stream_id,
            status=self.returned_status or status,
            reason=self.returned_reason if self.returned_reason is not None else reason,
        )


@dataclass(slots=True)
class StatusRig:
    state: PolarisStateStore
    audit: AuditLedger
    clock: MutableClock
    operator: ScriptedStatusOperator
    coordinator: DurableSsfStreamStatusCoordinator
    revocations: StateBackedRevocationProvider
    receiver: SharedSignalsReceiver
    private_key: rsa.RSAPrivateKey


def test_status_intent_response_and_reason_digest_survive_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "stream-status.db"
    rig = _rig(SqliteStateStore(database_path))
    reason = "Operator-approved activation"

    operation = rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        reason=reason,
        correlation_id="req-enable-stream",
    )

    assert operation.status is IdentityStreamStatusOperationStatus.CONFIRMED
    assert operation.reason_hash == hashlib.sha256(reason.encode()).hexdigest()
    assert rig.operator.calls == [(STREAM_ID, SsfStreamStatusValue.ENABLED, reason)]
    with rig.state.transaction() as transaction:
        persisted = transaction.get_identity_stream_status_operation(operation.operation_id)
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert persisted == operation
    assert observed is not None
    assert observed.status is IdentityStreamStatusValue.ENABLED
    assert observed.operation_id == operation.operation_id
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.HEALTHY
    assert reason.encode() not in database_path.read_bytes()
    assert reason not in str(rig.audit.snapshot())
    assert rig.audit.verify()

    restarted_state = SqliteStateStore(database_path)
    restarted_audit = AuditLedger(AUDIT_KEY, state=restarted_state, clock=rig.clock)
    restarted = DurableSsfStreamStatusCoordinator(
        operator=ScriptedStatusOperator(),
        state=restarted_state,
        audit=restarted_audit,
        stream_id=STREAM_ID,
        max_observed_age=timedelta(seconds=10),
        clock=rig.clock,
    )
    assert restarted.health().status is SsfOperationalHealthStatus.HEALTHY
    assert restarted.ready()


def test_ambiguous_dispatch_is_outcome_unknown_until_signed_event_reconciles() -> None:
    rig = _rig(InMemoryStateStore())
    rig.operator.failure = RuntimeError("synthetic upstream detail")

    with pytest.raises(SsfOperationError) as raised:
        rig.coordinator.request_status(
            SsfStreamStatusValue.ENABLED,
            correlation_id="req-ambiguous-enable",
        )
    assert "synthetic upstream detail" not in str(raised.value)
    with rig.state.transaction() as transaction:
        operation = transaction.latest_identity_stream_status_operation(STREAM_ID)
    assert operation is not None
    assert operation.status is IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.UNHEALTHY

    assert rig.receiver.accept(
        _stream_updated_set(
            rig.private_key,
            rig.clock.now,
            event_id="set-reconcile-enable",
            status="enabled",
        ),
        correlation_id="req-reconcile-enable",
        transmitter_id=TRANSMITTER_ID,
    )
    with rig.state.transaction() as transaction:
        reconciled = transaction.get_identity_stream_status_operation(operation.operation_id)
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert reconciled is not None
    assert reconciled.status is IdentityStreamStatusOperationStatus.CONFIRMED
    assert observed is not None and observed.signal_id == "set-reconcile-enable"
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.HEALTHY


def test_synchronous_signed_callback_wins_ambiguous_response_failure() -> None:
    rig = _rig(InMemoryStateStore())
    rig.operator.callback = lambda status, reason: rig.receiver.accept(
        _stream_updated_set(
            rig.private_key,
            rig.clock.now,
            event_id="set-status-race",
            status=status.value,
            reason=reason,
        ),
        correlation_id="req-status-race-callback",
        transmitter_id=TRANSMITTER_ID,
    )
    rig.operator.failure = RuntimeError("synthetic response loss")

    operation = rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        reason="Activate",
        correlation_id="req-status-race",
    )

    assert operation.status is IdentityStreamStatusOperationStatus.CONFIRMED
    with rig.state.transaction() as transaction:
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert observed is not None and observed.signal_id == "set-status-race"
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.HEALTHY


def test_paused_or_drifted_stream_fails_authorization_health_gate() -> None:
    rig = _rig(InMemoryStateStore())
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-for-auth",
    )
    rig.revocations.record_stream_success()
    rig.revocations.assert_not_revoked(
        token_id="tok-active",
        subject="user-care-1",
        issued_at=rig.clock.now,
    )

    rig.clock.advance(timedelta(seconds=1))
    rig.receiver.accept(
        _stream_updated_set(
            rig.private_key,
            rig.clock.now,
            event_id="set-stream-paused",
            status="paused",
            reason="Transmitter maintenance",
        ),
        correlation_id="req-stream-paused",
        transmitter_id=TRANSMITTER_ID,
    )

    health = rig.coordinator.health()
    assert health.status is SsfOperationalHealthStatus.UNHEALTHY
    assert health.desired_status is IdentityStreamStatusValue.ENABLED
    assert health.observed_status is IdentityStreamStatusValue.PAUSED
    with pytest.raises(SsfStreamStatusUnavailable):
        rig.revocations.assert_not_revoked(
            token_id="tok-active",
            subject="user-care-1",
            issued_at=rig.clock.now,
        )
    assert rig.revocations.ready() is False


def test_signed_observations_are_monotonic_and_same_time_conflicts_roll_back() -> None:
    rig = _rig(InMemoryStateStore())
    first_time = rig.clock.now
    rig.receiver.accept(
        _stream_updated_set(
            rig.private_key,
            rig.clock.now,
            event_id="set-paused-first",
            status="paused",
        ),
        correlation_id="req-paused-first",
        transmitter_id=TRANSMITTER_ID,
    )
    rig.clock.advance(timedelta(seconds=2))
    rig.receiver.accept(
        _stream_updated_set(
            rig.private_key,
            rig.clock.now,
            event_id="set-disabled-newer",
            status="disabled",
        ),
        correlation_id="req-disabled-newer",
        transmitter_id=TRANSMITTER_ID,
    )
    rig.receiver.accept(
        _stream_updated_set(
            rig.private_key,
            rig.clock.now,
            event_id="set-enabled-older",
            status="enabled",
            event_time=first_time,
        ),
        correlation_id="req-enabled-older",
        transmitter_id=TRANSMITTER_ID,
    )
    with rig.state.transaction() as transaction:
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert observed is not None
    assert observed.status is IdentityStreamStatusValue.DISABLED
    assert observed.signal_id == "set-disabled-newer"

    with pytest.raises(IdentitySignalValidationError) as raised:
        rig.receiver.accept(
            _stream_updated_set(
                rig.private_key,
                rig.clock.now,
                event_id="set-paused-conflict",
                status="paused",
            ),
            correlation_id="req-paused-conflict",
            transmitter_id=TRANSMITTER_ID,
        )
    assert raised.value.delivery_error_code == "invalid_state"
    with rig.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-paused-conflict") is None
        unchanged = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert unchanged == observed


@pytest.mark.parametrize(
    ("stream_id", "event", "error_code"),
    [
        ("wrong-stream", {"status": "enabled"}, "invalid_state"),
        (STREAM_ID, {"status": "unknown"}, "invalid_state"),
        (STREAM_ID, {"status": "enabled", "extra": "member"}, "invalid_state"),
        (STREAM_ID, {"status": "enabled", "reason": "x" * 513}, "invalid_state"),
    ],
)
def test_stream_updated_rejects_unbound_or_invalid_state(
    stream_id: str,
    event: dict[str, object],
    error_code: str,
) -> None:
    rig = _rig(InMemoryStateStore())
    token = _stream_updated_set(
        rig.private_key,
        rig.clock.now,
        event_id="set-invalid-stream-state",
        status="enabled",
        stream_id=stream_id,
        event=event,
    )

    with pytest.raises(IdentitySignalValidationError) as raised:
        rig.receiver.accept(
            token,
            correlation_id="req-invalid-stream-state",
            transmitter_id=TRANSMITTER_ID,
        )
    assert raised.value.delivery_error_code == error_code


def test_stream_updated_requires_configured_handler_and_status_freshness() -> None:
    rig = _rig(InMemoryStateStore())
    receiver_without_handler = SharedSignalsReceiver(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=_jwks_provider(rig.private_key),
        revocations=StateBackedRevocationProvider(
            rig.state,
            stream_id=STREAM_ID,
            max_staleness=timedelta(minutes=5),
            clock=rig.clock,
        ),
        audit=rig.audit,
        clock=rig.clock,
    )
    with pytest.raises(IdentitySignalValidationError) as raised:
        receiver_without_handler.accept(
            _stream_updated_set(
                rig.private_key,
                rig.clock.now,
                event_id="set-no-status-handler",
                status="enabled",
            ),
            correlation_id="req-no-status-handler",
            transmitter_id=TRANSMITTER_ID,
        )
    assert raised.value.delivery_error_code == "invalid_state"
    with rig.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-no-status-handler") is None

    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-stale",
    )
    rig.clock.advance(timedelta(seconds=11))
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.STALE
    assert rig.coordinator.ready() is False


def test_safe_status_read_recovers_ambiguous_write_and_survives_restart(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "stream-status-reconciliation.db"
    rig = _rig(SqliteStateStore(database_path))
    rig.operator.failure = RuntimeError("synthetic response loss")
    with pytest.raises(SsfOperationError):
        rig.coordinator.request_status(
            SsfStreamStatusValue.ENABLED,
            correlation_id="req-ambiguous-before-read",
        )
    rig.operator.failure = None
    rig.operator.read_responses.append(
        SsfStreamStatus(
            stream_id=STREAM_ID,
            status=SsfStreamStatusValue.ENABLED,
            reason="Provider confirms activation",
        )
    )

    result = rig.coordinator.reconcile(correlation_id="req-safe-status-read")

    assert result.attempts == 1
    assert result.matched_desired
    assert result.superseded is False
    with rig.state.transaction() as transaction:
        operation = transaction.get_identity_stream_status_operation(result.operation_id)
        reconciliation = transaction.get_identity_stream_status_reconciliation(
            result.reconciliation_id
        )
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert operation is not None
    assert operation.status is IdentityStreamStatusOperationStatus.CONFIRMED
    assert reconciliation is not None
    assert reconciliation.status is IdentityStreamStatusReconciliationStatus.OBSERVED
    assert observed is not None
    assert observed.reconciliation_id == result.reconciliation_id
    assert b"Provider confirms activation" not in database_path.read_bytes()
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.HEALTHY

    restarted_state = SqliteStateStore(database_path)
    restarted = DurableSsfStreamStatusCoordinator(
        operator=ScriptedStatusOperator(),
        state=restarted_state,
        audit=AuditLedger(AUDIT_KEY, state=restarted_state, clock=rig.clock),
        stream_id=STREAM_ID,
        max_observed_age=timedelta(seconds=10),
        sleeper=lambda _: None,
        clock=rig.clock,
    )
    assert restarted.health().status is SsfOperationalHealthStatus.HEALTHY


def test_status_read_persists_drift_and_refreshes_stale_observation() -> None:
    rig = _rig(InMemoryStateStore())
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-read-drift",
    )
    rig.clock.advance(timedelta(seconds=11))
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.STALE
    rig.operator.read_responses.append(
        SsfStreamStatus(
            stream_id=STREAM_ID,
            status=SsfStreamStatusValue.PAUSED,
            reason="Provider maintenance",
        )
    )

    result = rig.coordinator.reconcile(correlation_id="req-observe-read-drift")

    assert result.matched_desired is False
    assert result.superseded is False
    with rig.state.transaction() as transaction:
        operation = transaction.get_identity_stream_status_operation(result.operation_id)
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert operation is not None
    assert operation.status is IdentityStreamStatusOperationStatus.CONFIRMED
    assert observed is not None
    assert observed.status is IdentityStreamStatusValue.PAUSED
    assert observed.reconciliation_id == result.reconciliation_id
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.UNHEALTHY


def test_status_read_honors_retry_after_then_uses_bounded_backoff() -> None:
    sleeps: list[float] = []
    rig = _rig(InMemoryStateStore(), sleeper=sleeps.append)
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-retries",
    )
    rig.operator.read_responses.extend(
        [
            SsfOperationError(
                "SSF status read was rate limited",
                retryable=True,
                retry_after_seconds=2,
            ),
            SsfOperationError("SSF status read unavailable", retryable=True),
            SsfStreamStatus(
                stream_id=STREAM_ID,
                status=SsfStreamStatusValue.ENABLED,
            ),
        ]
    )

    result = rig.coordinator.reconcile(correlation_id="req-bounded-status-retry")

    assert result.attempts == 3
    assert sleeps == [2.0, 0.2]
    assert rig.operator.reads == [STREAM_ID, STREAM_ID, STREAM_ID]
    assert rig.coordinator.health().status is SsfOperationalHealthStatus.HEALTHY


@pytest.mark.parametrize(
    ("error", "expected_failure"),
    [
        (
            SsfOperationError("SSF status read rejected"),
            IdentityStreamStatusReconciliationFailure.NON_RETRYABLE,
        ),
        (
            SsfOperationError(
                "SSF retry window exceeds local budget",
                retryable=True,
                retry_after_seconds=3,
            ),
            IdentityStreamStatusReconciliationFailure.RETRY_BUDGET_EXHAUSTED,
        ),
    ],
)
def test_failed_status_read_is_durable_and_does_not_retry_unsafely(
    error: SsfOperationError,
    expected_failure: IdentityStreamStatusReconciliationFailure,
) -> None:
    sleeps: list[float] = []
    rig = _rig(
        InMemoryStateStore(),
        max_retry_delay=timedelta(seconds=2),
        sleeper=sleeps.append,
    )
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-failed-read",
    )
    rig.operator.read_responses.append(error)

    with pytest.raises(SsfStreamStatusUnavailable):
        rig.coordinator.reconcile(correlation_id="req-failed-status-read")

    audit_event = rig.audit.snapshot()[-1]
    reconciliation_id = audit_event.metadata["reconciliation_id"]
    with rig.state.transaction() as transaction:
        reconciliation = transaction.get_identity_stream_status_reconciliation(reconciliation_id)
    assert reconciliation is not None
    assert reconciliation.status is IdentityStreamStatusReconciliationStatus.FAILED
    assert reconciliation.failure is expected_failure
    assert reconciliation.attempts == 1
    assert sleeps == []


def test_status_read_retry_exhaustion_is_bounded_and_durable() -> None:
    sleeps: list[float] = []
    rig = _rig(InMemoryStateStore(), sleeper=sleeps.append)
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-exhaustion",
    )
    rig.operator.read_responses.extend(
        [
            SsfOperationError("SSF status read unavailable", retryable=True),
            SsfOperationError("SSF status read unavailable", retryable=True),
            SsfOperationError("SSF status read unavailable", retryable=True),
        ]
    )

    with pytest.raises(SsfStreamStatusUnavailable):
        rig.coordinator.reconcile(correlation_id="req-exhaust-status-read")

    audit_event = rig.audit.snapshot()[-1]
    with rig.state.transaction() as transaction:
        reconciliation = transaction.get_identity_stream_status_reconciliation(
            audit_event.metadata["reconciliation_id"]
        )
    assert reconciliation is not None
    assert reconciliation.status is IdentityStreamStatusReconciliationStatus.FAILED
    assert reconciliation.failure is IdentityStreamStatusReconciliationFailure.RETRY_EXHAUSTED
    assert reconciliation.attempts == 3
    assert sleeps == [0.1, 0.2]


def test_concurrent_newer_status_intent_supersedes_old_read_result() -> None:
    rig = _rig(InMemoryStateStore())
    first = rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-first-status",
    )
    rig.operator.read_responses.append(
        SsfStreamStatus(
            stream_id=STREAM_ID,
            status=SsfStreamStatusValue.ENABLED,
        )
    )
    rig.operator.read_callback = lambda: rig.coordinator.request_status(
        SsfStreamStatusValue.PAUSED,
        correlation_id="req-newer-status",
    )

    result = rig.coordinator.reconcile(correlation_id="req-read-old-status")

    assert result.operation_id == first.operation_id
    assert result.superseded
    with rig.state.transaction() as transaction:
        latest = transaction.latest_identity_stream_status_operation(STREAM_ID)
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
        reconciliation = transaction.get_identity_stream_status_reconciliation(
            result.reconciliation_id
        )
    assert latest is not None
    assert latest.desired_status is IdentityStreamStatusValue.PAUSED
    assert observed is not None
    assert observed.status is IdentityStreamStatusValue.PAUSED
    assert observed.operation_id == latest.operation_id
    assert reconciliation is not None
    assert reconciliation.status is IdentityStreamStatusReconciliationStatus.SUPERSEDED


def test_newer_signed_observation_supersedes_in_flight_read_result() -> None:
    rig = _rig(InMemoryStateStore())
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-concurrent-signal",
    )
    rig.operator.read_responses.append(
        SsfStreamStatus(
            stream_id=STREAM_ID,
            status=SsfStreamStatusValue.ENABLED,
        )
    )

    def deliver_newer_signed_observation() -> object:
        rig.clock.advance(timedelta(seconds=1))
        return rig.receiver.accept(
            _stream_updated_set(
                rig.private_key,
                rig.clock.now,
                event_id="set-concurrent-paused",
                status="paused",
            ),
            correlation_id="req-concurrent-paused",
            transmitter_id=TRANSMITTER_ID,
        )

    rig.operator.read_callback = deliver_newer_signed_observation

    result = rig.coordinator.reconcile(correlation_id="req-read-before-newer-signal")

    assert result.superseded
    with rig.state.transaction() as transaction:
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
        reconciliation = transaction.get_identity_stream_status_reconciliation(
            result.reconciliation_id
        )
    assert observed is not None
    assert observed.status is IdentityStreamStatusValue.PAUSED
    assert observed.signal_id == "set-concurrent-paused"
    assert reconciliation is not None
    assert reconciliation.status is IdentityStreamStatusReconciliationStatus.SUPERSEDED


def test_sqlite_observation_binding_tamper_fails_integrity(tmp_path: Path) -> None:
    database_path = tmp_path / "stream-status-tamper.db"
    rig = _rig(SqliteStateStore(database_path))
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-tamper",
    )
    with rig.state.transaction() as transaction:
        observed = transaction.get_identity_stream_observed_state(STREAM_ID)
    assert observed is not None
    substituted = observed.model_copy(update={"status": IdentityStreamStatusValue.PAUSED})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            UPDATE identity_stream_observed_states SET document_json = ? WHERE stream_id = ?
            """,
            (substituted.model_dump_json(), STREAM_ID),
        )

    assert rig.state.verify_integrity() is False


def test_sqlite_reconciliation_binding_tamper_fails_integrity(tmp_path: Path) -> None:
    database_path = tmp_path / "stream-reconciliation-tamper.db"
    rig = _rig(SqliteStateStore(database_path))
    rig.coordinator.request_status(
        SsfStreamStatusValue.ENABLED,
        correlation_id="req-enable-before-reconciliation-tamper",
    )
    result = rig.coordinator.reconcile(correlation_id="req-reconcile-before-tamper")
    with rig.state.transaction() as transaction:
        reconciliation = transaction.get_identity_stream_status_reconciliation(
            result.reconciliation_id
        )
    assert reconciliation is not None
    substituted = reconciliation.model_copy(
        update={"observed_status": IdentityStreamStatusValue.PAUSED}
    )
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            UPDATE identity_stream_status_reconciliations
            SET document_json = ? WHERE reconciliation_id = ?
            """,
            (substituted.model_dump_json(), result.reconciliation_id),
        )

    assert rig.state.verify_integrity() is False


def test_status_coordinator_configuration_and_response_binding_fail_closed() -> None:
    state = InMemoryStateStore()
    audit = AuditLedger(AUDIT_KEY, state=state)
    with pytest.raises(ValueError, match="share one transactional"):
        DurableSsfStreamStatusCoordinator(
            operator=ScriptedStatusOperator(),
            state=state,
            audit=AuditLedger(AUDIT_KEY, state=InMemoryStateStore()),
            stream_id=STREAM_ID,
        )
    with pytest.raises(ValueError, match="observed status age"):
        DurableSsfStreamStatusCoordinator(
            operator=ScriptedStatusOperator(),
            state=state,
            audit=audit,
            stream_id=STREAM_ID,
            max_observed_age=timedelta(0),
        )

    rig = _rig(state)
    rig.operator.returned_status = SsfStreamStatusValue.PAUSED
    with pytest.raises(SsfOperationError):
        rig.coordinator.request_status(
            SsfStreamStatusValue.ENABLED,
            correlation_id="req-substituted-response",
        )
    with rig.state.transaction() as transaction:
        operation = transaction.latest_identity_stream_status_operation(STREAM_ID)
    assert operation is not None
    assert operation.status is IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN

    wrong_stream = DurableSsfStreamStatusCoordinator(
        operator=ScriptedStatusOperator(),
        state=state,
        audit=rig.audit,
        stream_id="different-stream",
    )
    with pytest.raises(ValueError, match="share state and stream"):
        SharedSignalsReceiver(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_provider=_jwks_provider(rig.private_key),
            revocations=StateBackedRevocationProvider(
                state,
                stream_id=STREAM_ID,
                max_staleness=timedelta(minutes=5),
            ),
            audit=rig.audit,
            status_handler=wrong_stream,
        )


def _rig(
    state: PolarisStateStore,
    *,
    max_retry_delay: timedelta = timedelta(seconds=2),
    sleeper: Callable[[float], None] = lambda _: None,
) -> StatusRig:
    clock = MutableClock(datetime(2026, 8, 11, 12, tzinfo=UTC))
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    audit = AuditLedger(AUDIT_KEY, state=state, clock=clock)
    operator = ScriptedStatusOperator()
    coordinator = DurableSsfStreamStatusCoordinator(
        operator=operator,
        state=state,
        audit=audit,
        stream_id=STREAM_ID,
        max_observed_age=timedelta(seconds=10),
        max_retry_delay=max_retry_delay,
        sleeper=sleeper,
        jitter=lambda maximum: maximum,
        clock=clock,
    )
    revocations = StateBackedRevocationProvider(
        state,
        stream_id=STREAM_ID,
        max_staleness=timedelta(minutes=5),
        clock=clock,
        stream_health=coordinator,
    )
    receiver = SharedSignalsReceiver(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=_jwks_provider(private_key),
        revocations=revocations,
        audit=audit,
        clock=clock,
        status_handler=coordinator,
    )
    return StatusRig(
        state=state,
        audit=audit,
        clock=clock,
        operator=operator,
        coordinator=coordinator,
        revocations=revocations,
        receiver=receiver,
        private_key=private_key,
    )


def _stream_updated_set(
    private_key: rsa.RSAPrivateKey,
    now: datetime,
    *,
    event_id: str,
    status: str,
    reason: str | None = None,
    stream_id: str = STREAM_ID,
    event_time: datetime | None = None,
    event: dict[str, object] | None = None,
) -> str:
    event_payload: dict[str, object] = event or {"status": status}
    if event is None and reason is not None:
        event_payload["reason"] = reason
    event_payload.setdefault(
        "event_timestamp",
        int((event_time or now).timestamp()),
    )
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": int(now.timestamp()),
            "jti": event_id,
            "sub_id": {"format": "opaque", "id": stream_id},
            "events": {STREAM_UPDATED_EVENT: event_payload},
        },
        private_key,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": KEY_ID, "typ": "secevent+jwt"},
    )


def _jwks_provider(private_key: rsa.RSAPrivateKey) -> StaticJwksProvider:
    public = private_key.public_key().public_numbers()
    return StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": KEY_ID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _base64url_uint(public.n),
                    "e": _base64url_uint(public.e),
                }
            ]
        }
    )


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

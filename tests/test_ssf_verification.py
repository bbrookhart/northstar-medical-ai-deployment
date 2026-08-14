from __future__ import annotations

import base64
import hashlib
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from polaris.domain import IdentityStreamVerificationStatus
from polaris.security.auth import StaticJwksProvider
from polaris.security.identity_signals import (
    IdentitySignalValidationError,
    SharedSignalsReceiver,
    StateBackedRevocationProvider,
)
from polaris.security.signal_delivery import (
    JSON_MEDIA_TYPE,
    SET_MEDIA_TYPE,
    HashedBearerTransmitterAuthenticator,
    SharedSignalsPushService,
    SignalDeliveryError,
)
from polaris.security.ssf_operations import PendingSsfVerification, SsfOperationError
from polaris.security.ssf_verification import (
    DurableSsfVerificationCoordinator,
    SsfStreamHealthStatus,
    SsfUnsolicitedVerificationPolicy,
    SsfVerificationUnavailable,
)
from polaris.services.audit import AuditLedger
from polaris.services.state import InMemoryStateStore, PolarisStateStore, SqliteStateStore

ISSUER = "https://identity.northstar.example.test"
AUDIENCE = "polaris-identity-signals"
STREAM_ID = "enterprise-identity-stream"
TRANSMITTER_ID = "northstar-idp-transmitter"
KEY_ID = "northstar-verification-key-1"
AUDIT_KEY = "synthetic-audit-key-with-sufficient-entropy"
VERIFICATION_EVENT = "https://schemas.openid.net/secevent/ssf/event-type/verification"


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class ScriptedRequester:
    def __init__(self) -> None:
        self.states: list[str] = []
        self.callback: Callable[[str], object] | None = None
        self.failure: Exception | None = None

    def trigger_verification(
        self,
        stream_id: str,
        *,
        state: str | None = None,
    ) -> PendingSsfVerification:
        if state is None:
            raise AssertionError("Coordinator must request correlation state")
        self.states.append(state)
        if self.callback is not None:
            self.callback(state)
        if self.failure is not None:
            raise self.failure
        return PendingSsfVerification(stream_id=stream_id, state=state)


@dataclass(slots=True)
class VerificationRig:
    state: PolarisStateStore
    audit: AuditLedger
    clock: MutableClock
    requester: ScriptedRequester
    coordinator: DurableSsfVerificationCoordinator
    receiver: SharedSignalsReceiver
    private_key: rsa.RSAPrivateKey


def test_async_verification_receipt_is_durable_hashed_and_restart_safe(tmp_path: Path) -> None:
    database_path = tmp_path / "verification-state.db"
    rig = _rig(SqliteStateStore(database_path))

    pending = rig.coordinator.request(correlation_id="req-verify-async")
    plaintext_state = rig.requester.states[-1]

    assert pending.status is IdentityStreamVerificationStatus.PENDING
    assert pending.state_hash == hashlib.sha256(plaintext_state.encode()).hexdigest()
    assert rig.coordinator.health().status is SsfStreamHealthStatus.PENDING
    assert rig.coordinator.ready() is False
    with pytest.raises(SsfVerificationUnavailable):
        rig.coordinator.assert_healthy()

    token = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=plaintext_state,
        event_id="set-verification-async",
    )
    assert rig.receiver.accept(
        token,
        correlation_id="req-receive-async",
        transmitter_id=TRANSMITTER_ID,
    )

    with rig.state.transaction() as transaction:
        verified = transaction.get_identity_stream_verification(pending.verification_id)
        signal = transaction.get_identity_signal("set-verification-async")
        checkpoint = transaction.get_identity_stream_checkpoint(STREAM_ID)
    assert verified is not None
    assert verified.status is IdentityStreamVerificationStatus.VERIFIED
    assert verified.signal_id == "set-verification-async"
    assert signal is not None
    assert signal.verification_state_hash == pending.state_hash
    assert checkpoint is not None
    assert rig.coordinator.health().status is SsfStreamHealthStatus.HEALTHY
    rig.coordinator.assert_healthy()
    assert rig.coordinator.ready()
    assert plaintext_state.encode() not in database_path.read_bytes()
    assert plaintext_state not in str(rig.audit.snapshot())
    assert rig.audit.verify()

    restarted_state = SqliteStateStore(database_path)
    restarted_audit = AuditLedger(AUDIT_KEY, state=restarted_state, clock=rig.clock)
    restarted = DurableSsfVerificationCoordinator(
        requester=ScriptedRequester(),
        state=restarted_state,
        audit=restarted_audit,
        stream_id=STREAM_ID,
        verification_timeout=timedelta(seconds=5),
        max_verified_age=timedelta(seconds=10),
        clock=rig.clock,
    )
    assert restarted.health().status is SsfStreamHealthStatus.HEALTHY
    assert restarted.ready()
    assert restarted_audit.verify()


def test_synchronous_callback_race_is_correlated_before_dispatch_returns() -> None:
    rig = _rig(InMemoryStateStore())

    rig.requester.callback = lambda state: rig.receiver.accept(
        _verification_set(
            rig.private_key,
            rig.clock.now,
            state=state,
            event_id="set-verification-race",
        ),
        correlation_id="req-verification-race-delivery",
        transmitter_id=TRANSMITTER_ID,
    )

    verified = rig.coordinator.request(correlation_id="req-verification-race")

    assert verified.status is IdentityStreamVerificationStatus.VERIFIED
    assert verified.accepted_at is not None
    assert verified.signal_id == "set-verification-race"
    assert rig.coordinator.health().status is SsfStreamHealthStatus.HEALTHY
    assert [event.outcome for event in rig.audit.snapshot()].count(
        "SSF_VERIFICATION_CONFIRMED"
    ) == 1
    assert rig.audit.verify()


def test_confirmed_callback_wins_over_ambiguous_dispatch_failure() -> None:
    rig = _rig(InMemoryStateStore())
    rig.requester.callback = lambda state: rig.receiver.accept(
        _verification_set(
            rig.private_key,
            rig.clock.now,
            state=state,
            event_id="set-verification-before-failure",
        ),
        correlation_id="req-before-failure",
        transmitter_id=TRANSMITTER_ID,
    )
    rig.requester.failure = SsfOperationError("synthetic response path failed")

    result = rig.coordinator.request(correlation_id="req-ambiguous-dispatch")

    assert result.status is IdentityStreamVerificationStatus.VERIFIED
    assert rig.coordinator.health().status is SsfStreamHealthStatus.HEALTHY
    assert "SSF_VERIFICATION_DISPATCH_FAILED" not in {
        event.outcome for event in rig.audit.snapshot()
    }


def test_wrong_or_reused_state_returns_registered_invalid_state_without_commit() -> None:
    rig = _rig(InMemoryStateStore())
    pending = rig.coordinator.request(correlation_id="req-verification-state")
    expected_state = rig.requester.states[-1]
    delivery = _push_service(rig)
    context = delivery.authenticate_request(
        stream_id=STREAM_ID,
        authorization=f"Bearer {'x' * 32}",
        content_type=SET_MEDIA_TYPE,
        accept=JSON_MEDIA_TYPE,
        correlation_id="req-authenticated-verification",
    )
    wrong = _verification_set(
        rig.private_key,
        rig.clock.now,
        state="different-correlation-state",
        event_id="set-verification-wrong-state",
    )

    with pytest.raises(SignalDeliveryError) as wrong_error:
        delivery.deliver(context, wrong.encode(), correlation_id="req-wrong-state")
    assert wrong_error.value.error_code == "invalid_state"
    with rig.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-verification-wrong-state") is None
        unchanged = transaction.get_identity_stream_verification(pending.verification_id)
    assert unchanged is not None
    assert unchanged.status is IdentityStreamVerificationStatus.PENDING

    accepted = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=expected_state,
        event_id="set-verification-single-use",
    )
    assert rig.receiver.accept(accepted, correlation_id="req-single-use")
    assert rig.receiver.accept(accepted, correlation_id="req-exact-replay") is False
    reused = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=expected_state,
        event_id="set-verification-reused-state",
    )
    with pytest.raises(IdentitySignalValidationError) as reuse_error:
        rig.receiver.accept(reused, correlation_id="req-reused-state")
    assert reuse_error.value.delivery_error_code == "invalid_state"
    with rig.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-verification-reused-state") is None
    assert rig.audit.verify()


@pytest.mark.parametrize(
    ("stream_id", "event"),
    [
        ("different-stream", {"state": "expected-state"}),
        (STREAM_ID, {"state": "line\nbreak"}),
        (STREAM_ID, {"state": None}),
        (STREAM_ID, {"unexpected": "member"}),
    ],
)
def test_verification_event_requires_bound_stream_and_valid_shape(
    stream_id: str,
    event: dict[str, object],
) -> None:
    rig = _rig(InMemoryStateStore())
    token = _verification_set(
        rig.private_key,
        rig.clock.now,
        state="unused",
        event_id="set-invalid-verification-shape",
        stream_id=stream_id,
        event=event,
    )

    with pytest.raises(IdentitySignalValidationError) as raised:
        rig.receiver.accept(token, correlation_id="req-invalid-verification-shape")

    assert raised.value.delivery_error_code == "invalid_state"


def test_unsolicited_verification_is_rejected_by_default_policy() -> None:
    rig = _rig(InMemoryStateStore())
    token = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=None,
        event_id="set-unsolicited-rejected",
    )

    with pytest.raises(IdentitySignalValidationError) as raised:
        rig.receiver.accept(token, correlation_id="req-unsolicited-rejected")

    assert raised.value.delivery_error_code == "access_denied"
    with rig.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-unsolicited-rejected") is None
        assert transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID) is None
        assert transaction.get_identity_stream_checkpoint(STREAM_ID) is None
    assert rig.audit.snapshot()[-1].outcome == "IDENTITY_SIGNAL_ACCESS_DENIED"


def test_unsolicited_delivery_only_receipt_is_durable_and_health_isolated(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "unsolicited-verification.db"
    rig = _rig(
        SqliteStateStore(database_path),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
    )
    pending = rig.coordinator.request(correlation_id="req-correlated-pending")
    token = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=None,
        event_id="set-unsolicited-accepted",
    )

    assert rig.receiver.accept(token, correlation_id="req-unsolicited-accepted")

    with rig.state.transaction() as transaction:
        unchanged = transaction.get_identity_stream_verification(pending.verification_id)
        receipt = transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID)
        signal = transaction.get_identity_signal("set-unsolicited-accepted")
        checkpoint = transaction.get_identity_stream_checkpoint(STREAM_ID)
    assert unchanged is not None
    assert unchanged.status is IdentityStreamVerificationStatus.PENDING
    assert receipt is not None
    assert receipt.accepted_count == 1
    assert receipt.last_signal_id == "set-unsolicited-accepted"
    assert signal is not None and signal.verification_state_hash is None
    assert checkpoint is not None
    assert rig.coordinator.health().status is SsfStreamHealthStatus.PENDING
    assert rig.coordinator.ready() is False
    assert "SSF_UNSOLICITED_VERIFICATION_ACCEPTED" in {
        event.outcome for event in rig.audit.snapshot()
    }
    assert rig.audit.verify()

    restarted = _rig(
        SqliteStateStore(database_path),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
    )
    with restarted.state.transaction() as transaction:
        persisted = transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID)
    assert persisted == receipt
    assert restarted.coordinator.health().status is SsfStreamHealthStatus.PENDING


def test_delivery_only_policy_does_not_accept_uncorrelated_state() -> None:
    rig = _rig(
        InMemoryStateStore(),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
    )
    token = _verification_set(
        rig.private_key,
        rig.clock.now,
        state="transmitter-must-not-invent-state",
        event_id="set-unsolicited-with-state",
    )

    with pytest.raises(IdentitySignalValidationError) as raised:
        rig.receiver.accept(token, correlation_id="req-unsolicited-with-state")

    assert raised.value.delivery_error_code == "invalid_state"
    with rig.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-unsolicited-with-state") is None
        assert transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID) is None


def test_unsolicited_verification_rate_limit_replay_and_window_reset_are_durable(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "unsolicited-rate-limit.db"
    rig = _rig(
        SqliteStateStore(database_path),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
        unsolicited_window=timedelta(seconds=10),
        max_unsolicited_per_window=2,
    )
    first = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=None,
        event_id="set-unsolicited-first",
    )
    second = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=None,
        event_id="set-unsolicited-second",
    )
    assert rig.receiver.accept(first, correlation_id="req-unsolicited-first")
    assert rig.receiver.accept(first, correlation_id="req-unsolicited-replay") is False
    assert rig.receiver.accept(second, correlation_id="req-unsolicited-second")

    restarted = _rig(
        SqliteStateStore(database_path),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
        unsolicited_window=timedelta(seconds=10),
        max_unsolicited_per_window=2,
    )
    third = _verification_set(
        restarted.private_key,
        restarted.clock.now,
        state=None,
        event_id="set-unsolicited-rate-limited",
    )
    with pytest.raises(IdentitySignalValidationError) as raised:
        restarted.receiver.accept(third, correlation_id="req-unsolicited-rate-limited")
    assert raised.value.delivery_error_code == "access_denied"
    with restarted.state.transaction() as transaction:
        assert transaction.get_identity_signal("set-unsolicited-rate-limited") is None
        limited = transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID)
    assert limited is not None and limited.accepted_count == 2
    assert restarted.audit.snapshot()[-1].outcome == "IDENTITY_SIGNAL_ACCESS_DENIED"

    restarted.clock.advance(timedelta(seconds=10))
    after_window = _verification_set(
        restarted.private_key,
        restarted.clock.now,
        state=None,
        event_id="set-unsolicited-new-window",
    )
    assert restarted.receiver.accept(after_window, correlation_id="req-unsolicited-new-window")
    with restarted.state.transaction() as transaction:
        reset = transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID)
    assert reset is not None
    assert reset.accepted_count == 1
    assert reset.window_started_at == restarted.clock.now
    assert restarted.coordinator.health().status is SsfStreamHealthStatus.UNKNOWN


def test_unsolicited_rate_limit_maps_to_push_access_denied() -> None:
    rig = _rig(
        InMemoryStateStore(),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
        max_unsolicited_per_window=1,
    )
    delivery = _push_service(rig)
    context = delivery.authenticate_request(
        stream_id=STREAM_ID,
        authorization=f"Bearer {'x' * 32}",
        content_type=SET_MEDIA_TYPE,
        accept=JSON_MEDIA_TYPE,
        correlation_id="req-auth-unsolicited-limit",
    )
    first = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=None,
        event_id="set-push-unsolicited-first",
    )
    second = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=None,
        event_id="set-push-unsolicited-second",
    )
    delivery.deliver(context, first.encode(), correlation_id="req-push-unsolicited-first")
    with pytest.raises(SignalDeliveryError) as raised:
        delivery.deliver(context, second.encode(), correlation_id="req-push-unsolicited-second")
    assert raised.value.error_code == "access_denied"


def test_unsolicited_quota_is_atomic_under_concurrent_delivery(tmp_path: Path) -> None:
    rig = _rig(
        SqliteStateStore(tmp_path / "concurrent-unsolicited.db"),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
        max_unsolicited_per_window=2,
    )
    event_ids = tuple(f"set-unsolicited-concurrent-{index}" for index in range(4))
    tokens = tuple(
        _verification_set(
            rig.private_key,
            rig.clock.now,
            state=None,
            event_id=event_id,
        )
        for event_id in event_ids
    )
    barrier = Barrier(len(tokens))

    def deliver(index: int) -> bool | str:
        barrier.wait()
        try:
            return rig.receiver.accept(
                tokens[index],
                correlation_id=f"req-unsolicited-concurrent-{index}",
            )
        except IdentitySignalValidationError as exc:
            return exc.delivery_error_code

    with ThreadPoolExecutor(max_workers=len(tokens)) as pool:
        results = list(pool.map(deliver, range(len(tokens))))

    assert results.count(True) == 2
    assert results.count("access_denied") == 2
    with rig.state.transaction() as transaction:
        receipt = transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID)
        committed = sum(
            transaction.get_identity_signal(event_id) is not None for event_id in event_ids
        )
    assert receipt is not None and receipt.accepted_count == 2
    assert committed == 2
    assert rig.audit.verify()


def test_timeout_expires_pending_challenge_and_late_event_fails_closed(tmp_path: Path) -> None:
    database_path = tmp_path / "verification-timeout.db"
    rig = _rig(SqliteStateStore(database_path))
    pending = rig.coordinator.request(correlation_id="req-verification-timeout")
    plaintext_state = rig.requester.states[-1]
    rig.clock.advance(timedelta(seconds=5))

    first_health = rig.coordinator.health()
    second_health = rig.coordinator.health()

    assert first_health.status is SsfStreamHealthStatus.UNHEALTHY
    assert second_health == first_health
    with rig.state.transaction() as transaction:
        expired = transaction.get_identity_stream_verification(pending.verification_id)
    assert expired is not None
    assert expired.status is IdentityStreamVerificationStatus.EXPIRED
    assert [event.outcome for event in rig.audit.snapshot()].count("SSF_VERIFICATION_EXPIRED") == 1
    late = _verification_set(
        rig.private_key,
        rig.clock.now,
        state=plaintext_state,
        event_id="set-verification-late",
    )
    with pytest.raises(IdentitySignalValidationError) as raised:
        rig.receiver.accept(late, correlation_id="req-verification-late")
    assert raised.value.delivery_error_code == "invalid_state"
    assert rig.coordinator.ready() is False
    with pytest.raises(SsfVerificationUnavailable):
        rig.coordinator.assert_healthy()
    assert rig.audit.verify()

    restarted = _rig(SqliteStateStore(database_path))
    assert restarted.coordinator.health().status is SsfStreamHealthStatus.UNHEALTHY


def test_fresh_success_remains_healthy_during_new_probe_then_timeout_marks_unhealthy() -> None:
    rig = _rig(InMemoryStateStore())
    first = rig.coordinator.request(correlation_id="req-first-verification")
    first_state = rig.requester.states[-1]
    rig.receiver.accept(
        _verification_set(
            rig.private_key,
            rig.clock.now,
            state=first_state,
            event_id="set-first-verification",
        ),
        correlation_id="req-first-receipt",
    )
    assert first.status is IdentityStreamVerificationStatus.PENDING
    assert rig.coordinator.health().status is SsfStreamHealthStatus.HEALTHY

    second = rig.coordinator.request(correlation_id="req-second-verification")
    health_during_probe = rig.coordinator.health()

    assert second.status is IdentityStreamVerificationStatus.PENDING
    assert health_during_probe.status is SsfStreamHealthStatus.HEALTHY
    assert health_during_probe.pending_verification_id == second.verification_id
    rig.clock.advance(timedelta(seconds=5))
    assert rig.coordinator.health().status is SsfStreamHealthStatus.UNHEALTHY


def test_verified_health_becomes_stale_and_dispatch_failure_is_durable() -> None:
    rig = _rig(InMemoryStateStore())
    rig.coordinator.request(correlation_id="req-stale-verification")
    rig.receiver.accept(
        _verification_set(
            rig.private_key,
            rig.clock.now,
            state=rig.requester.states[-1],
            event_id="set-stale-verification",
        ),
        correlation_id="req-stale-receipt",
    )
    rig.clock.advance(timedelta(seconds=11))
    assert rig.coordinator.health().status is SsfStreamHealthStatus.STALE
    with pytest.raises(SsfVerificationUnavailable):
        rig.coordinator.assert_healthy()

    failing_rig = _rig(InMemoryStateStore())
    failing_rig.requester.failure = SsfOperationError("synthetic upstream detail")
    with pytest.raises(SsfOperationError) as raised:
        failing_rig.coordinator.request(correlation_id="req-dispatch-failure")
    assert "synthetic upstream detail" not in str(raised.value)
    with failing_rig.state.transaction() as transaction:
        failed = transaction.latest_identity_stream_verification(STREAM_ID)
    assert failed is not None
    assert failed.status is IdentityStreamVerificationStatus.FAILED
    assert failing_rig.coordinator.health().status is SsfStreamHealthStatus.UNHEALTHY
    assert failing_rig.audit.verify()


def test_verification_record_binding_tamper_fails_sqlite_integrity(tmp_path: Path) -> None:
    database_path = tmp_path / "verification-tamper.db"
    rig = _rig(SqliteStateStore(database_path))
    record = rig.coordinator.request(correlation_id="req-verification-tamper")
    substituted = record.model_copy(update={"stream_id": "substituted-stream"})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            UPDATE identity_stream_verifications SET document_json = ?
            WHERE verification_id = ?
            """,
            (substituted.model_dump_json(), record.verification_id),
        )

    assert rig.state.verify_integrity() is False


def test_unsolicited_receipt_binding_tamper_fails_sqlite_integrity(tmp_path: Path) -> None:
    database_path = tmp_path / "unsolicited-verification-tamper.db"
    rig = _rig(
        SqliteStateStore(database_path),
        unsolicited_policy=SsfUnsolicitedVerificationPolicy.ACCEPT_DELIVERY_ONLY,
    )
    rig.receiver.accept(
        _verification_set(
            rig.private_key,
            rig.clock.now,
            state=None,
            event_id="set-unsolicited-before-tamper",
        ),
        correlation_id="req-unsolicited-before-tamper",
    )
    with rig.state.transaction() as transaction:
        receipt = transaction.get_identity_stream_unsolicited_verification_state(STREAM_ID)
    assert receipt is not None
    substituted = receipt.model_copy(update={"accepted_count": 2})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            UPDATE identity_stream_unsolicited_verifications SET document_json = ?
            WHERE stream_id = ?
            """,
            (substituted.model_dump_json(), STREAM_ID),
        )

    assert rig.state.verify_integrity() is False


def test_coordinator_and_receiver_configuration_fail_closed() -> None:
    state = InMemoryStateStore()
    audit = AuditLedger(AUDIT_KEY, state=state)
    other_audit = AuditLedger(AUDIT_KEY, state=InMemoryStateStore())
    requester = ScriptedRequester()
    with pytest.raises(ValueError, match="share one transactional"):
        DurableSsfVerificationCoordinator(
            requester=requester,
            state=state,
            audit=other_audit,
            stream_id=STREAM_ID,
        )
    with pytest.raises(ValueError, match="timeout"):
        DurableSsfVerificationCoordinator(
            requester=requester,
            state=state,
            audit=audit,
            stream_id=STREAM_ID,
            verification_timeout=timedelta(0),
        )
    with pytest.raises(ValueError, match="verified age"):
        DurableSsfVerificationCoordinator(
            requester=requester,
            state=state,
            audit=audit,
            stream_id=STREAM_ID,
            max_verified_age=timedelta(days=2),
        )
    with pytest.raises(ValueError, match="unsolicited verification policy"):
        DurableSsfVerificationCoordinator(
            requester=requester,
            state=state,
            audit=audit,
            stream_id=STREAM_ID,
            unsolicited_policy="ACCEPT_DELIVERY_ONLY",  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="unsolicited verification window"):
        DurableSsfVerificationCoordinator(
            requester=requester,
            state=state,
            audit=audit,
            stream_id=STREAM_ID,
            unsolicited_window=timedelta(0),
        )
    with pytest.raises(ValueError, match="unsolicited verification limit"):
        DurableSsfVerificationCoordinator(
            requester=requester,
            state=state,
            audit=audit,
            stream_id=STREAM_ID,
            max_unsolicited_per_window=101,
        )

    rig = _rig(state)
    wrong_stream_handler = DurableSsfVerificationCoordinator(
        requester=requester,
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
            verification_handler=wrong_stream_handler,
        )


def _rig(
    state: PolarisStateStore,
    *,
    unsolicited_policy: SsfUnsolicitedVerificationPolicy = (
        SsfUnsolicitedVerificationPolicy.REJECT
    ),
    unsolicited_window: timedelta = timedelta(minutes=1),
    max_unsolicited_per_window: int = 5,
) -> VerificationRig:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    clock = MutableClock(now)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    audit = AuditLedger(AUDIT_KEY, state=state, clock=clock)
    requester = ScriptedRequester()
    coordinator = DurableSsfVerificationCoordinator(
        requester=requester,
        state=state,
        audit=audit,
        stream_id=STREAM_ID,
        verification_timeout=timedelta(seconds=5),
        max_verified_age=timedelta(seconds=10),
        unsolicited_policy=unsolicited_policy,
        unsolicited_window=unsolicited_window,
        max_unsolicited_per_window=max_unsolicited_per_window,
        clock=clock,
    )
    revocations = StateBackedRevocationProvider(
        state,
        stream_id=STREAM_ID,
        max_staleness=timedelta(minutes=5),
        clock=clock,
    )
    receiver = SharedSignalsReceiver(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=_jwks_provider(private_key),
        revocations=revocations,
        audit=audit,
        clock=clock,
        verification_handler=coordinator,
    )
    return VerificationRig(
        state=state,
        audit=audit,
        clock=clock,
        requester=requester,
        coordinator=coordinator,
        receiver=receiver,
        private_key=private_key,
    )


def _push_service(rig: VerificationRig) -> SharedSignalsPushService:
    bearer = "x" * 32
    return SharedSignalsPushService(
        receiver=rig.receiver,
        authenticator=HashedBearerTransmitterAuthenticator(
            transmitter_id=TRANSMITTER_ID,
            expected_token_sha256=hashlib.sha256(bearer.encode()).hexdigest(),
        ),
        audit=rig.audit,
        stream_id=STREAM_ID,
    )


def _verification_set(
    private_key: rsa.RSAPrivateKey,
    now: datetime,
    *,
    state: str | None,
    event_id: str,
    stream_id: str = STREAM_ID,
    event: dict[str, object] | None = None,
) -> str:
    event_payload = event if event is not None else ({} if state is None else {"state": state})
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": int(now.timestamp()),
            "jti": event_id,
            "sub_id": {"format": "opaque", "id": stream_id},
            "events": {VERIFICATION_EVENT: event_payload},
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

from __future__ import annotations

import base64
import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from polaris.config import Settings
from polaris.domain import IdentitySignalType
from polaris.errors import AuthenticationError
from polaris.main import create_app
from polaris.security.auth import OidcAccessTokenAuthenticator, StaticJwksProvider
from polaris.security.identity_signals import (
    IdentitySignalUnavailable,
    IdentitySignalValidationError,
    SharedSignalsReceiver,
    StateBackedRevocationProvider,
)
from polaris.services.audit import AuditLedger
from polaris.services.state import InMemoryStateStore, SqliteStateStore, StateIntegrityError

ISSUER = "https://identity.northstar.example.test"
AUDIENCE = "polaris-identity-signals"
API_AUDIENCE = "polaris-api"
KEY_ID = "northstar-identity-signal-key-1"


class MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


@pytest.fixture(scope="module")
def signal_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def signal_jwks(signal_private_key: rsa.RSAPrivateKey) -> StaticJwksProvider:
    numbers = signal_private_key.public_key().public_numbers()
    return StaticJwksProvider(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": KEY_ID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _base64url_uint(numbers.n),
                    "e": _base64url_uint(numbers.e),
                }
            ]
        }
    )


def test_subject_signal_watermark_survives_restart_and_never_regresses(
    tmp_path: Path,
    settings: Settings,
    signal_private_key: rsa.RSAPrivateKey,
    signal_jwks: StaticJwksProvider,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = MutableClock(now)
    database_path = tmp_path / "identity-state.db"
    state = SqliteStateStore(database_path)
    audit = AuditLedger(settings.audit_hmac_key, clock=clock, state=state)
    revocations = StateBackedRevocationProvider(
        state,
        stream_id="enterprise-identity-stream",
        max_staleness=timedelta(minutes=5),
        clock=clock,
    )
    receiver = _receiver(signal_jwks, revocations, audit, clock)
    revocations.record_stream_success()
    authenticator = _authenticator(signal_jwks, revocations, clock)
    old_token = _access_token(signal_private_key, now, token_id="tok-before-signal")
    new_token = _access_token(
        signal_private_key,
        now,
        token_id="tok-after-signal",
        issued_at=now - timedelta(seconds=5),
    )
    assert authenticator.authenticate(old_token).subject == "user-care-1"

    applied = receiver.accept(
        _subject_set(
            signal_private_key,
            now,
            event_id="set-session-revoked-1",
            event_time=now - timedelta(seconds=10),
        ),
        correlation_id="req-signal-1",
    )
    assert applied is True
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(old_token)
    assert authenticator.authenticate(new_token).token_id == "tok-after-signal"

    receiver.accept(
        _subject_claims_set(
            signal_private_key,
            now,
            event_id="set-subject-entitlements-1",
            event_time=now - timedelta(seconds=8),
        ),
        correlation_id="req-entitlement-signal",
    )
    assert authenticator.authenticate(new_token).token_id == "tok-after-signal"

    receiver.accept(
        _subject_set(
            signal_private_key,
            now,
            event_id="set-session-revoked-older",
            event_time=now - timedelta(minutes=2),
        ),
        correlation_id="req-signal-older",
    )
    with state.transaction() as transaction:
        subject_state = transaction.get_identity_subject_state("user-care-1")
    assert subject_state is not None
    assert subject_state.invalid_before == now - timedelta(seconds=8)

    restarted_state = SqliteStateStore(database_path)
    restarted_revocations = StateBackedRevocationProvider(
        restarted_state,
        stream_id="enterprise-identity-stream",
        max_staleness=timedelta(minutes=5),
        clock=clock,
    )
    restarted_authenticator = _authenticator(signal_jwks, restarted_revocations, clock)
    with pytest.raises(AuthenticationError):
        restarted_authenticator.authenticate(old_token)
    assert restarted_authenticator.authenticate(new_token).token_id == "tok-after-signal"
    assert restarted_revocations.ready()
    assert audit.verify()

    with restarted_state.transaction() as transaction:
        signal = transaction.get_identity_signal("set-session-revoked-1")
    assert signal is not None
    substituted = signal.model_copy(update={"event_id": "set-substituted"})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE identity_signals SET document_json = ? WHERE event_id = ?",
            (substituted.model_dump_json(), signal.event_id),
        )
    assert restarted_state.verify_integrity() is False
    assert restarted_revocations.ready() is False


def test_final_ssf_credential_change_invalidates_subject_sessions(
    settings: Settings,
    signal_private_key: rsa.RSAPrivateKey,
    signal_jwks: StaticJwksProvider,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = MutableClock(now)
    state = InMemoryStateStore()
    audit = AuditLedger(settings.audit_hmac_key, clock=clock, state=state)
    revocations = StateBackedRevocationProvider(
        state,
        stream_id="enterprise-identity-stream",
        max_staleness=timedelta(minutes=5),
        clock=clock,
    )
    receiver = _receiver(signal_jwks, revocations, audit, clock)
    revocations.record_stream_success()
    authenticator = _authenticator(signal_jwks, revocations, clock)
    token = _access_token(signal_private_key, now, token_id="tok-before-credential-change")

    changed = _set_token(
        signal_private_key,
        now,
        event_id="set-credential-change-1",
        subject_id={"format": "iss_sub", "iss": ISSUER, "sub": "user-care-1"},
        events={
            IdentitySignalType.CREDENTIAL_CHANGE.value: {
                "subject": {"format": "iss_sub", "iss": ISSUER, "sub": "user-care-1"},
                "credential_type": "password",
                "change_type": "update",
                "event_timestamp": int(now.timestamp()),
                "initiating_entity": "user",
                "reason_admin": {"en": "Password changed"},
            }
        },
    )
    assert receiver.accept(changed, correlation_id="req-credential-change") is True
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(token)

    invalid = _set_token(
        signal_private_key,
        now,
        event_id="set-credential-change-invalid",
        events={
            IdentitySignalType.CREDENTIAL_CHANGE.value: {
                "subject": {"format": "iss_sub", "iss": ISSUER, "sub": "different-user"},
                "credential_type": "password",
                "change_type": "update",
            }
        },
    )
    with pytest.raises(IdentitySignalValidationError):
        receiver.accept(invalid, correlation_id="req-credential-change-invalid")


def test_token_claim_change_is_targeted_replay_safe_and_collision_detecting(
    settings: Settings,
    signal_private_key: rsa.RSAPrivateKey,
    signal_jwks: StaticJwksProvider,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = MutableClock(now)
    state = InMemoryStateStore()
    audit = AuditLedger(settings.audit_hmac_key, clock=clock, state=state)
    revocations = StateBackedRevocationProvider(
        state,
        stream_id="enterprise-identity-stream",
        max_staleness=timedelta(minutes=2),
        clock=clock,
    )
    receiver = _receiver(signal_jwks, revocations, audit, clock)
    revocations.record_stream_success()
    authenticator = _authenticator(signal_jwks, revocations, clock)
    targeted = _access_token(signal_private_key, now, token_id="tok-claims-changed")
    unaffected = _access_token(signal_private_key, now, token_id="tok-unaffected")
    signal_token = _token_set(
        signal_private_key,
        now,
        event_id="set-token-claims-1",
        token_id="tok-claims-changed",
        event_time=now - timedelta(seconds=5),
    )

    assert receiver.accept(signal_token, correlation_id="req-token-signal") is True
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(targeted)
    assert authenticator.authenticate(unaffected).token_id == "tok-unaffected"

    with state.transaction() as transaction:
        checkpoint_before = transaction.get_identity_stream_checkpoint("enterprise-identity-stream")
    clock.current += timedelta(seconds=30)
    assert receiver.accept(signal_token, correlation_id="req-token-replay") is False
    with state.transaction() as transaction:
        checkpoint_after = transaction.get_identity_stream_checkpoint("enterprise-identity-stream")
    assert checkpoint_before == checkpoint_after

    collision = _token_set(
        signal_private_key,
        clock.current,
        event_id="set-token-claims-1",
        token_id="tok-different",
        event_time=now,
    )
    with pytest.raises(StateIntegrityError):
        receiver.accept(collision, correlation_id="req-token-collision")
    outcomes = [event.outcome for event in audit.snapshot()]
    assert "IDENTITY_SIGNAL_IDEMPOTENT_REPLAY" in outcomes
    assert "IDENTITY_SIGNAL_REPLAY_COLLISION" in outcomes
    assert audit.verify()


def test_stale_or_missing_signal_stream_fails_authentication_and_readiness(
    tmp_path: Path,
    settings: Settings,
    signal_private_key: rsa.RSAPrivateKey,
    signal_jwks: StaticJwksProvider,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = MutableClock(now)
    state = SqliteStateStore(tmp_path / "stale-identity-state.db")
    revocations = StateBackedRevocationProvider(
        state,
        stream_id="enterprise-identity-stream",
        max_staleness=timedelta(seconds=30),
        clock=clock,
    )
    authenticator = _authenticator(signal_jwks, revocations, clock)
    token = _access_token(signal_private_key, now, token_id="tok-stream-freshness")

    with pytest.raises(IdentitySignalUnavailable):
        authenticator.authenticate(token)
    with TestClient(
        create_app(settings, clock=clock, authenticator=authenticator, state_store=state)
    ) as client:
        assert client.get("/health/ready").json() == {"status": "not-ready"}
        revocations.record_stream_success()
        assert client.get("/health/ready").json() == {"status": "ready"}
        allowed = client.get(
            "/v1/patients/SYN-P1001/summary",
            headers=_headers(token),
        )
        assert allowed.status_code == 200

        clock.current += timedelta(seconds=31)
        assert client.get("/health/ready").json() == {"status": "not-ready"}
        denied = client.get(
            "/v1/patients/SYN-P1001/summary",
            headers=_headers(token),
        )
        assert denied.status_code == 503
        assert denied.json()["code"] == "IDENTITY_SIGNAL_UNAVAILABLE"


def test_identity_signal_configuration_and_checkpoint_times_fail_closed(
    settings: Settings,
    signal_jwks: StaticJwksProvider,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = MutableClock(now)
    state = InMemoryStateStore()
    audit = AuditLedger(settings.audit_hmac_key, clock=clock, state=state)

    with pytest.raises(ValueError, match="staleness"):
        StateBackedRevocationProvider(
            state,
            stream_id="stream",
            max_staleness=timedelta(0),
            clock=clock,
        )
    revocations = StateBackedRevocationProvider(
        state,
        stream_id="stream",
        max_staleness=timedelta(minutes=5),
        clock=clock,
    )
    with pytest.raises(ValueError, match="checkpoint"):
        revocations.record_stream_success(now.replace(tzinfo=None))
    with pytest.raises(ValueError, match="checkpoint"):
        revocations.record_stream_success(now + timedelta(seconds=121))

    with pytest.raises(ValueError, match="issuer"):
        SharedSignalsReceiver(
            issuer="http://identity.example.test",
            audience=AUDIENCE,
            jwks_provider=signal_jwks,
            revocations=revocations,
            audit=audit,
            clock=clock,
        )
    with pytest.raises(ValueError, match="audience"):
        SharedSignalsReceiver(
            issuer=ISSUER,
            audience="",
            jwks_provider=signal_jwks,
            revocations=revocations,
            audit=audit,
            clock=clock,
        )
    with pytest.raises(ValueError, match="Maximum SET age"):
        SharedSignalsReceiver(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_provider=signal_jwks,
            revocations=revocations,
            audit=audit,
            max_set_age=timedelta(0),
            clock=clock,
        )
    with pytest.raises(ValueError, match="leeway"):
        SharedSignalsReceiver(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_provider=signal_jwks,
            revocations=revocations,
            audit=audit,
            leeway_seconds=121,
            clock=clock,
        )
    other_audit = AuditLedger(settings.audit_hmac_key, state=InMemoryStateStore())
    with pytest.raises(ValueError, match="share one transactional"):
        SharedSignalsReceiver(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_provider=signal_jwks,
            revocations=revocations,
            audit=other_audit,
            clock=clock,
        )


@pytest.mark.parametrize(
    "case",
    [
        "wrong-type",
        "wrong-audience",
        "access-token-sub",
        "forbidden-expiry",
        "multiple-events",
        "unknown-event",
        "untrusted-subject-issuer",
        "over-age",
        "token-url-header",
        "wrong-signature",
        "unknown-key",
    ],
)
def test_invalid_or_confusable_security_event_tokens_are_rejected_and_audited(
    case: str,
    settings: Settings,
    signal_private_key: rsa.RSAPrivateKey,
    signal_jwks: StaticJwksProvider,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    clock = MutableClock(now)
    state = InMemoryStateStore()
    audit = AuditLedger(settings.audit_hmac_key, clock=clock, state=state)
    revocations = StateBackedRevocationProvider(
        state,
        stream_id="enterprise-identity-stream",
        max_staleness=timedelta(minutes=5),
        clock=clock,
    )
    receiver = _receiver(signal_jwks, revocations, audit, clock)
    token = _invalid_set(case, signal_private_key, now)

    with pytest.raises(IdentitySignalValidationError):
        receiver.accept(token, correlation_id=f"req-invalid-{case}")
    assert audit.snapshot()[-1].outcome == "IDENTITY_SIGNAL_REJECTED"
    assert audit.verify()


def _receiver(
    jwks: StaticJwksProvider,
    revocations: StateBackedRevocationProvider,
    audit: AuditLedger,
    clock: Callable[[], datetime],
) -> SharedSignalsReceiver:
    return SharedSignalsReceiver(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=jwks,
        revocations=revocations,
        audit=audit,
        clock=clock,
    )


def _authenticator(
    jwks: StaticJwksProvider,
    revocations: StateBackedRevocationProvider,
    clock: Callable[[], datetime],
) -> OidcAccessTokenAuthenticator:
    return OidcAccessTokenAuthenticator(
        issuer=ISSUER,
        audience=API_AUDIENCE,
        jwks_provider=jwks,
        revocations=revocations,
        clock=clock,
    )


def _access_token(
    key: rsa.RSAPrivateKey,
    now: datetime,
    *,
    token_id: str,
    issued_at: datetime | None = None,
) -> str:
    issued = issued_at or now - timedelta(seconds=30)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": API_AUDIENCE,
            "sub": "user-care-1",
            "jti": token_id,
            "client_id": "polaris-web",
            "iat": issued,
            "exp": now + timedelta(minutes=10),
            "scope": "polaris.patient.read",
            "roles": ["care_coordinator"],
            "facilities": ["FAC-NORTH"],
            "assigned_patients": ["SYN-P1001"],
        },
        key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": KEY_ID},
    )


def _subject_set(
    key: rsa.RSAPrivateKey,
    issued_at: datetime,
    *,
    event_id: str,
    event_time: datetime,
) -> str:
    return _set_token(
        key,
        issued_at,
        event_id=event_id,
        subject_id={"format": "iss_sub", "iss": ISSUER, "sub": "user-care-1"},
        events={
            IdentitySignalType.SESSION_REVOKED.value: {
                "event_timestamp": int(event_time.timestamp())
            }
        },
    )


def _token_set(
    key: rsa.RSAPrivateKey,
    issued_at: datetime,
    *,
    event_id: str,
    token_id: str,
    event_time: datetime,
) -> str:
    return _set_token(
        key,
        issued_at,
        event_id=event_id,
        subject_id={"format": "jwt_id", "iss": ISSUER, "jti": token_id},
        events={
            IdentitySignalType.TOKEN_CLAIMS_CHANGE.value: {
                "event_timestamp": int(event_time.timestamp()),
                "claims": {"roles": ["updated-role"]},
            }
        },
    )


def _subject_claims_set(
    key: rsa.RSAPrivateKey,
    issued_at: datetime,
    *,
    event_id: str,
    event_time: datetime,
) -> str:
    return _set_token(
        key,
        issued_at,
        event_id=event_id,
        subject_id={"format": "iss_sub", "iss": ISSUER, "sub": "user-care-1"},
        events={
            IdentitySignalType.TOKEN_CLAIMS_CHANGE.value: {
                "event_timestamp": int(event_time.timestamp()),
                "claims": {"roles": ["updated-role"]},
            }
        },
    )


def _set_token(
    key: rsa.RSAPrivateKey,
    issued_at: datetime,
    *,
    event_id: str = "set-valid-1",
    subject_id: dict[str, object] | None = None,
    events: dict[str, object] | None = None,
    issuer: str = ISSUER,
    audience: object = AUDIENCE,
    headers: dict[str, str] | None = None,
    extra: dict[str, object] | None = None,
) -> str:
    claims: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "iat": int(issued_at.timestamp()),
        "jti": event_id,
        "sub_id": subject_id or {"format": "iss_sub", "iss": ISSUER, "sub": "user-care-1"},
        "events": events
        or {
            IdentitySignalType.SESSION_REVOKED.value: {
                "event_timestamp": int(issued_at.timestamp())
            }
        },
    }
    claims.update(extra or {})
    token_headers = {"typ": "secevent+jwt", "kid": KEY_ID}
    token_headers.update(headers or {})
    return jwt.encode(claims, key, algorithm="RS256", headers=token_headers)


def _invalid_set(case: str, key: rsa.RSAPrivateKey, now: datetime) -> str:
    kwargs: dict[str, Any] = {}
    signing_key = key
    if case == "wrong-type":
        kwargs["headers"] = {"typ": "at+jwt"}
    elif case == "wrong-audience":
        kwargs["audience"] = "different-receiver"
    elif case == "access-token-sub":
        kwargs["extra"] = {"sub": "user-care-1"}
    elif case == "forbidden-expiry":
        kwargs["extra"] = {"exp": int((now + timedelta(minutes=5)).timestamp())}
    elif case == "multiple-events":
        kwargs["events"] = {
            IdentitySignalType.SESSION_REVOKED.value: {},
            IdentitySignalType.TOKEN_CLAIMS_CHANGE.value: {"claims": {"roles": []}},
        }
    elif case == "unknown-event":
        kwargs["events"] = {"https://attacker.example.test/event": {}}
    elif case == "untrusted-subject-issuer":
        kwargs["subject_id"] = {
            "format": "iss_sub",
            "iss": "https://attacker.example.test",
            "sub": "user-care-1",
        }
    elif case == "over-age":
        now -= timedelta(minutes=6)
    elif case == "token-url-header":
        kwargs["headers"] = {"jku": "https://attacker.example.test/jwks.json"}
    elif case == "wrong-signature":
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif case == "unknown-key":
        kwargs["headers"] = {"kid": "unknown-key"}
    return _set_token(signing_key, now, event_id=f"set-invalid-{case}", **kwargs)


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Purpose-Of-Use": "HEALTHCARE_OPERATIONS",
    }


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

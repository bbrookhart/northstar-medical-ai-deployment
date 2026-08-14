from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from polaris.config import Settings
from polaris.domain import IdentitySignalType
from polaris.main import create_app
from polaris.security.auth import StaticJwksProvider
from polaris.security.identity_signals import SharedSignalsReceiver, StateBackedRevocationProvider
from polaris.security.signal_delivery import (
    JSON_MEDIA_TYPE,
    SET_MEDIA_TYPE,
    HashedBearerTransmitterAuthenticator,
    SharedSignalsPushService,
)
from polaris.services.audit import AuditLedger
from polaris.services.state import InMemoryStateStore

ISSUER = "https://identity.northstar.example.test"
AUDIENCE = "polaris-identity-signals"
STREAM_ID = "enterprise-identity-stream"
TRANSMITTER_ID = "northstar-idp-transmitter"
KEY_ID = "northstar-signal-delivery-key-1"


@dataclass(slots=True)
class DeliveryRig:
    client: TestClient
    state: InMemoryStateStore
    audit: AuditLedger
    private_key: rsa.RSAPrivateKey
    authorization: str


def test_authenticated_push_persists_and_acknowledges_new_and_replayed_set(
    settings: Settings,
) -> None:
    with _delivery_rig(settings) as rig:
        now = datetime.now(UTC).replace(microsecond=0)
        set_token = _set_token(rig.private_key, now, event_id="set-push-valid-1")

        first = _post(rig, set_token)
        with rig.state.transaction() as transaction:
            signal = transaction.get_identity_signal("set-push-valid-1")
            checkpoint = transaction.get_identity_stream_checkpoint(STREAM_ID)

        assert first.status_code == 202
        assert first.content == b""
        assert first.headers["cache-control"] == "no-store"
        assert signal is not None
        assert signal.stream_id == STREAM_ID
        assert signal.transmitter_id == TRANSMITTER_ID
        assert checkpoint is not None

        replay = _post(rig, set_token)
        with rig.state.transaction() as transaction:
            replay_checkpoint = transaction.get_identity_stream_checkpoint(STREAM_ID)
        assert replay.status_code == 202
        assert replay.content == b""
        assert replay_checkpoint == checkpoint
        assert "IDENTITY_SIGNAL_IDEMPOTENT_REPLAY" in {
            event.outcome for event in rig.audit.snapshot()
        }
        assert rig.audit.verify()


def test_push_transport_authenticates_before_accepting_stream_or_media_types(
    settings: Settings,
) -> None:
    with _delivery_rig(settings) as rig:
        set_token = _set_token(
            rig.private_key,
            datetime.now(UTC).replace(microsecond=0),
            event_id="set-never-applied",
        )
        base_headers = {"Content-Type": SET_MEDIA_TYPE, "Accept": JSON_MEDIA_TYPE}

        missing = rig.client.post(
            f"/v1/identity/streams/{STREAM_ID}/events",
            content=set_token,
            headers=base_headers,
        )
        wrong = rig.client.post(
            f"/v1/identity/streams/{STREAM_ID}/events",
            content=set_token,
            headers={**base_headers, "Authorization": f"Bearer {secrets.token_urlsafe(32)}"},
        )
        wrong_stream = rig.client.post(
            "/v1/identity/streams/different-stream/events",
            content=set_token,
            headers={**base_headers, "Authorization": rig.authorization},
        )
        wrong_type = rig.client.post(
            f"/v1/identity/streams/{STREAM_ID}/events",
            content=set_token,
            headers={
                "Authorization": rig.authorization,
                "Content-Type": "application/jwt",
                "Accept": JSON_MEDIA_TYPE,
            },
        )
        wrong_accept = rig.client.post(
            f"/v1/identity/streams/{STREAM_ID}/events",
            content=set_token,
            headers={
                "Authorization": rig.authorization,
                "Content-Type": SET_MEDIA_TYPE,
                "Accept": "*/*",
            },
        )

        for response, error_code in (
            (missing, "authentication_failed"),
            (wrong, "authentication_failed"),
            (wrong_stream, "access_denied"),
            (wrong_type, "invalid_request"),
            (wrong_accept, "invalid_request"),
        ):
            assert response.status_code == 400
            assert response.json()["err"] == error_code
            assert response.headers["content-language"] == "en-US"
        with rig.state.transaction() as transaction:
            assert transaction.get_identity_signal("set-never-applied") is None
        assert rig.audit.verify()


def test_push_rejects_invalid_empty_non_ascii_and_oversized_bodies(
    settings: Settings,
) -> None:
    with _delivery_rig(settings, max_body_bytes=1024) as rig:
        invalid_set = _set_token(
            rig.private_key,
            datetime.now(UTC).replace(microsecond=0),
            event_id="set-wrong-type",
            typ="at+jwt",
        )
        wrong_signature = _set_token(
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            datetime.now(UTC).replace(microsecond=0),
            event_id="set-wrong-signature",
        )
        wrong_issuer = _set_token(
            rig.private_key,
            datetime.now(UTC).replace(microsecond=0),
            event_id="set-wrong-issuer",
            issuer="https://attacker.example.test",
        )
        wrong_audience = _set_token(
            rig.private_key,
            datetime.now(UTC).replace(microsecond=0),
            event_id="set-wrong-audience",
            audience="different-receiver",
        )
        unknown_key = _set_token(
            rig.private_key,
            datetime.now(UTC).replace(microsecond=0),
            event_id="set-unknown-key",
            key_id="unknown-key",
        )
        invalid = _post(rig, invalid_set)
        invalid_key = _post(rig, wrong_signature)
        invalid_issuer = _post(rig, wrong_issuer)
        invalid_audience = _post(rig, wrong_audience)
        unknown_key_response = _post(rig, unknown_key)
        empty = _post(rig, b"")
        non_ascii = _post(rig, b"\xff")
        oversized = _post(rig, b"x" * 1025)

        for response, error_code, description in (
            (invalid, "invalid_request", "SET validation failed"),
            (invalid_key, "invalid_key", "SET validation failed"),
            (invalid_issuer, "invalid_issuer", "SET validation failed"),
            (invalid_audience, "invalid_audience", "SET validation failed"),
            (unknown_key_response, "invalid_key", "SET validation failed"),
            (empty, "invalid_request", "SET request body is invalid"),
            (non_ascii, "invalid_request", "SET request body is invalid"),
        ):
            assert response.status_code == 400
            assert response.json() == {
                "err": error_code,
                "description": description,
            }
        assert oversized.status_code == 413
        assert oversized.content == b""
        outcomes = {event.outcome for event in rig.audit.snapshot()}
        assert "IDENTITY_SIGNAL_REJECTED" in outcomes
        assert "IDENTITY_SIGNAL_TRANSPORT_INVALID_REQUEST" in outcomes
        assert "IDENTITY_SIGNAL_TRANSPORT_PAYLOAD_TOO_LARGE" in outcomes
        assert rig.audit.verify()


def test_push_does_not_acknowledge_event_id_payload_collision(
    settings: Settings,
) -> None:
    with _delivery_rig(settings) as rig:
        now = datetime.now(UTC).replace(microsecond=0)
        first = _set_token(rig.private_key, now, event_id="set-push-collision")
        collision = _set_token(
            rig.private_key,
            now,
            event_id="set-push-collision",
            event_time=now - timedelta(seconds=10),
        )

        assert _post(rig, first).status_code == 202
        response = _post(rig, collision)

        assert response.status_code == 503
        assert response.json()["code"] == "STATE_INTEGRITY_FAILURE"
        assert rig.audit.snapshot()[-1].outcome == "IDENTITY_SIGNAL_REPLAY_COLLISION"
        assert rig.audit.verify()


def test_push_endpoint_is_disabled_without_an_explicit_delivery_adapter(
    settings: Settings,
) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.post(
            f"/v1/identity/streams/{STREAM_ID}/events",
            content="not-a-set",
            headers={"Content-Type": SET_MEDIA_TYPE, "Accept": JSON_MEDIA_TYPE},
        )
    assert response.status_code == 404


def test_hashed_transmitter_authenticator_configuration_fails_closed() -> None:
    valid_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    with pytest.raises(ValueError, match="transmitter ID"):
        HashedBearerTransmitterAuthenticator(
            transmitter_id="invalid transmitter",
            expected_token_sha256=valid_hash,
        )
    with pytest.raises(ValueError, match="token hash"):
        HashedBearerTransmitterAuthenticator(
            transmitter_id=TRANSMITTER_ID,
            expected_token_sha256="not-a-hash",
        )


class _DeliveryRigContext:
    def __init__(self, settings: Settings, max_body_bytes: int) -> None:
        self._settings = settings
        self._max_body_bytes = max_body_bytes
        self._client: TestClient | None = None

    def __enter__(self) -> DeliveryRig:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        state = InMemoryStateStore()
        audit = AuditLedger(self._settings.audit_hmac_key, state=state)
        revocations = StateBackedRevocationProvider(
            state,
            stream_id=STREAM_ID,
            max_staleness=timedelta(minutes=5),
        )
        receiver = SharedSignalsReceiver(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_provider=_jwks(private_key),
            revocations=revocations,
            audit=audit,
        )
        bearer_token = secrets.token_urlsafe(32)
        transport_auth = HashedBearerTransmitterAuthenticator(
            transmitter_id=TRANSMITTER_ID,
            expected_token_sha256=hashlib.sha256(bearer_token.encode()).hexdigest(),
        )
        delivery = SharedSignalsPushService(
            receiver=receiver,
            authenticator=transport_auth,
            audit=audit,
            stream_id=STREAM_ID,
            max_body_bytes=self._max_body_bytes,
        )
        self._client = TestClient(
            create_app(
                self._settings,
                state_store=state,
                identity_signal_delivery=delivery,
            )
        )
        self._client.__enter__()
        return DeliveryRig(
            client=self._client,
            state=state,
            audit=audit,
            private_key=private_key,
            authorization=f"Bearer {bearer_token}",
        )

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._client is not None:
            self._client.__exit__(exc_type, exc, traceback)


def _delivery_rig(settings: Settings, *, max_body_bytes: int = 64 * 1024) -> _DeliveryRigContext:
    return _DeliveryRigContext(settings, max_body_bytes)


def _post(rig: DeliveryRig, body: str | bytes) -> Any:
    return rig.client.post(
        f"/v1/identity/streams/{STREAM_ID}/events",
        content=body,
        headers={
            "Authorization": rig.authorization,
            "Content-Type": SET_MEDIA_TYPE,
            "Accept": JSON_MEDIA_TYPE,
            "X-Request-ID": "req-signal-push",
        },
    )


def _set_token(
    key: rsa.RSAPrivateKey,
    now: datetime,
    *,
    event_id: str,
    event_time: datetime | None = None,
    typ: str = "secevent+jwt",
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    key_id: str = KEY_ID,
) -> str:
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "iat": int(now.timestamp()),
            "jti": event_id,
            "sub_id": {"format": "iss_sub", "iss": ISSUER, "sub": "user-care-1"},
            "events": {
                IdentitySignalType.SESSION_REVOKED.value: {
                    "event_timestamp": int((event_time or now).timestamp())
                }
            },
        },
        key,
        algorithm="RS256",
        headers={"typ": typ, "kid": key_id},
    )


def _jwks(key: rsa.RSAPrivateKey) -> StaticJwksProvider:
    numbers = key.public_key().public_numbers()
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


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

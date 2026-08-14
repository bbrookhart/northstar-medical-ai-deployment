from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from polaris.config import Settings
from polaris.errors import AuthenticationError
from polaris.main import create_app
from polaris.security.auth import (
    OidcAccessTokenAuthenticator,
    RevocationRegistry,
    StaticJwksProvider,
)

ISSUER = "https://identity.northstar.example.test"
AUDIENCE = "polaris-api"
KEY_ID = "northstar-test-key-1"


@pytest.fixture(scope="module")
def rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(rsa_private_key: rsa.RSAPrivateKey) -> dict[str, object]:
    numbers = rsa_private_key.public_key().public_numbers()
    return {
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


@pytest.fixture
def oidc_token_factory(
    rsa_private_key: rsa.RSAPrivateKey,
) -> Callable[..., str]:
    def mint(
        *,
        subject: str = "user-care-1",
        token_id: str | None = None,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        issued_delta: timedelta = timedelta(0),
        expires_delta: timedelta = timedelta(minutes=15),
        scope: str = "polaris.patient.read",
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "jti": token_id or f"tok-{uuid4().hex}",
            "client_id": "polaris-web",
            "iat": now + issued_delta,
            "exp": now + expires_delta,
            "scope": scope,
            "roles": ["care_coordinator"],
            "facilities": ["FAC-NORTH"],
            "assigned_patients": ["SYN-P1001"],
        }
        claims.update(extra or {})
        token_headers = {"typ": "at+jwt", "kid": KEY_ID}
        token_headers.update(headers or {})
        return jwt.encode(claims, rsa_private_key, algorithm="RS256", headers=token_headers)

    return mint


@pytest.fixture
def oidc_authenticator(jwks: dict[str, object]) -> OidcAccessTokenAuthenticator:
    return OidcAccessTokenAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=StaticJwksProvider(jwks),
    )


def test_valid_oidc_access_token_maps_typed_principal(
    oidc_authenticator: OidcAccessTokenAuthenticator,
    oidc_token_factory: Callable[..., str],
) -> None:
    principal = oidc_authenticator.authenticate(
        oidc_token_factory(scope="polaris.patient.read polaris.task.propose")
    )

    assert principal.subject == "user-care-1"
    assert principal.client_id == "polaris-web"
    assert principal.scopes == frozenset({"polaris.patient.read", "polaris.task.propose"})
    assert principal.facilities == frozenset({"FAC-NORTH"})
    assert principal.assigned_patients == frozenset({"SYN-P1001"})


@pytest.mark.parametrize(
    "token_kwargs",
    [
        {"issuer": "https://attacker.example.test"},
        {"audience": "different-api"},
        {"headers": {"typ": "JWT"}},
        {"headers": {"kid": "unknown-key"}},
        {"issued_delta": timedelta(minutes=-21), "expires_delta": timedelta(minutes=1)},
        {"extra": {"client_id": None}},
        {"extra": {"sub": None}},
        {"extra": {"jti": 12345}},
        {"extra": {"scope": ""}},
        {"headers": {"jku": "https://attacker.example.test/jwks.json"}},
        {"headers": {"crit": "attacker-extension"}},
    ],
)
def test_oidc_verifier_rejects_wrong_context_and_malformed_claims(
    oidc_authenticator: OidcAccessTokenAuthenticator,
    oidc_token_factory: Callable[..., str],
    token_kwargs: dict[str, Any],
) -> None:
    with pytest.raises(AuthenticationError, match="Bearer token is invalid"):
        oidc_authenticator.authenticate(oidc_token_factory(**token_kwargs))


def test_revoked_token_and_subject_are_rejected(
    jwks: dict[str, object],
    oidc_token_factory: Callable[..., str],
) -> None:
    revocations = RevocationRegistry()
    authenticator = OidcAccessTokenAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=StaticJwksProvider(jwks),
        revocations=revocations,
    )
    revoked_token = oidc_token_factory(token_id="tok-revoked")
    revoked_subject = oidc_token_factory(subject="user-revoked")

    revocations.revoke_token("tok-revoked")
    revocations.revoke_subject("user-revoked")

    with pytest.raises(AuthenticationError):
        authenticator.authenticate(revoked_token)
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(revoked_subject)


@pytest.mark.parametrize(
    "invalid_jwks",
    [
        {},
        {"keys": []},
        {"keys": [{"kid": KEY_ID, "kty": "oct", "alg": "HS256"}]},
        {"keys": [{"kid": KEY_ID, "kty": "RSA", "alg": "RS256", "use": "enc"}]},
    ],
)
def test_static_jwks_rejects_missing_or_unsafe_keys(invalid_jwks: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        StaticJwksProvider(invalid_jwks)


def test_static_jwks_rejects_private_rsa_material(jwks: dict[str, object]) -> None:
    keys = jwks["keys"]
    assert isinstance(keys, list)
    public_key = keys[0]
    assert isinstance(public_key, dict)
    unsafe_key = dict(public_key)
    unsafe_key["d"] = "synthetic-private-parameter"

    with pytest.raises(ValueError, match="private RSA key material"):
        StaticJwksProvider({"keys": [unsafe_key]})


def test_api_uses_injected_oidc_verifier_and_enforces_operation_scope(
    oidc_authenticator: OidcAccessTokenAuthenticator,
    oidc_token_factory: Callable[..., str],
    settings: Settings,
) -> None:
    with TestClient(create_app(settings, authenticator=oidc_authenticator)) as client:
        allowed = client.get(
            "/v1/patients/SYN-P1001/summary",
            headers=_headers(oidc_token_factory(scope="polaris.patient.read")),
        )
        denied = client.get(
            "/v1/patients/SYN-P1001/summary",
            headers=_headers(oidc_token_factory(scope="polaris.policy.read")),
        )

    assert allowed.status_code == 200
    assert allowed.json()["synthetic_data"] is True
    assert denied.status_code == 404
    assert denied.json()["code"] == "PATIENT_NOT_AVAILABLE"


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Purpose-Of-Use": "HEALTHCARE_OPERATIONS",
    }


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

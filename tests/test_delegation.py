from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from polaris.errors import (
    AuthenticationError,
    AuthorizationError,
    DependencyUnavailableError,
    UpstreamDataError,
)
from polaris.security.auth import OidcAccessTokenAuthenticator, StaticJwksProvider
from polaris.security.delegation import (
    ACCESS_TOKEN_TYPE,
    DEFAULT_DELEGATION_POLICIES,
    FHIR_PATIENT_READ_POLICY,
    TOKEN_EXCHANGE_GRANT,
    DelegatedJwtAccessTokenValidator,
    DelegationPolicy,
    DelegationTarget,
    OAuthTokenExchangeBroker,
)

API_ISSUER = "https://identity.northstar.example.test"
STS_ISSUER = "https://sts.northstar.example.test"
API_AUDIENCE = "polaris-api"


class RecordingExchangeTransport:
    def __init__(
        self,
        response: Mapping[str, object]
        | Exception
        | Callable[[Mapping[str, str]], Mapping[str, object]],
    ) -> None:
        self.response = response
        self.calls: list[dict[str, str]] = []

    def exchange(self, form: Mapping[str, str]) -> Mapping[str, object]:
        self.calls.append(dict(form))
        if isinstance(self.response, Exception):
            raise self.response
        if callable(self.response):
            return self.response(form)
        return self.response


@pytest.fixture(scope="module")
def api_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def sts_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_exchange_is_fixed_scope_audience_bound_and_secret_redacted(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
) -> None:
    now = datetime.now(UTC)
    subject_token = _subject_token(api_key, now=now)
    delegated_token = _delegated_token(sts_key, now=now)
    response = _exchange_response(delegated_token)
    transport = RecordingExchangeTransport(response)
    broker = _broker(api_key, sts_key, transport, now=now)

    result = broker.exchange(
        subject_token=subject_token,
        target=DelegationTarget.FHIR_PATIENT_READ,
    )

    assert transport.calls == [
        {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "resource": FHIR_PATIENT_READ_POLICY.resource,
            "audience": FHIR_PATIENT_READ_POLICY.audience,
            "scope": "user/Consent.rs user/Patient.rs",
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
        }
    ]
    assert result.subject == "user-care-1"
    assert result.audience == "northstar-fhir-api"
    assert result.scopes == frozenset({"user/Consent.rs", "user/Patient.rs"})
    assert result.access_token.get_secret_value() == delegated_token
    assert delegated_token not in repr(result)
    assert delegated_token not in result.model_dump_json()


def test_broker_reauthenticates_subject_token_before_contacting_sts(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
) -> None:
    now = datetime.now(UTC)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = RecordingExchangeTransport({})
    broker = _broker(api_key, sts_key, transport, now=now)

    with pytest.raises(AuthenticationError):
        broker.exchange(
            subject_token=_subject_token(attacker_key, now=now),
            target=DelegationTarget.FHIR_PATIENT_READ,
        )

    assert transport.calls == []


def test_broker_denies_missing_api_scope_and_unknown_target_before_exchange(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
) -> None:
    now = datetime.now(UTC)
    transport = RecordingExchangeTransport({})
    broker = _broker(api_key, sts_key, transport, now=now)

    with pytest.raises(AuthorizationError, match="Access denied"):
        broker.exchange(
            subject_token=_subject_token(api_key, now=now, scope="polaris.policy.read"),
            target=DelegationTarget.FHIR_PATIENT_READ,
        )
    with pytest.raises(AuthorizationError):
        broker.exchange(
            subject_token=_subject_token(api_key, now=now),
            target=cast(DelegationTarget, "unknown.target"),
        )

    assert transport.calls == []


@pytest.mark.parametrize(
    "response_override",
    [
        {"access_token": None},
        {"token_type": "MAC"},
        {"issued_token_type": "urn:example:id-token"},
        {"expires_in": 301},
        {"expires_in": True},
        {"scope": "user/Patient.rs user/Consent.rs user/Observation.rs"},
        {"refresh_token": "refresh-tokens-are-prohibited"},
    ],
)
def test_broker_rejects_unsafe_token_exchange_response_shapes(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
    response_override: Mapping[str, object],
) -> None:
    now = datetime.now(UTC)
    subject_token = _subject_token(api_key, now=now)
    delegated_token = _delegated_token(sts_key, now=now)
    response = _exchange_response(delegated_token)
    response.update(response_override)
    broker = _broker(api_key, sts_key, RecordingExchangeTransport(response), now=now)

    with pytest.raises(UpstreamDataError, match="Required service returned invalid data"):
        broker.exchange(
            subject_token=subject_token,
            target=DelegationTarget.FHIR_PATIENT_READ,
        )


def test_broker_rejects_incoming_token_passthrough(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
) -> None:
    now = datetime.now(UTC)
    subject_token = _subject_token(api_key, now=now)

    def passthrough(form: Mapping[str, str]) -> Mapping[str, object]:
        return _exchange_response(form["subject_token"])

    broker = _broker(api_key, sts_key, RecordingExchangeTransport(passthrough), now=now)

    with pytest.raises(UpstreamDataError):
        broker.exchange(
            subject_token=subject_token,
            target=DelegationTarget.FHIR_PATIENT_READ,
        )


def test_broker_maps_sts_outage_without_leaking_details(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
) -> None:
    now = datetime.now(UTC)
    broker = _broker(
        api_key,
        sts_key,
        RecordingExchangeTransport(RuntimeError("secret endpoint detail")),
        now=now,
    )

    with pytest.raises(DependencyUnavailableError, match="Required service is unavailable") as exc:
        broker.exchange(
            subject_token=_subject_token(api_key, now=now),
            target=DelegationTarget.FHIR_PATIENT_READ,
        )

    assert "secret endpoint detail" not in str(exc.value)


@pytest.mark.parametrize(
    ("claim_overrides", "header_overrides", "lifetime"),
    [
        ({"aud": "other-api"}, {}, timedelta(minutes=2)),
        ({"aud": ["northstar-fhir-api", "other-api"]}, {}, timedelta(minutes=2)),
        ({"sub": "other-user"}, {}, timedelta(minutes=2)),
        (
            {"scope": "user/Patient.rs user/Consent.rs user/Observation.rs"},
            {},
            timedelta(minutes=2),
        ),
        ({"client_id": None}, {}, timedelta(minutes=2)),
        ({"client_id": "other-workload"}, {}, timedelta(minutes=2)),
        ({}, {"typ": "JWT"}, timedelta(minutes=2)),
        ({}, {"jku": "https://attacker.example.test/jwks.json"}, timedelta(minutes=2)),
        ({}, {"kid": "unknown-key"}, timedelta(minutes=2)),
        ({}, {}, timedelta(minutes=6)),
        ({"exp": 1}, {}, timedelta(minutes=2)),
    ],
)
def test_delegated_validator_rejects_wrong_context_broadened_rights_and_long_life(
    sts_key: rsa.RSAPrivateKey,
    claim_overrides: Mapping[str, Any],
    header_overrides: Mapping[str, str],
    lifetime: timedelta,
) -> None:
    now = datetime.now(UTC)
    token = _delegated_token(
        sts_key,
        now=now,
        lifetime=lifetime,
        claim_overrides=claim_overrides,
        header_overrides=header_overrides,
    )
    validator = _delegated_validator(sts_key, now=now)

    with pytest.raises(AuthenticationError, match="Bearer token is invalid"):
        validator.validate(
            token,
            expected_subject="user-care-1",
            expected_audience="northstar-fhir-api",
            expected_scopes=frozenset({"user/Consent.rs", "user/Patient.rs"}),
            expected_client_id="polaris-workload",
            max_lifetime=timedelta(minutes=5),
        )


def test_broker_rejects_invalid_delegated_signature_and_expiry_mismatch(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
) -> None:
    now = datetime.now(UTC)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad_signature = _delegated_token(attacker_key, now=now)
    bad_signature_broker = _broker(
        api_key,
        sts_key,
        RecordingExchangeTransport(_exchange_response(bad_signature)),
        now=now,
    )
    short_token = _delegated_token(sts_key, now=now, lifetime=timedelta(seconds=60))
    mismatched_expiry_broker = _broker(
        api_key,
        sts_key,
        RecordingExchangeTransport(_exchange_response(short_token, expires_in=120)),
        now=now,
    )

    with pytest.raises(UpstreamDataError):
        bad_signature_broker.exchange(
            subject_token=_subject_token(api_key, now=now),
            target=DelegationTarget.FHIR_PATIENT_READ,
        )
    with pytest.raises(UpstreamDataError):
        mismatched_expiry_broker.exchange(
            subject_token=_subject_token(api_key, now=now),
            target=DelegationTarget.FHIR_PATIENT_READ,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"resource": "http://fhir.example.test"},
        {"audience": "two audiences"},
        {"scopes": frozenset()},
        {"expected_client_id": "two clients"},
        {"max_token_lifetime": timedelta(minutes=6)},
    ],
)
def test_delegation_policy_rejects_unsafe_configuration(kwargs: Mapping[str, object]) -> None:
    values: dict[str, object] = {
        "resource": "https://fhir.example.test/fhir",
        "audience": "fhir-api",
        "scopes": frozenset({"user/Patient.rs"}),
        "required_principal_scope": "polaris.patient.read",
        "expected_client_id": "polaris-workload",
    }
    values.update(kwargs)

    with pytest.raises(ValueError):
        DelegationPolicy(**values)  # type: ignore[arg-type]


def _broker(
    api_key: rsa.RSAPrivateKey,
    sts_key: rsa.RSAPrivateKey,
    transport: RecordingExchangeTransport,
    *,
    now: datetime,
) -> OAuthTokenExchangeBroker:
    subject_authenticator = OidcAccessTokenAuthenticator(
        issuer=API_ISSUER,
        audience=API_AUDIENCE,
        jwks_provider=StaticJwksProvider(_jwks(api_key, "api-key")),
        clock=lambda: now,
    )
    return OAuthTokenExchangeBroker(
        subject_token_authenticator=subject_authenticator,
        transport=transport,
        delegated_token_validator=_delegated_validator(sts_key, now=now),
        policies=DEFAULT_DELEGATION_POLICIES,
        clock=lambda: now,
    )


def _delegated_validator(
    sts_key: rsa.RSAPrivateKey,
    *,
    now: datetime,
) -> DelegatedJwtAccessTokenValidator:
    return DelegatedJwtAccessTokenValidator(
        issuer=STS_ISSUER,
        jwks_provider=StaticJwksProvider(_jwks(sts_key, "sts-key")),
        clock=lambda: now,
    )


def _subject_token(
    key: rsa.RSAPrivateKey,
    *,
    now: datetime,
    scope: str = "polaris.patient.read",
) -> str:
    return jwt.encode(
        {
            "iss": API_ISSUER,
            "aud": API_AUDIENCE,
            "sub": "user-care-1",
            "jti": "subject-token-1",
            "client_id": "polaris-web",
            "iat": now,
            "exp": now + timedelta(minutes=10),
            "scope": scope,
            "roles": ["care_coordinator"],
            "facilities": ["FAC-NORTH"],
            "assigned_patients": ["SYN-P1001"],
        },
        key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": "api-key"},
    )


def _delegated_token(
    key: rsa.RSAPrivateKey,
    *,
    now: datetime,
    lifetime: timedelta = timedelta(minutes=2),
    claim_overrides: Mapping[str, Any] | None = None,
    header_overrides: Mapping[str, str] | None = None,
) -> str:
    claims: dict[str, Any] = {
        "iss": STS_ISSUER,
        "aud": "northstar-fhir-api",
        "sub": "user-care-1",
        "jti": "delegated-token-1",
        "client_id": "polaris-workload",
        "iat": now,
        "exp": now + lifetime,
        "scope": "user/Consent.rs user/Patient.rs",
    }
    claims.update(claim_overrides or {})
    headers = {"typ": "at+jwt", "kid": "sts-key"}
    headers.update(header_overrides or {})
    return jwt.encode(claims, key, algorithm="RS256", headers=headers)


def _exchange_response(token: str, *, expires_in: int = 120) -> dict[str, object]:
    return {
        "access_token": token,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "user/Consent.rs user/Patient.rs",
    }


def _jwks(key: rsa.RSAPrivateKey, kid: str) -> dict[str, object]:
    numbers = key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": _base64url_uint(numbers.n),
                "e": _base64url_uint(numbers.e),
            }
        ]
    }


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import jwt
from jwt import InvalidTokenError
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from polaris.domain import Identifier
from polaris.errors import (
    AuthenticationError,
    AuthorizationError,
    DependencyUnavailableError,
    UpstreamDataError,
)
from polaris.security.auth import JwksProvider, TokenAuthenticator

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
_MAX_TOKEN_BYTES = 32_768


class DelegationTarget(StrEnum):
    FHIR_PATIENT_READ = "fhir.patient.read"


@dataclass(frozen=True, slots=True)
class DelegationPolicy:
    """Server-owned allowlist entry for one downstream operation."""

    resource: str
    audience: str
    scopes: frozenset[str]
    required_principal_scope: str
    expected_client_id: str
    max_token_lifetime: timedelta = timedelta(minutes=5)

    def __post_init__(self) -> None:
        parsed = urlsplit(self.resource)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Delegation resources must be canonical HTTPS URLs")
        if (
            not self.audience
            or len(self.audience) > 256
            or any(char.isspace() for char in self.audience)
        ):
            raise ValueError("Delegation audience is invalid")
        if not self.scopes or any(
            not scope or len(scope) > 128 or any(char.isspace() for char in scope)
            for scope in self.scopes
        ):
            raise ValueError("Delegation scopes are invalid")
        if not self.required_principal_scope or any(
            char.isspace() for char in self.required_principal_scope
        ):
            raise ValueError("Required principal scope is invalid")
        if not self.expected_client_id or any(char.isspace() for char in self.expected_client_id):
            raise ValueError("Expected delegated client ID is invalid")
        if not timedelta(seconds=1) <= self.max_token_lifetime <= timedelta(minutes=5):
            raise ValueError("Delegated token lifetime must be between 1 second and 5 minutes")


FHIR_PATIENT_READ_POLICY = DelegationPolicy(
    resource="https://fhir.northstar.example.test/fhir",
    audience="northstar-fhir-api",
    scopes=frozenset({"user/Consent.rs", "user/Patient.rs"}),
    required_principal_scope="polaris.patient.read",
    expected_client_id="polaris-workload",
)

DEFAULT_DELEGATION_POLICIES: Mapping[DelegationTarget, DelegationPolicy] = MappingProxyType(
    {DelegationTarget.FHIR_PATIENT_READ: FHIR_PATIENT_READ_POLICY}
)


class DelegatedAccessToken(BaseModel):
    """Validated downstream credential; Pydantic redacts the token from repr and serialization."""

    model_config = ConfigDict(frozen=True)

    access_token: SecretStr = Field(min_length=1, max_length=_MAX_TOKEN_BYTES)
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_at: datetime
    audience: str = Field(min_length=1, max_length=256)
    resource: str = Field(min_length=1, max_length=2048)
    scopes: frozenset[str]
    subject: Identifier


class TokenExchangeTransport(Protocol):
    """Confidential-client token endpoint boundary.

    Implementations are responsible for TLS, no redirects, response bounds, and workload client
    authentication (for example, private_key_jwt or mTLS). They must never log the request form.
    """

    def exchange(self, form: Mapping[str, str]) -> Mapping[str, object]: ...


class DelegatedTokenValidator(Protocol):
    def validate(
        self,
        token: str,
        *,
        expected_subject: str,
        expected_audience: str,
        expected_scopes: frozenset[str],
        expected_client_id: str,
        max_lifetime: timedelta,
    ) -> datetime: ...


class DelegatedJwtAccessTokenValidator:
    """Cryptographically validates an RFC 9068-style token returned by the exchange service."""

    def __init__(
        self,
        *,
        issuer: str,
        jwks_provider: JwksProvider,
        maximum_token_lifetime: timedelta = timedelta(minutes=5),
        leeway_seconds: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Delegated token issuer must be a canonical HTTPS URL")
        if not timedelta(seconds=1) <= maximum_token_lifetime <= timedelta(minutes=5):
            raise ValueError(
                "Maximum delegated token lifetime must be between 1 second and 5 minutes"
            )
        if not 0 <= leeway_seconds <= 60:
            raise ValueError("Delegated token leeway must be between 0 and 60 seconds")
        self._issuer = issuer
        self._jwks = jwks_provider
        self._maximum_token_lifetime = maximum_token_lifetime
        self._leeway_seconds = leeway_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    def validate(
        self,
        token: str,
        *,
        expected_subject: str,
        expected_audience: str,
        expected_scopes: frozenset[str],
        expected_client_id: str,
        max_lifetime: timedelta,
    ) -> datetime:
        try:
            if max_lifetime <= timedelta(0) or max_lifetime > self._maximum_token_lifetime:
                raise _invalid_delegated_token()
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("typ", "").casefold() not in {
                "at+jwt",
                "application/at+jwt",
            }:
                raise _invalid_delegated_token()
            if any(name in header for name in ("jku", "x5u", "x5c")) or header.get("crit"):
                raise _invalid_delegated_token()
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise _invalid_delegated_token()
            claims = jwt.decode(
                token,
                self._jwks.signing_key(kid),
                algorithms=["RS256"],
                audience=expected_audience,
                issuer=self._issuer,
                leeway=self._leeway_seconds,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "iss",
                        "aud",
                        "sub",
                        "jti",
                        "client_id",
                        "scope",
                    ]
                },
            )
            if claims.get("aud") != expected_audience or claims.get("sub") != expected_subject:
                raise _invalid_delegated_token()
            if (
                not _nonempty_string(claims.get("jti"))
                or claims.get("client_id") != expected_client_id
            ):
                raise _invalid_delegated_token()
            scope = claims.get("scope")
            if not isinstance(scope, str) or frozenset(scope.split()) != expected_scopes:
                raise _invalid_delegated_token()
            issued_at = _numeric_date(claims.get("iat"))
            expires_at = _numeric_date(claims.get("exp"))
            if expires_at <= issued_at or expires_at - issued_at > max_lifetime:
                raise _invalid_delegated_token()
            now = _aware_utc(self._clock())
            if expires_at <= now - timedelta(seconds=self._leeway_seconds):
                raise _invalid_delegated_token()
            return expires_at
        except AuthenticationError as exc:
            raise _invalid_delegated_token() from exc
        except (InvalidTokenError, KeyError, TypeError, ValueError, OverflowError) as exc:
            raise _invalid_delegated_token() from exc


class OAuthTokenExchangeBroker:
    """Reauthenticates the subject token and exchanges it under a fixed least-privilege policy."""

    def __init__(
        self,
        *,
        subject_token_authenticator: TokenAuthenticator,
        transport: TokenExchangeTransport,
        delegated_token_validator: DelegatedTokenValidator,
        policies: Mapping[DelegationTarget, DelegationPolicy] = DEFAULT_DELEGATION_POLICIES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not policies:
            raise ValueError("At least one downstream delegation policy is required")
        self._subject_tokens = subject_token_authenticator
        self._transport = transport
        self._delegated_tokens = delegated_token_validator
        self._policies = MappingProxyType(dict(policies))
        self._clock = clock or (lambda: datetime.now(UTC))

    def exchange(
        self,
        *,
        subject_token: str,
        target: DelegationTarget,
    ) -> DelegatedAccessToken:
        if not subject_token or len(subject_token.encode()) > _MAX_TOKEN_BYTES:
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
        principal = self._subject_tokens.authenticate(subject_token)
        policy = self._policies.get(target)
        if policy is None or policy.required_principal_scope not in principal.scopes:
            raise AuthorizationError("DOWNSTREAM_DELEGATION_DENIED")
        scopes = frozenset(policy.scopes)
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "resource": policy.resource,
            "audience": policy.audience,
            "scope": " ".join(sorted(scopes)),
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
        }
        try:
            response = self._transport.exchange(form)
        except Exception as exc:
            raise DependencyUnavailableError("TOKEN_EXCHANGE_UNAVAILABLE") from exc
        delegated_token, expires_in = _validated_exchange_response(
            response,
            subject_token=subject_token,
            expected_scopes=scopes,
            max_lifetime=policy.max_token_lifetime,
        )
        try:
            expires_at = self._delegated_tokens.validate(
                delegated_token,
                expected_subject=principal.subject,
                expected_audience=policy.audience,
                expected_scopes=scopes,
                expected_client_id=policy.expected_client_id,
                max_lifetime=policy.max_token_lifetime,
            )
            now = _aware_utc(self._clock())
        except AuthenticationError as exc:
            raise UpstreamDataError("TOKEN_EXCHANGE_RESPONSE_INVALID") from exc
        reported_expiry = now + timedelta(seconds=expires_in)
        if abs((expires_at - reported_expiry).total_seconds()) > 30:
            raise UpstreamDataError("TOKEN_EXCHANGE_RESPONSE_INVALID")
        return DelegatedAccessToken(
            access_token=SecretStr(delegated_token),
            expires_at=expires_at,
            audience=policy.audience,
            resource=policy.resource,
            scopes=scopes,
            subject=principal.subject,
        )


def _validated_exchange_response(
    response: Mapping[str, object],
    *,
    subject_token: str,
    expected_scopes: frozenset[str],
    max_lifetime: timedelta,
) -> tuple[str, int]:
    token = response.get("access_token")
    token_type = response.get("token_type")
    issued_type = response.get("issued_token_type")
    expires_in = response.get("expires_in")
    returned_scope = response.get("scope")
    if (
        not isinstance(token, str)
        or not token
        or len(token.encode()) > _MAX_TOKEN_BYTES
        or token == subject_token
        or not isinstance(token_type, str)
        or token_type.casefold() != "bearer"
        or issued_type != ACCESS_TOKEN_TYPE
        or not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or not 1 <= expires_in <= int(max_lifetime.total_seconds())
        or "refresh_token" in response
    ):
        raise UpstreamDataError("TOKEN_EXCHANGE_RESPONSE_INVALID")
    if returned_scope is not None and (
        not isinstance(returned_scope, str) or frozenset(returned_scope.split()) != expected_scopes
    ):
        raise UpstreamDataError("TOKEN_EXCHANGE_RESPONSE_INVALID")
    return token, expires_in


def _numeric_date(value: Any) -> datetime:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError("JWT NumericDate claim is invalid")
    return datetime.fromtimestamp(value, UTC)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Clock must return an aware datetime")
    return value.astimezone(UTC)


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _invalid_delegated_token() -> AuthenticationError:
    return AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")

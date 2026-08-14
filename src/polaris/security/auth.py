from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any, Protocol

import jwt
from jwt import InvalidTokenError, PyJWK

from polaris.config import Settings
from polaris.domain import Principal
from polaris.errors import AuthenticationError


class TokenAuthenticator(Protocol):
    def authenticate(self, token: str) -> Principal: ...

    def ready(self) -> bool: ...


class JwksProvider(Protocol):
    """Trusted signing-key source; implementations must never trust token-supplied URLs."""

    def signing_key(self, kid: str) -> PyJWK: ...


class RevocationProvider(Protocol):
    def assert_not_revoked(
        self,
        *,
        token_id: str,
        subject: str,
        issued_at: datetime,
    ) -> None: ...

    def ready(self) -> bool: ...


class RevocationRegistry:
    """Local deterministic revocation oracle; production uses enterprise signals plus short TTLs."""

    def __init__(self) -> None:
        self._token_ids: set[str] = set()
        self._subjects: set[str] = set()
        self._lock = RLock()

    def revoke_token(self, token_id: str) -> None:
        with self._lock:
            self._token_ids.add(token_id)

    def revoke_subject(self, subject: str) -> None:
        with self._lock:
            self._subjects.add(subject)

    def is_revoked(self, *, token_id: str, subject: str) -> bool:
        with self._lock:
            return token_id in self._token_ids or subject in self._subjects

    def assert_not_revoked(
        self,
        *,
        token_id: str,
        subject: str,
        issued_at: datetime,
    ) -> None:
        del issued_at
        if self.is_revoked(token_id=token_id, subject=subject):
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")

    def ready(self) -> bool:
        return True


class StaticJwksProvider:
    """Validates and serves a configured JWKS without token-controlled network access."""

    def __init__(self, jwks: Mapping[str, object]) -> None:
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not keys:
            raise ValueError("JWKS must contain a non-empty keys array")
        parsed: dict[str, PyJWK] = {}
        for value in keys:
            if not isinstance(value, dict):
                raise ValueError("Each JWKS key must be an object")
            kid = value.get("kid")
            if not isinstance(kid, str) or not kid or kid in parsed:
                raise ValueError("Each JWKS key must have a unique non-empty kid")
            if value.get("kty") != "RSA" or value.get("alg") != "RS256":
                raise ValueError("JWKS keys must be RSA keys restricted to RS256")
            if value.get("use", "sig") != "sig":
                raise ValueError("JWKS keys must be signing keys")
            if any(name in value for name in ("d", "p", "q", "dp", "dq", "qi", "oth")):
                raise ValueError("JWKS must not contain private RSA key material")
            parsed[kid] = PyJWK.from_dict(value, algorithm="RS256")
        self._keys = parsed

    def signing_key(self, kid: str) -> PyJWK:
        key = self._keys.get(kid)
        if key is None:
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
        return key


class OidcAccessTokenAuthenticator:
    """Strict RFC 9068-style asymmetric access-token verifier for a configured issuer/JWKS."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_provider: JwksProvider,
        revocations: RevocationProvider | None = None,
        max_token_age: timedelta = timedelta(minutes=20),
        leeway_seconds: int = 30,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not issuer.startswith("https://"):
            raise ValueError("OIDC issuer must use https")
        if not audience:
            raise ValueError("OIDC audience is required")
        if max_token_age <= timedelta(0):
            raise ValueError("Maximum token age must be positive")
        if not 0 <= leeway_seconds <= 120:
            raise ValueError("OIDC leeway must be between 0 and 120 seconds")
        self._issuer = issuer
        self._audience = audience
        self._jwks = jwks_provider
        self._revocations = revocations or RevocationRegistry()
        self._max_token_age = max_token_age
        self._leeway_seconds = leeway_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    def authenticate(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or header.get("typ", "").casefold() != "at+jwt":
                raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
            if any(name in header for name in ("jku", "x5u", "x5c")) or header.get("crit"):
                raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
            claims = jwt.decode(
                token,
                self._jwks.signing_key(kid),
                algorithms=["RS256"],
                audience=self._audience,
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
                        "roles",
                        "facilities",
                        "assigned_patients",
                    ]
                },
            )
            principal = _principal_from_claims(claims)
            issued_at = datetime.fromtimestamp(int(claims["iat"]), UTC)
            if self._clock() - issued_at > self._max_token_age:
                raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
            self._revocations.assert_not_revoked(
                token_id=principal.token_id,
                subject=principal.subject,
                issued_at=issued_at,
            )
            return principal
        except AuthenticationError as exc:
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid") from exc
        except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid") from exc

    def ready(self) -> bool:
        return self._revocations.ready()


class JwtAuthenticator:
    """Legacy HS256 local fixture; never an automatic production fallback."""

    def __init__(self, settings: Settings) -> None:
        if settings.environment == "production":
            raise ValueError("Legacy HS256 authentication is prohibited in production")
        self._settings = settings

    def authenticate(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "HS256" or header.get("typ", "").casefold() != "at+jwt":
                raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
            claims = jwt.decode(
                token,
                self._settings.jwt_signing_key,
                algorithms=["HS256"],
                audience=self._settings.jwt_audience,
                issuer=self._settings.jwt_issuer,
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
        except AuthenticationError:
            raise
        except InvalidTokenError as exc:
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid") from exc

        return _principal_from_claims(claims)

    def ready(self) -> bool:
        return True


def _principal_from_claims(claims: Mapping[str, Any]) -> Principal:
    try:
        roles = _string_set_claim(claims, "roles")
        facilities = _string_set_claim(claims, "facilities")
        patients = _string_set_claim(claims, "assigned_patients")
        scopes = _scope_claim(claims)
        return Principal(
            subject=_identifier_claim(claims, "sub"),
            token_id=_identifier_claim(claims, "jti"),
            client_id=_identifier_claim(claims, "client_id"),
            scopes=scopes,
            roles=roles,
            facilities=facilities,
            assigned_patients=patients,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthenticationError("AUTH_INVALID_CLAIMS", "Bearer token claims are invalid") from exc


def _identifier_claim(claims: Mapping[str, Any], name: str) -> str:
    value = claims[name]
    if not isinstance(value, str) or not value:
        raise TypeError(f"{name} must be a non-empty string")
    return value


def _string_set_claim(claims: Mapping[str, Any], name: str) -> frozenset[str]:
    value = claims[name]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{name} must be a list of strings")
    return frozenset(value)


def _scope_claim(claims: Mapping[str, Any]) -> frozenset[str]:
    value = claims["scope"]
    if not isinstance(value, str):
        raise TypeError("scope must be a space-delimited string")
    scopes = frozenset(value.split())
    if not scopes:
        raise ValueError("scope must not be empty")
    return scopes

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from jwt import PyJWK

from polaris.errors import AuthenticationError
from polaris.security.auth import StaticJwksProvider

_MAX_DOCUMENT_BYTES = 262_144
_JSON_MEDIA_TYPES = frozenset({"application/json", "application/jwk-set+json"})


class OidcJsonTransportError(RuntimeError):
    """Detail-free failure at the trusted identity metadata boundary."""


class OidcJsonTransport(Protocol):
    def get_json(self, url: str) -> Mapping[str, object]: ...


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class UrllibOidcJsonTransport:
    """Bounded HTTPS JSON fetcher restricted to administrator-configured origins."""

    def __init__(
        self,
        *,
        allowed_origins: Iterable[str],
        timeout_seconds: float = 3.0,
        max_document_bytes: int = _MAX_DOCUMENT_BYTES,
    ) -> None:
        origins = frozenset(_validated_origin(value) for value in allowed_origins)
        if not origins:
            raise ValueError("At least one trusted OIDC origin is required")
        if timeout_seconds <= 0 or timeout_seconds > 10:
            raise ValueError("OIDC timeout must be greater than zero and no more than 10 seconds")
        if max_document_bytes < 1 or max_document_bytes > _MAX_DOCUMENT_BYTES:
            raise ValueError("OIDC document limit must be between 1 byte and 256 KiB")
        self._allowed_origins = origins
        self._timeout_seconds = timeout_seconds
        self._max_document_bytes = max_document_bytes
        self._opener = build_opener(_RejectRedirects())

    def get_json(self, url: str) -> Mapping[str, object]:
        if _url_origin(url) not in self._allowed_origins:
            raise OidcJsonTransportError("OIDC endpoint is outside the trusted origin set")
        request = Request(  # noqa: S310 - exact HTTPS origins are allowlisted above.
            url,
            headers={
                "Accept": "application/json, application/jwk-set+json",
                "User-Agent": "northstar-polaris/0.1",
            },
            method="GET",
        )
        try:
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                final_url = cast(str, response.geturl())
                if final_url != url:
                    raise OidcJsonTransportError("OIDC redirects are prohibited")
                content_type = response.headers.get_content_type().casefold()
                if content_type not in _JSON_MEDIA_TYPES:
                    raise OidcJsonTransportError("OIDC response media type is invalid")
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > self._max_document_bytes:
                    raise OidcJsonTransportError("OIDC response exceeded the configured limit")
                raw = cast(bytes, response.read(self._max_document_bytes + 1))
        except OidcJsonTransportError:
            raise
        except (HTTPError, URLError, OSError, TimeoutError, ValueError) as exc:
            raise OidcJsonTransportError("OIDC document retrieval failed") from exc
        if len(raw) > self._max_document_bytes:
            raise OidcJsonTransportError("OIDC response exceeded the configured limit")
        try:
            payload: object = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OidcJsonTransportError("OIDC response was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise OidcJsonTransportError("OIDC response was not a JSON object")
        return cast(Mapping[str, object], payload)


@dataclass(frozen=True, slots=True)
class _JwksCache:
    provider: StaticJwksProvider
    fetched_at: datetime


class OidcDiscoveryJwksProvider:
    """Trusted OIDC discovery/JWKS provider with rotation and bounded stale-key use.

    Discovery is derived only from the configured issuer. JWKS origins are independently
    allowlisted. A previously validated known key may be used during a short outage, but unknown
    keys and keys older than ``max_stale`` always fail closed.
    """

    def __init__(
        self,
        *,
        issuer: str,
        transport: OidcJsonTransport,
        allowed_jwks_origins: Iterable[str] | None = None,
        cache_ttl: timedelta = timedelta(minutes=5),
        max_stale: timedelta = timedelta(minutes=15),
        refresh_cooldown: timedelta = timedelta(seconds=10),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        _validated_https_endpoint(issuer)
        issuer_origin = _url_origin(issuer)
        trusted_origins = frozenset(
            _validated_origin(value) for value in (allowed_jwks_origins or (issuer_origin,))
        )
        if not trusted_origins:
            raise ValueError("At least one trusted JWKS origin is required")
        if cache_ttl < timedelta(seconds=1) or cache_ttl > timedelta(hours=1):
            raise ValueError("JWKS cache TTL must be between 1 second and 1 hour")
        if max_stale < cache_ttl or max_stale > timedelta(hours=24):
            raise ValueError("JWKS maximum stale age must be at least the TTL and at most 24 hours")
        if refresh_cooldown < timedelta(0) or refresh_cooldown > cache_ttl:
            raise ValueError("JWKS refresh cooldown must be between zero and the cache TTL")
        self._issuer = issuer
        self._discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        self._transport = transport
        self._allowed_jwks_origins = trusted_origins
        self._cache_ttl = cache_ttl
        self._max_stale = max_stale
        self._refresh_cooldown = refresh_cooldown
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cache: _JwksCache | None = None
        self._last_refresh_attempt: datetime | None = None
        self._last_unknown_key_refresh: datetime | None = None
        self._lock = RLock()

    def signing_key(self, kid: str) -> PyJWK:
        if not kid:
            raise _invalid_token()
        now = self._now()
        with self._lock:
            cache = self._cache
            if cache is None:
                cache = self._attempt_refresh(now)
                if cache is None:
                    raise _invalid_token()
                key = _cached_key(cache, kid)
                if key is None:
                    raise _invalid_token()
                return key

            age = _cache_age(cache, now)
            key = _cached_key(cache, kid)
            if age <= self._cache_ttl and key is not None:
                return key

            if age <= self._cache_ttl:
                if self._cooldown_elapsed(self._last_unknown_key_refresh, now):
                    self._last_unknown_key_refresh = now
                    refreshed = self._attempt_refresh(now)
                    if refreshed is not None:
                        refreshed_key = _cached_key(refreshed, kid)
                        if refreshed_key is not None:
                            return refreshed_key
                raise _invalid_token()

            if self._cooldown_elapsed(self._last_refresh_attempt, now):
                refreshed = self._attempt_refresh(now)
                if refreshed is not None:
                    refreshed_key = _cached_key(refreshed, kid)
                    if refreshed_key is not None:
                        return refreshed_key
                    raise _invalid_token()

            if key is not None and age <= self._max_stale:
                return key
            raise _invalid_token()

    def _attempt_refresh(self, now: datetime) -> _JwksCache | None:
        self._last_refresh_attempt = now
        try:
            metadata = self._transport.get_json(self._discovery_url)
            if metadata.get("issuer") != self._issuer:
                raise ValueError("OIDC metadata issuer did not exactly match configured issuer")
            jwks_uri = metadata.get("jwks_uri")
            if not isinstance(jwks_uri, str):
                raise ValueError("OIDC metadata did not contain a JWKS URI")
            _validated_https_endpoint(jwks_uri)
            if _url_origin(jwks_uri) not in self._allowed_jwks_origins:
                raise ValueError("OIDC JWKS URI origin is not trusted")
            provider = StaticJwksProvider(self._transport.get_json(jwks_uri))
        except Exception:
            return None
        cache = _JwksCache(provider=provider, fetched_at=now)
        self._cache = cache
        return cache

    def _cooldown_elapsed(self, last_attempt: datetime | None, now: datetime) -> bool:
        if last_attempt is None:
            return True
        elapsed = now - last_attempt
        return elapsed < timedelta(0) or elapsed >= self._refresh_cooldown

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise _invalid_token()
        return now.astimezone(UTC)


def _cached_key(cache: _JwksCache, kid: str) -> PyJWK | None:
    try:
        return cache.provider.signing_key(kid)
    except AuthenticationError:
        return None


def _cache_age(cache: _JwksCache, now: datetime) -> timedelta:
    age = now - cache.fetched_at
    return timedelta.max if age < timedelta(0) else age


def _validated_origin(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Trusted OIDC origins must not include a path, query, or fragment")
    return _url_origin(origin)


def _validated_https_endpoint(url: str) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("OIDC endpoint port is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("OIDC endpoints must be canonical HTTPS URLs")
    return url


def _url_origin(url: str) -> str:
    _validated_https_endpoint(url)
    parsed = urlsplit(url)
    hostname = cast(str, parsed.hostname).lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    port = parsed.port
    if port is not None and port != 443:
        host = f"{host}:{port}"
    return f"https://{host}"


def _invalid_token() -> AuthenticationError:
    return AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from types import TracebackType

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import polaris.security.oidc_remote as oidc_remote
from polaris.errors import AuthenticationError
from polaris.security.auth import OidcAccessTokenAuthenticator
from polaris.security.oidc_remote import (
    OidcDiscoveryJwksProvider,
    OidcJsonTransportError,
    UrllibOidcJsonTransport,
)

ISSUER = "https://identity.northstar.example.test/tenant"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = "https://keys.northstar.example.test/access-token-jwks.json"
AUDIENCE = "polaris-api"


class MutableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class ScriptedJsonTransport:
    def __init__(self, *responses: Mapping[str, object] | Exception) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []

    def get_json(self, url: str) -> Mapping[str, object]:
        self.calls.append(url)
        if not self.responses:
            raise AssertionError("Unexpected identity document request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeHeaders:
    def __init__(self, content_type: str, content_length: str | None = None) -> None:
        self._content_type = content_type
        self._content_length = content_length

    def get_content_type(self) -> str:
        return self._content_type

    def get(self, name: str) -> str | None:
        if name == "Content-Length":
            return self._content_length
        return None


class FakeResponse:
    def __init__(
        self,
        raw: bytes,
        *,
        url: str = JWKS_URL,
        content_type: str = "application/json",
        content_length: str | None = None,
    ) -> None:
        self.raw = raw
        self.url = url
        self.headers = FakeHeaders(content_type, content_length)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, amount: int) -> bytes:
        return self.raw[:amount]


class FakeOpener:
    def __init__(self, result: FakeResponse | Exception) -> None:
        self.result = result

    def open(self, request: object, *, timeout: float) -> FakeResponse:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_discovery_provider_authenticates_with_trusted_cross_origin_jwks() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = _jwks(key, "key-1")
    transport = ScriptedJsonTransport(_metadata(), jwks)
    provider = OidcDiscoveryJwksProvider(
        issuer=ISSUER,
        transport=transport,
        allowed_jwks_origins={"https://keys.northstar.example.test"},
    )
    authenticator = OidcAccessTokenAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_provider=provider,
    )

    principal = authenticator.authenticate(_polaris_token(key, "key-1"))

    assert principal.subject == "user-care-1"
    assert transport.calls == [DISCOVERY_URL, JWKS_URL]


@pytest.mark.parametrize(
    "metadata",
    [
        {"issuer": "https://attacker.example.test", "jwks_uri": JWKS_URL},
        {"issuer": ISSUER, "jwks_uri": "http://keys.northstar.example.test/jwks.json"},
        {"issuer": ISSUER, "jwks_uri": "https://attacker.example.test/jwks.json"},
        {"issuer": ISSUER, "jwks_uri": f"{JWKS_URL}?target=internal"},
    ],
)
def test_discovery_rejects_trust_substitution_and_untrusted_jwks_urls(
    metadata: Mapping[str, object],
) -> None:
    transport = ScriptedJsonTransport(metadata)
    provider = OidcDiscoveryJwksProvider(
        issuer=ISSUER,
        transport=transport,
        allowed_jwks_origins={"https://keys.northstar.example.test"},
    )

    with pytest.raises(AuthenticationError, match="Bearer token is invalid"):
        provider.signing_key("key-1")

    assert transport.calls == [DISCOVERY_URL]


def test_unknown_kid_forces_one_rotation_refresh_then_observes_cooldown() -> None:
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = ScriptedJsonTransport(
        _metadata(),
        _jwks(old_key, "old-key"),
        _metadata(),
        _jwks(new_key, "new-key"),
    )
    provider = _provider(transport)

    assert provider.signing_key("old-key").key_id == "old-key"
    assert provider.signing_key("new-key").key_id == "new-key"
    with pytest.raises(AuthenticationError):
        provider.signing_key("attacker-random-key")

    assert transport.calls == [DISCOVERY_URL, JWKS_URL, DISCOVERY_URL, JWKS_URL]


def test_known_key_has_bounded_stale_availability_then_fails_closed() -> None:
    clock = MutableClock(datetime(2026, 8, 11, 12, tzinfo=UTC))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = ScriptedJsonTransport(
        _metadata(),
        _jwks(key, "key-1"),
        OidcJsonTransportError("offline"),
        OidcJsonTransportError("still offline"),
    )
    provider = _provider(transport, clock=clock)
    provider.signing_key("key-1")

    clock.advance(timedelta(minutes=6))
    assert provider.signing_key("key-1").key_id == "key-1"

    clock.advance(timedelta(minutes=10))
    with pytest.raises(AuthenticationError):
        provider.signing_key("key-1")

    assert transport.calls == [DISCOVERY_URL, JWKS_URL, DISCOVERY_URL, DISCOVERY_URL]


def test_invalid_rotation_does_not_replace_last_valid_known_key() -> None:
    clock = MutableClock(datetime(2026, 8, 11, 12, tzinfo=UTC))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = ScriptedJsonTransport(
        _metadata(),
        _jwks(key, "key-1"),
        _metadata(),
        {"keys": []},
    )
    provider = _provider(transport, clock=clock)
    provider.signing_key("key-1")

    clock.advance(timedelta(minutes=6))

    assert provider.signing_key("key-1").key_id == "key-1"


def test_successful_rotation_that_removes_old_key_revokes_it_immediately() -> None:
    clock = MutableClock(datetime(2026, 8, 11, 12, tzinfo=UTC))
    old_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    transport = ScriptedJsonTransport(
        _metadata(),
        _jwks(old_key, "old-key"),
        _metadata(),
        _jwks(new_key, "new-key"),
    )
    provider = _provider(transport, clock=clock)
    provider.signing_key("old-key")
    clock.advance(timedelta(minutes=6))

    with pytest.raises(AuthenticationError):
        provider.signing_key("old-key")

    assert provider.signing_key("new-key").key_id == "new-key"


def test_provider_rejects_naive_clock_and_unsafe_cache_configuration() -> None:
    transport = ScriptedJsonTransport()
    naive_provider = _provider(transport, clock=lambda: datetime(2026, 8, 11))

    with pytest.raises(AuthenticationError):
        naive_provider.signing_key("key-1")
    with pytest.raises(ValueError):
        OidcDiscoveryJwksProvider(
            issuer="http://identity.example.test",
            transport=transport,
        )
    with pytest.raises(ValueError):
        OidcDiscoveryJwksProvider(
            issuer=ISSUER,
            transport=transport,
            cache_ttl=timedelta(0),
        )
    with pytest.raises(ValueError):
        OidcDiscoveryJwksProvider(
            issuer=ISSUER,
            transport=transport,
            cache_ttl=timedelta(minutes=10),
            max_stale=timedelta(minutes=5),
        )


def test_urllib_transport_enforces_origin_media_type_and_document_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(FakeResponse(b'{"keys": []}'))

    def build_fake_opener(*handlers: object) -> FakeOpener:
        return opener

    monkeypatch.setattr(oidc_remote, "build_opener", build_fake_opener)
    transport = UrllibOidcJsonTransport(allowed_origins={"https://keys.northstar.example.test"})

    assert transport.get_json(JWKS_URL) == {"keys": []}
    with pytest.raises(OidcJsonTransportError):
        transport.get_json("https://attacker.example.test/jwks.json")


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(b"not-json"),
        FakeResponse(b"[]"),
        FakeResponse(b"{}", content_type="text/html"),
        FakeResponse(b"{}", url="https://attacker.example.test/jwks.json"),
        FakeResponse(b"{}", content_length="999999"),
        FakeResponse(b"12345"),
        OSError("offline"),
    ],
)
def test_urllib_transport_fails_closed_on_unsafe_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: FakeResponse | Exception,
) -> None:
    opener = FakeOpener(response)

    def build_fake_opener(*handlers: object) -> FakeOpener:
        return opener

    monkeypatch.setattr(oidc_remote, "build_opener", build_fake_opener)
    transport = UrllibOidcJsonTransport(
        allowed_origins={"https://keys.northstar.example.test"},
        max_document_bytes=128,
    )

    with pytest.raises(OidcJsonTransportError):
        transport.get_json(JWKS_URL)


def _provider(
    transport: ScriptedJsonTransport,
    *,
    clock: Callable[[], datetime] | None = None,
) -> OidcDiscoveryJwksProvider:
    return OidcDiscoveryJwksProvider(
        issuer=ISSUER,
        transport=transport,
        allowed_jwks_origins={"https://keys.northstar.example.test"},
        cache_ttl=timedelta(minutes=5),
        max_stale=timedelta(minutes=15),
        refresh_cooldown=timedelta(seconds=1),
        clock=clock,
    )


def _metadata() -> dict[str, object]:
    return {"issuer": ISSUER, "jwks_uri": JWKS_URL}


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


def _polaris_token(key: rsa.RSAPrivateKey, kid: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-care-1",
            "jti": "tok-discovery-1",
            "client_id": "polaris-web",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "scope": "polaris.patient.read",
            "roles": ["care_coordinator"],
            "facilities": ["FAC-NORTH"],
            "assigned_patients": ["SYN-P1001"],
        },
        key,
        algorithm="RS256",
        headers={"typ": "at+jwt", "kid": kid},
    )


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

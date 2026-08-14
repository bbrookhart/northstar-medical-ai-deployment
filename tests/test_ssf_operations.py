from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from types import TracebackType
from typing import Any, cast
from urllib.error import URLError

import pytest
from pydantic import SecretStr

import polaris.security.ssf_operations as ssf
from polaris.security.ssf_operations import (
    PendingSsfVerification,
    SsfHttpResponse,
    SsfOperationError,
    SsfStreamConfiguration,
    SsfStreamOperationsClient,
    SsfStreamStatusValue,
    SsfSubjectOperation,
    SsfSubjectOperationAccepted,
    SsfTransportError,
    UrllibSsfHttpTransport,
)

ISSUER = "https://signals.northstar.example.test/tenant-a"
ORIGIN = "https://signals.northstar.example.test"
DISCOVERY_URL = f"{ORIGIN}/.well-known/ssf-configuration/tenant-a"
JWKS_URL = f"{ORIGIN}/keys/set-jwks.json"
CONFIGURATION_URL = f"{ORIGIN}/ssf/streams"
STATUS_URL = f"{ORIGIN}/ssf/status"
VERIFICATION_URL = f"{ORIGIN}/ssf/verification"
STREAM_ID = "northstar-stream-01"
AUTHORIZATION = "Bearer synthetic-management-token"
AUDIENCE = "polaris-identity-signals"
PUSH_URL = "https://polaris.northstar.example.test/identity-signals/northstar-stream-01"
SUBJECT_ISSUER = "https://identity.northstar.example.test"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
TOKEN_CLAIMS_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
EVENT_TYPES = (SESSION_REVOKED, TOKEN_CLAIMS_CHANGE)


@dataclass(frozen=True, slots=True)
class RecordedRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None


class ScriptedTransport:
    def __init__(self, *responses: SsfHttpResponse | Exception) -> None:
        self.responses = list(responses)
        self.requests: list[RecordedRequest] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> SsfHttpResponse:
        self.requests.append(RecordedRequest(method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError("Unexpected SSF request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeHeaders:
    def __init__(self, values: Mapping[str, str]) -> None:
        self.values = dict(values)

    def get(self, name: str) -> str | None:
        return self.values.get(name)

    def items(self) -> list[tuple[str, str]]:
        return list(self.values.items())


class FakeResponse:
    def __init__(
        self,
        *,
        raw: bytes = b"{}",
        url: str = DISCOVERY_URL,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.raw = raw
        self.url = url
        self.status = status
        self.headers = FakeHeaders(headers or {"Content-Type": "application/json"})

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
        self.requests: list[tuple[Any, float]] = []

    def open(self, request: Any, *, timeout: float) -> FakeResponse:
        self.requests.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _json_response(
    payload: object,
    *,
    no_store: bool = False,
    status_code: int = 200,
) -> SsfHttpResponse:
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if no_store:
        headers["Cache-Control"] = "no-store"
    return SsfHttpResponse(
        status_code=status_code,
        headers=headers,
        body=json.dumps(payload).encode(),
    )


def test_discovers_path_issuer_then_reads_status_and_requests_verification() -> None:
    transport = ScriptedTransport(
        _json_response(_metadata()),
        _json_response(
            {"stream_id": STREAM_ID, "status": "paused", "reason": "MAINTENANCE"},
            no_store=True,
        ),
        SsfHttpResponse(status_code=204, headers={"Cache-Control": "private, no-store"}),
    )
    client = _client(transport)

    configuration = client.discover()
    status = client.read_status(STREAM_ID)
    pending = client.trigger_verification(STREAM_ID, state="synthetic-correlation-state")

    assert client.discovery_url == DISCOVERY_URL
    assert configuration.issuer == ISSUER
    assert configuration.jwks_uri == JWKS_URL
    assert configuration.delivery_methods_supported == (ssf.SSF_PUSH_METHOD,)
    assert configuration.critical_subject_members == ("tenant", "user")
    assert configuration.authorization_scheme_urns == (ssf.OAUTH_AUTHORIZATION_SCHEME,)
    assert configuration.default_subjects == "NONE"
    assert status.status is SsfStreamStatusValue.PAUSED
    assert status.reason == "MAINTENANCE"
    assert pending == PendingSsfVerification(STREAM_ID, "synthetic-correlation-state")
    assert [request.url for request in transport.requests] == [
        DISCOVERY_URL,
        f"{STATUS_URL}?stream_id={STREAM_ID}",
        VERIFICATION_URL,
    ]
    assert "Authorization" not in transport.requests[0].headers
    assert transport.requests[1].headers["Authorization"] == AUTHORIZATION
    assert json.loads(transport.requests[2].body or b"") == {
        "state": "synthetic-correlation-state",
        "stream_id": STREAM_ID,
    }


def test_generated_verification_state_is_bounded_and_acceptance_is_not_delivery_proof() -> None:
    transport = ScriptedTransport(
        _json_response(_metadata()),
        SsfHttpResponse(status_code=204, headers={"cache-control": "no-store"}),
    )
    client = _client(transport)
    client.discover()

    pending = client.trigger_verification(STREAM_ID)

    assert pending.stream_id == STREAM_ID
    assert 32 <= len(pending.state) <= 64
    assert not hasattr(pending, "delivered")


def test_stream_configuration_status_subject_and_delete_lifecycle_is_strictly_bound() -> None:
    created_payload = _stream_configuration(description="Polaris continuous access")
    updated_payload = _stream_configuration(description="Updated Polaris stream")
    replaced_payload = _stream_configuration()
    transport = ScriptedTransport(
        _json_response(_metadata()),
        _json_response(created_payload, no_store=True, status_code=201),
        _json_response(created_payload, no_store=True),
        _json_response(updated_payload, no_store=True),
        _json_response(replaced_payload, no_store=True),
        _json_response(
            {"stream_id": STREAM_ID, "status": "paused", "reason": "MAINTENANCE"},
            no_store=True,
        ),
        SsfHttpResponse(status_code=204, headers={"Cache-Control": "no-store"}),
        SsfHttpResponse(status_code=204, headers={"Cache-Control": "no-store"}),
        SsfHttpResponse(status_code=204, headers={"Cache-Control": "no-store"}),
    )
    client = _client(transport)
    client.discover()

    created = client.create_stream(description="Polaris continuous access")
    read = client.read_configuration(STREAM_ID)
    updated = client.update_configuration(read, description="Updated Polaris stream")
    replaced = client.replace_configuration(
        updated,
        events_requested=reversed(EVENT_TYPES),
    )
    status = client.update_status(
        STREAM_ID,
        SsfStreamStatusValue.PAUSED,
        reason="MAINTENANCE",
    )
    added = client.add_subject(STREAM_ID, "synthetic-user-01")
    removed = client.remove_subject(STREAM_ID, "synthetic-user-01")
    client.delete_stream(STREAM_ID)

    assert created == SsfStreamConfiguration(
        stream_id=STREAM_ID,
        issuer=ISSUER,
        audience=AUDIENCE,
        delivery_endpoint=PUSH_URL,
        events_supported=EVENT_TYPES,
        events_requested=EVENT_TYPES,
        events_delivered=EVENT_TYPES,
        description="Polaris continuous access",
        min_verification_interval=30,
        inactivity_timeout=3600,
    )
    assert read == created
    assert replaced.description is None
    assert status.status is SsfStreamStatusValue.PAUSED
    assert added == SsfSubjectOperationAccepted(STREAM_ID, SsfSubjectOperation.ADD)
    assert removed == SsfSubjectOperationAccepted(STREAM_ID, SsfSubjectOperation.REMOVE)
    assert not hasattr(added, "subject_exists")
    assert [request.method for request in transport.requests] == [
        "GET",
        "POST",
        "GET",
        "PATCH",
        "PUT",
        "POST",
        "POST",
        "POST",
        "DELETE",
    ]
    assert transport.requests[2].url == f"{CONFIGURATION_URL}?stream_id={STREAM_ID}"
    assert transport.requests[-1].url == f"{CONFIGURATION_URL}?stream_id={STREAM_ID}"
    create_body = json.loads(transport.requests[1].body or b"")
    assert create_body == {
        "delivery": {"endpoint_url": PUSH_URL, "method": ssf.SSF_PUSH_METHOD},
        "description": "Polaris continuous access",
        "events_requested": list(EVENT_TYPES),
    }
    patch_body = json.loads(transport.requests[3].body or b"")
    assert patch_body["events_delivered"] == list(EVENT_TYPES)
    assert patch_body["stream_id"] == STREAM_ID
    add_body = json.loads(transport.requests[6].body or b"")
    assert add_body == {
        "stream_id": STREAM_ID,
        "subject": {
            "format": "iss_sub",
            "iss": SUBJECT_ISSUER,
            "sub": "synthetic-user-01",
        },
        "verified": False,
    }
    assert AUTHORIZATION not in repr(created)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("iss", "https://attacker.example.test"),
        ("aud", "different-receiver"),
        ("aud", [AUDIENCE, "different-receiver"]),
        (
            "delivery",
            {
                "method": ssf.SSF_PUSH_METHOD,
                "endpoint_url": "https://attacker.example.test/events",
            },
        ),
        ("events_requested", [SESSION_REVOKED]),
        ("events_delivered", [SESSION_REVOKED]),
        ("events_supported", [SESSION_REVOKED]),
        ("min_verification_interval", True),
        ("inactivity_timeout", 86401),
    ],
)
def test_stream_configuration_rejects_issuer_audience_delivery_and_event_substitution(
    field: str,
    value: object,
) -> None:
    payload = _stream_configuration()
    payload[field] = value
    transport = ScriptedTransport(
        _json_response(_metadata()),
        _json_response(payload, no_store=True),
    )
    client = _client(transport)
    client.discover()

    with pytest.raises(SsfOperationError, match="configuration response is invalid"):
        client.read_configuration(STREAM_ID)


def test_stream_mutations_reject_pending_or_unbound_responses() -> None:
    current = SsfStreamConfiguration(
        stream_id=STREAM_ID,
        issuer=ISSUER,
        audience=AUDIENCE,
        delivery_endpoint=PUSH_URL,
        events_supported=EVENT_TYPES,
        events_requested=EVENT_TYPES,
        events_delivered=EVENT_TYPES,
        description=None,
        min_verification_interval=None,
        inactivity_timeout=None,
    )
    transport = ScriptedTransport(
        _json_response(_metadata()),
        SsfHttpResponse(status_code=202, headers={"Cache-Control": "no-store"}),
    )
    client = _client(transport)
    client.discover()

    with pytest.raises(SsfOperationError):
        client.update_configuration(current, description="pending")

    unbound = replace(current, audience="different-receiver")
    with pytest.raises(ValueError, match="outside local policy"):
        client.replace_configuration(unbound, events_requested=EVENT_TYPES)
    with pytest.raises(ValueError, match="requires a property"):
        client.update_configuration(current)
    with pytest.raises(ValueError, match="exactly match"):
        client.replace_configuration(current, events_requested=[SESSION_REVOKED])


@pytest.mark.parametrize("subject", ["", "has space", "line\nbreak", "x" * 129])
def test_subject_management_rejects_unsafe_identifiers_before_credentials_or_transport(
    subject: str,
) -> None:
    transport = ScriptedTransport(_json_response(_metadata()))
    client = _client(transport)
    client.discover()

    with pytest.raises(ValueError, match="subject ID"):
        client.add_subject(STREAM_ID, subject)
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "response",
    [
        SsfHttpResponse(status_code=200, headers={}),
        SsfHttpResponse(status_code=200, headers={"Cache-Control": "no-store"}, body=b"{}"),
        SsfHttpResponse(status_code=404, headers={"Cache-Control": "no-store"}),
    ],
)
def test_subject_acknowledgement_is_empty_noncacheable_and_non_enumerating(
    response: SsfHttpResponse,
) -> None:
    transport = ScriptedTransport(_json_response(_metadata()), response)
    client = _client(transport)
    client.discover()

    with pytest.raises(SsfOperationError, match="management request failed") as raised:
        client.add_subject(STREAM_ID, "synthetic-user-01")
    assert "synthetic-user-01" not in str(raised.value)


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("spec_version", "1_0-ID1"),
        ("issuer", "https://attacker.example.test"),
        ("jwks_uri", "http://signals.northstar.example.test/keys.json"),
        ("status_endpoint", "https://attacker.example.test/status"),
        ("delivery_methods_supported", ["urn:ietf:rfc:8936"]),
        ("authorization_schemes", [{"spec_urn": "urn:example:unsupported"}]),
        ("default_subjects", "SOME"),
        ("default_subjects", None),
        ("add_subject_endpoint", None),
        ("remove_subject_endpoint", "https://attacker.example.test/remove"),
        ("critical_subject_members", ["tenant", "tenant"]),
    ],
)
def test_discovery_rejects_version_trust_and_metadata_substitution(
    change: str,
    value: object,
) -> None:
    metadata = _metadata()
    metadata[change] = value
    client = _client(ScriptedTransport(_json_response(metadata)))

    with pytest.raises(SsfOperationError, match="configuration is invalid"):
        client.discover()

    with pytest.raises(SsfOperationError, match="has not been discovered"):
        client.read_status(STREAM_ID)


@pytest.mark.parametrize(
    "raw_body",
    [
        b"[]",
        b"not-json",
        b'{"issuer":"one","issuer":"two"}',
    ],
)
def test_discovery_rejects_non_object_invalid_and_duplicate_json(raw_body: bytes) -> None:
    response = SsfHttpResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body=raw_body,
    )

    with pytest.raises(SsfOperationError):
        _client(ScriptedTransport(response)).discover()


def test_failed_rediscovery_invalidates_previously_accepted_configuration() -> None:
    transport = ScriptedTransport(
        _json_response(_metadata()),
        SsfHttpResponse(status_code=503, headers={}, body=b""),
    )
    client = _client(transport)
    client.discover()

    with pytest.raises(SsfOperationError):
        client.discover()
    with pytest.raises(SsfOperationError, match="has not been discovered"):
        client.trigger_verification(STREAM_ID)


@pytest.mark.parametrize(
    "response",
    [
        _json_response({"stream_id": "wrong", "status": "enabled"}, no_store=True),
        _json_response({"stream_id": STREAM_ID, "status": "unknown"}, no_store=True),
        _json_response({"stream_id": STREAM_ID, "status": "enabled"}),
        SsfHttpResponse(
            status_code=200,
            headers={"Content-Type": "text/html", "Cache-Control": "no-store"},
            body=b"{}",
        ),
        SsfHttpResponse(status_code=404, headers={}, body=b""),
    ],
)
def test_status_fails_closed_on_binding_state_cache_media_and_status_errors(
    response: SsfHttpResponse,
) -> None:
    transport = ScriptedTransport(_json_response(_metadata()), response)
    client = _client(transport)
    client.discover()

    with pytest.raises(SsfOperationError):
        client.read_status(STREAM_ID)


def test_status_errors_expose_only_bounded_retry_metadata() -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    transport = ScriptedTransport(
        _json_response(_metadata()),
        SsfHttpResponse(status_code=429, headers={"Retry-After": "5"}),
        SsfHttpResponse(
            status_code=503,
            headers={"Retry-After": format_datetime(now + timedelta(seconds=7), usegmt=True)},
        ),
        SsfHttpResponse(status_code=502, headers={"Retry-After": "invalid"}),
        SsfHttpResponse(status_code=401, headers={"Retry-After": "10"}),
    )
    client = _client(transport, clock=lambda: now)
    client.discover()

    with pytest.raises(SsfOperationError) as rate_limited:
        client.read_status(STREAM_ID)
    assert rate_limited.value.retryable
    assert rate_limited.value.retry_after_seconds == 5

    with pytest.raises(SsfOperationError) as unavailable:
        client.read_status(STREAM_ID)
    assert unavailable.value.retryable
    assert unavailable.value.retry_after_seconds == 7

    with pytest.raises(SsfOperationError) as malformed:
        client.read_status(STREAM_ID)
    assert malformed.value.retryable
    assert malformed.value.retry_after_seconds is None

    with pytest.raises(SsfOperationError) as unauthorized:
        client.read_status(STREAM_ID)
    assert unauthorized.value.retryable is False
    assert unauthorized.value.retry_after_seconds is None


@pytest.mark.parametrize(
    "response",
    [
        SsfHttpResponse(status_code=202, headers={"Cache-Control": "no-store"}),
        SsfHttpResponse(status_code=204, headers={}),
        SsfHttpResponse(status_code=204, headers={"Cache-Control": "no-store"}, body=b"x"),
    ],
)
def test_verification_requires_empty_noncacheable_204(response: SsfHttpResponse) -> None:
    transport = ScriptedTransport(_json_response(_metadata()), response)
    client = _client(transport)
    client.discover()

    with pytest.raises(SsfOperationError, match="verification request failed"):
        client.trigger_verification(STREAM_ID, state="valid-state")


@pytest.mark.parametrize("value", ["bad stream", "", "x" * 129])
def test_stream_identifiers_are_rejected_before_credentials_or_transport(value: str) -> None:
    transport = ScriptedTransport(_json_response(_metadata()))
    client = _client(transport)
    client.discover()

    with pytest.raises(ValueError, match="stream ID"):
        client.read_status(value)

    assert len(transport.requests) == 1


@pytest.mark.parametrize("state", ["", " leading", "line\nbreak", "x" * 1025])
def test_verification_state_is_strictly_bounded(state: str) -> None:
    transport = ScriptedTransport(_json_response(_metadata()))
    client = _client(transport)
    client.discover()

    with pytest.raises(ValueError, match="verification state"):
        client.trigger_verification(STREAM_ID, state=state)


def test_management_authorization_is_secret_wrapped_and_header_injection_fails() -> None:
    transport = ScriptedTransport(_json_response(_metadata()))
    client = SsfStreamOperationsClient(
        issuer=ISSUER,
        transport=transport,
        authorization_provider=lambda: SecretStr("Bearer value\r\nX-Evil: yes"),
        expected_audience=AUDIENCE,
        receiver_push_endpoint=PUSH_URL,
        requested_event_types=EVENT_TYPES,
        subject_issuer=SUBJECT_ISSUER,
    )
    client.discover()

    with pytest.raises(SsfOperationError, match="authorization is invalid"):
        client.read_status(STREAM_ID)

    assert len(transport.requests) == 1


def test_cross_origin_endpoints_require_explicit_administrator_allowlist() -> None:
    keys_origin = "https://keys.northstar.example.test"
    metadata = _metadata()
    metadata["jwks_uri"] = f"{keys_origin}/set-jwks.json"

    with pytest.raises(SsfOperationError):
        _client(ScriptedTransport(_json_response(metadata))).discover()

    client = _client(
        ScriptedTransport(_json_response(metadata)),
        allowed_origins={ORIGIN, keys_origin},
    )
    assert client.discover().jwks_uri == f"{keys_origin}/set-jwks.json"


def test_transport_enforces_origin_method_request_size_and_header_safety() -> None:
    transport = UrllibSsfHttpTransport(allowed_origins={ORIGIN}, max_request_bytes=8)

    with pytest.raises(SsfTransportError, match="outside"):
        transport.request(method="GET", url="https://attacker.example.test/x", headers={})
    with pytest.raises(SsfTransportError, match="method"):
        transport.request(method="OPTIONS", url=CONFIGURATION_URL, headers={})
    with pytest.raises(SsfTransportError, match="request exceeded"):
        transport.request(method="POST", url=CONFIGURATION_URL, headers={}, body=b"123456789")
    with pytest.raises(SsfTransportError, match="header"):
        transport.request(
            method="GET",
            url=CONFIGURATION_URL,
            headers={"Authorization": "safe\r\nunsafe"},
        )


def test_transport_returns_bounded_response_and_refuses_redirects_and_failures() -> None:
    transport = UrllibSsfHttpTransport(allowed_origins={ORIGIN}, max_response_bytes=8)
    success = FakeOpener(
        FakeResponse(
            raw=b'{"ok":1}',
            headers={"Content-Type": "application/json", "Content-Length": "8"},
        )
    )
    transport._opener = cast(Any, success)

    response = transport.request(method="GET", url=DISCOVERY_URL, headers={"Accept": "x"})

    assert response.status_code == 200
    assert response.body == b'{"ok":1}'
    assert response.headers["content-type"] == "application/json"
    request, timeout = success.requests[0]
    assert request.get_header("User-agent") == "northstar-polaris/0.1"
    assert timeout == 3.0

    transport._opener = cast(Any, FakeOpener(FakeResponse(url=f"{ORIGIN}/redirected")))
    with pytest.raises(SsfTransportError, match="redirects"):
        transport.request(method="GET", url=DISCOVERY_URL, headers={})

    transport._opener = cast(Any, FakeOpener(URLError("offline")))
    with pytest.raises(SsfTransportError, match="request failed"):
        transport.request(method="GET", url=DISCOVERY_URL, headers={})


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(raw=b"123456789"),
        FakeResponse(raw=b"{}", headers={"Content-Length": "9"}),
        FakeResponse(raw=b"{}", headers={"Content-Length": "invalid"}),
    ],
)
def test_transport_rejects_oversized_or_malformed_content_length(response: FakeResponse) -> None:
    transport = UrllibSsfHttpTransport(allowed_origins={ORIGIN}, max_response_bytes=8)
    transport._opener = cast(Any, FakeOpener(response))

    with pytest.raises(SsfTransportError):
        transport.request(method="GET", url=DISCOVERY_URL, headers={})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"allowed_origins": set()},
        {"allowed_origins": {"http://unsafe.example.test"}},
        {"allowed_origins": {ORIGIN}, "timeout_seconds": 0},
        {"allowed_origins": {ORIGIN}, "max_response_bytes": 0},
        {"allowed_origins": {ORIGIN}, "max_request_bytes": 0},
    ],
)
def test_transport_configuration_fails_closed(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        UrllibSsfHttpTransport(**kwargs)  # type: ignore[arg-type]


def test_client_rejects_unsafe_issuer_origin_and_authorization_scheme() -> None:
    transport = ScriptedTransport()
    with pytest.raises(ValueError):
        SsfStreamOperationsClient(
            issuer="http://signals.example.test",
            transport=transport,
            authorization_provider=_authorization,
            expected_audience=AUDIENCE,
            receiver_push_endpoint=PUSH_URL,
            requested_event_types=EVENT_TYPES,
            subject_issuer=SUBJECT_ISSUER,
        )
    with pytest.raises(ValueError):
        _client(transport, allowed_origins={f"{ORIGIN}/path"})
    with pytest.raises(ValueError, match="At least one trusted"):
        _client(transport, allowed_origins=set())
    with pytest.raises(ValueError):
        SsfStreamOperationsClient(
            issuer=ISSUER,
            transport=transport,
            authorization_provider=_authorization,
            expected_audience=AUDIENCE,
            receiver_push_endpoint=PUSH_URL,
            requested_event_types=EVENT_TYPES,
            subject_issuer=SUBJECT_ISSUER,
            authorization_scheme_urn=" ",
        )
    with pytest.raises(ValueError, match="expected audience"):
        SsfStreamOperationsClient(
            issuer=ISSUER,
            transport=transport,
            authorization_provider=_authorization,
            expected_audience=" ",
            receiver_push_endpoint=PUSH_URL,
            requested_event_types=EVENT_TYPES,
            subject_issuer=SUBJECT_ISSUER,
        )
    with pytest.raises(ValueError, match="canonical HTTPS"):
        SsfStreamOperationsClient(
            issuer=ISSUER,
            transport=transport,
            authorization_provider=_authorization,
            expected_audience=AUDIENCE,
            receiver_push_endpoint="http://receiver.example.test/events",
            requested_event_types=EVENT_TYPES,
            subject_issuer=SUBJECT_ISSUER,
        )
    with pytest.raises(ValueError, match="requested events"):
        SsfStreamOperationsClient(
            issuer=ISSUER,
            transport=transport,
            authorization_provider=_authorization,
            expected_audience=AUDIENCE,
            receiver_push_endpoint=PUSH_URL,
            requested_event_types=(),
            subject_issuer=SUBJECT_ISSUER,
        )


def test_mutation_inputs_and_empty_responses_fail_closed() -> None:
    transport = ScriptedTransport(
        _json_response(_metadata()),
        SsfHttpResponse(status_code=200, headers={"Cache-Control": "no-store"}),
    )
    client = _client(transport)
    client.discover()

    with pytest.raises(ValueError, match="status is invalid"):
        client.update_status(STREAM_ID, "paused")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="reason is invalid"):
        client.update_status(STREAM_ID, SsfStreamStatusValue.PAUSED, reason="line\nbreak")
    with pytest.raises(ValueError, match="description is invalid"):
        client.create_stream(description="line\nbreak")
    with pytest.raises(SsfOperationError, match="management request failed"):
        client.delete_stream(STREAM_ID)


def test_transport_and_authorization_provider_failures_are_non_enumerating() -> None:
    unavailable = _client(ScriptedTransport(SsfTransportError("sensitive upstream detail")))
    with pytest.raises(SsfOperationError, match="operation is unavailable") as raised:
        unavailable.discover()
    assert "sensitive upstream detail" not in str(raised.value)
    assert raised.value.retryable

    transport = ScriptedTransport(_json_response(_metadata()))

    def failed_authorization() -> SecretStr:
        raise RuntimeError("synthetic secret retrieval detail")

    client = SsfStreamOperationsClient(
        issuer=ISSUER,
        transport=transport,
        authorization_provider=failed_authorization,
        expected_audience=AUDIENCE,
        receiver_push_endpoint=PUSH_URL,
        requested_event_types=EVENT_TYPES,
        subject_issuer=SUBJECT_ISSUER,
    )
    client.discover()
    with pytest.raises(SsfOperationError, match="authorization is unavailable") as auth_error:
        client.read_status(STREAM_ID)
    assert "synthetic secret" not in str(auth_error.value)


def _client(
    transport: ScriptedTransport,
    *,
    allowed_origins: set[str] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> SsfStreamOperationsClient:
    return SsfStreamOperationsClient(
        issuer=ISSUER,
        transport=transport,
        authorization_provider=_authorization,
        expected_audience=AUDIENCE,
        receiver_push_endpoint=PUSH_URL,
        requested_event_types=EVENT_TYPES,
        subject_issuer=SUBJECT_ISSUER,
        allowed_endpoint_origins=allowed_origins,
        clock=clock,
    )


def _authorization() -> SecretStr:
    return SecretStr(AUTHORIZATION)


def _metadata() -> dict[str, object]:
    return {
        "spec_version": "1_0",
        "issuer": ISSUER,
        "jwks_uri": JWKS_URL,
        "delivery_methods_supported": [ssf.SSF_PUSH_METHOD],
        "configuration_endpoint": CONFIGURATION_URL,
        "status_endpoint": STATUS_URL,
        "add_subject_endpoint": f"{ORIGIN}/ssf/subjects:add",
        "remove_subject_endpoint": f"{ORIGIN}/ssf/subjects:remove",
        "verification_endpoint": VERIFICATION_URL,
        "critical_subject_members": ["tenant", "user"],
        "authorization_schemes": [{"spec_urn": ssf.OAUTH_AUTHORIZATION_SCHEME}],
        "default_subjects": "NONE",
        "unknown_extension": "ignored",
    }


def _stream_configuration(*, description: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "stream_id": STREAM_ID,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "delivery": {"method": ssf.SSF_PUSH_METHOD, "endpoint_url": PUSH_URL},
        "events_supported": list(EVENT_TYPES),
        "events_requested": list(EVENT_TYPES),
        "events_delivered": list(EVENT_TYPES),
        "min_verification_interval": 30,
        "inactivity_timeout": 3600,
    }
    if description is not None:
        payload["description"] = description
    return payload

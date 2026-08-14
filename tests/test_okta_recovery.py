from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
from pydantic import SecretStr

from polaris.domain import IdentitySignalType
from polaris.security.okta_recovery import (
    OKTA_SSF_INTEROPERABILITY_PROFILE,
    OktaRecoveryError,
    OktaSystemLogRecoveryClient,
)
from polaris.security.ssf_operations import (
    SsfHttpResponse,
    SsfTransportError,
)

ORIGIN = "https://northstar.okta.example.test"


class MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


class ScriptedTransport:
    def __init__(self, *responses: SsfHttpResponse | Exception) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> SsfHttpResponse:
        recorded: dict[str, object] = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "body": body,
        }
        self.requests.append(recorded)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_okta_profile_and_cursor_page_normalize_only_documented_success_events() -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    transport = ScriptedTransport()
    client = _client(now, transport)
    cursor = _next_cursor(client.initial_cursor_url)
    transport.responses.append(
        _response(
            client,
            cursor,
            [
                _event(
                    event_id="11111111-1111-4111-8111-111111111111",
                    event_type="user.session.end",
                    published=now - timedelta(seconds=4),
                    subject="00uNorthstarUser01",
                ),
                _event(
                    event_id="22222222-2222-4222-8222-222222222222",
                    event_type="user.account.update_password",
                    published=now - timedelta(seconds=3),
                    subject="00uNorthstarUser02",
                ),
                _event(
                    event_id="33333333-3333-4333-8333-333333333333",
                    event_type="user.mfa.factor.activate",
                    published=now - timedelta(seconds=2),
                    subject="00uIgnoredFailed01",
                    result="FAILURE",
                ),
            ],
        )
    )

    page = client.fetch_page()

    assert page.scanned_count == 3
    assert page.ignored_count == 1
    assert page.caught_up is False
    assert page.next_cursor_url == cursor
    assert [event.signal_type for event in page.events] == [
        IdentitySignalType.SESSION_REVOKED,
        IdentitySignalType.CREDENTIAL_CHANGE,
    ]
    assert [event.subject for event in page.events] == [
        "00uNorthstarUser01",
        "00uNorthstarUser02",
    ]
    request = transport.requests[0]
    assert request["method"] == "GET"
    assert request["body"] is None
    assert request["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer system-log-oauth-token",
    }
    assert OKTA_SSF_INTEROPERABILITY_PROFILE.ssf_event_replay_documented is False
    assert OKTA_SSF_INTEROPERABILITY_PROFILE.live_final_ssf_conformance_verified is False


def test_empty_polling_page_is_caught_up_but_still_advances_cursor() -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    transport = ScriptedTransport()
    client = _client(now, transport)
    first_cursor = _next_cursor(client.initial_cursor_url, after="cursor-1")
    second_cursor = _next_cursor(client.initial_cursor_url, after="cursor-2")
    transport.responses.append(_response(client, second_cursor, []))

    page = client.fetch_page(cursor_url=first_cursor)

    assert page.caught_up is True
    assert page.events == ()
    assert page.next_cursor_url == second_cursor
    assert transport.requests[0]["url"] == first_cursor


@pytest.mark.parametrize(
    ("origin", "since_offset", "message"),
    [
        ("http://northstar.okta.example.test", timedelta(hours=-1), "origin"),
        (f"{ORIGIN}/tenant", timedelta(hours=-1), "origin"),
        (ORIGIN, timedelta(days=-90), "retention"),
        (ORIGIN, timedelta(seconds=1), "retention"),
    ],
)
def test_recovery_configuration_fails_closed(
    origin: str,
    since_offset: timedelta,
    message: str,
) -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    with pytest.raises(ValueError, match=message):
        OktaSystemLogRecoveryClient(
            okta_origin=origin,
            transport=ScriptedTransport(),
            authorization_provider=lambda: SecretStr("token"),
            initial_since=now + since_offset,
            clock=MutableClock(now),
        )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda url: url.replace("northstar.okta", "attacker"),
        lambda url: url.replace("/api/v1/logs", "/api/v1/users"),
        lambda url: url.replace("sortOrder=ASCENDING", "sortOrder=DESCENDING"),
        lambda url: url.replace("filter=", "q="),
        lambda url: f"{url}&until=2026-08-11T12%3A00%3A00Z",
        lambda url: url.replace("2026-08-11T11%3A55%3A00.000Z", "2026-08-10T11%3A55%3A00.000Z"),
        lambda url: f"{url}#fragment",
    ],
)
def test_recovery_cursor_rejects_origin_path_query_and_fragment_substitution(
    mutator: Any,
) -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    transport = ScriptedTransport()
    client = _client(now, transport)
    substituted = mutator(_next_cursor(client.initial_cursor_url))

    with pytest.raises(OktaRecoveryError):
        client.fetch_page(cursor_url=substituted)
    assert transport.requests == []


@pytest.mark.parametrize(
    ("status", "retryable"),
    [(401, False), (429, True), (503, True)],
)
def test_provider_http_failures_expose_only_retry_classification(
    status: int,
    retryable: bool,
) -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    transport = ScriptedTransport(SsfHttpResponse(status, {}, b"provider detail"))
    client = _client(now, transport)

    with pytest.raises(OktaRecoveryError) as caught:
        client.fetch_page()
    assert str(caught.value) == "Okta identity-event recovery failed"
    assert caught.value.retryable is retryable
    assert "provider detail" not in str(caught.value)


def test_transport_and_credential_failures_do_not_leak_secrets() -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    client = _client(now, ScriptedTransport(SsfTransportError("socket with secret")))
    with pytest.raises(OktaRecoveryError) as caught:
        client.fetch_page()
    assert caught.value.retryable is True
    assert "secret" not in str(caught.value)

    empty_token_client = OktaSystemLogRecoveryClient(
        okta_origin=ORIGIN,
        transport=ScriptedTransport(),
        authorization_provider=lambda: SecretStr(""),
        initial_since=now - timedelta(minutes=5),
        clock=MutableClock(now),
    )
    with pytest.raises(OktaRecoveryError) as empty:
        empty_token_client.fetch_page()
    assert empty.value.retryable is False


@pytest.mark.parametrize(
    "case",
    [
        "not-page",
        "invalid-target-member",
        "bad-uuid",
        "unsupported-type",
        "missing-outcome",
        "missing-target",
        "bad-subject",
    ],
)
def test_malformed_or_out_of_profile_system_log_events_fail_the_whole_page(
    case: str,
) -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    transport = ScriptedTransport()
    client = _client(now, transport)
    payloads: dict[str, object] = {
        "not-page": {"not": "a page"},
        "invalid-target-member": [
            _event(target=["not-a-target", {"type": "User", "id": "00uNorthstarUser01"}])
        ],
        "bad-uuid": [_event(event_id="not-a-uuid")],
        "unsupported-type": [_event(event_type="user.session.start")],
        "missing-outcome": [_event(result=None)],
        "missing-target": [_event(target=[])],
        "bad-subject": [_event(target=[{"type": "User", "id": "x"}])],
    }
    transport.responses.append(
        _response(client, _next_cursor(client.initial_cursor_url), payloads[case])
    )

    with pytest.raises(OktaRecoveryError):
        client.fetch_page()


def test_duplicate_event_and_invalid_link_or_media_type_fail_closed() -> None:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    duplicate = _event()
    clients: list[OktaSystemLogRecoveryClient] = []
    transports = [
        ScriptedTransport(),
        ScriptedTransport(),
        ScriptedTransport(),
    ]
    for transport in transports:
        clients.append(_client(now, transport))
    cursor = _next_cursor(clients[0].initial_cursor_url)
    transports[0].responses.append(_response(clients[0], cursor, [duplicate, duplicate]))
    transports[1].responses.append(
        SsfHttpResponse(200, {"content-type": "application/json"}, b"[]")
    )
    transports[2].responses.append(
        SsfHttpResponse(
            200,
            {"content-type": "text/html", "link": f'<{cursor}>; rel="next"'},
            b"[]",
        )
    )

    for client in clients:
        with pytest.raises(OktaRecoveryError):
            client.fetch_page()


def _client(now: datetime, transport: ScriptedTransport) -> OktaSystemLogRecoveryClient:
    return OktaSystemLogRecoveryClient(
        okta_origin=ORIGIN,
        transport=transport,
        authorization_provider=lambda: SecretStr("system-log-oauth-token"),
        initial_since=now - timedelta(minutes=5),
        clock=MutableClock(now),
    )


def _next_cursor(initial_url: str, *, after: str = "cursor-1") -> str:
    parsed = urlsplit(initial_url)
    query = [*parse_qsl(parsed.query, keep_blank_values=True), ("after", after)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _response(
    client: OktaSystemLogRecoveryClient,
    cursor: str,
    payload: object,
) -> SsfHttpResponse:
    link = f'<{client.initial_cursor_url}>; rel="self", <{cursor}>; rel="next"'
    return SsfHttpResponse(
        200,
        {
            "content-type": "application/json; charset=utf-8",
            "link": link,
        },
        json.dumps(payload).encode(),
    )


def _event(
    *,
    event_id: object = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    event_type: object = "user.session.end",
    published: datetime | None = None,
    subject: str = "00uNorthstarUser01",
    result: object = "SUCCESS",
    target: object | None = None,
) -> dict[str, object]:
    timestamp = published or datetime(2026, 8, 11, 11, 59, 59, tzinfo=UTC)
    return {
        "uuid": event_id,
        "published": timestamp.isoformat().replace("+00:00", "Z"),
        "eventType": event_type,
        "outcome": {"result": result},
        "target": target if target is not None else [{"type": "User", "id": subject}],
    }

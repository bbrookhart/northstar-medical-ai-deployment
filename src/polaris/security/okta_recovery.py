from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from urllib.parse import SplitResult, parse_qs, urlencode, urlsplit
from uuid import UUID

from pydantic import SecretStr

from polaris.domain import IdentitySignalType
from polaris.security.ssf_operations import SsfHttpTransport, SsfTransportError
from polaris.services.audit import utc_now

_SYSTEM_LOG_PATH = "/api/v1/logs"
_PAGE_LIMIT = 100
_MAX_BODY_BYTES = 256 * 1024
_MAX_LINK_BYTES = 8 * 1024
_MAX_CURSOR_BYTES = 4 * 1024
_OKTA_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")
_OUTCOME_RESULTS = frozenset({"SUCCESS", "FAILURE", "SKIPPED", "UNKNOWN"})

OKTA_SYSTEM_LOG_EVENT_TYPES: Mapping[str, IdentitySignalType] = MappingProxyType(
    {
        "user.session.end": IdentitySignalType.SESSION_REVOKED,
        "user.mfa.factor.activate": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.mfa.factor.deactivate": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.mfa.factor.reset_all": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.mfa.factor.suspend": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.mfa.factor.unsuspend": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.mfa.factor.update": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.account.reset_password": IdentitySignalType.CREDENTIAL_CHANGE,
        "user.account.update_password": IdentitySignalType.CREDENTIAL_CHANGE,
    }
)

_EVENT_FILTER = " or ".join(
    f'eventType eq "{event_type}"' for event_type in OKTA_SYSTEM_LOG_EVENT_TYPES
)


class OktaRecoveryError(RuntimeError):
    """Detail-free failure at the separately authorized Okta recovery boundary."""

    def __init__(self, *, retryable: bool = False) -> None:
        super().__init__("Okta identity-event recovery failed")
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class OktaSsfInteroperabilityProfile:
    provider: str
    assessed_on: str
    ssf_events: tuple[IdentitySignalType, ...]
    ssf_event_replay_documented: bool
    compensating_cursor_feed: str
    live_final_ssf_conformance_verified: bool


OKTA_SSF_INTEROPERABILITY_PROFILE = OktaSsfInteroperabilityProfile(
    provider="Okta Identity Engine",
    assessed_on="2026-08-11",
    ssf_events=(IdentitySignalType.SESSION_REVOKED, IdentitySignalType.CREDENTIAL_CHANGE),
    ssf_event_replay_documented=False,
    compensating_cursor_feed="Okta System Log polling API",
    live_final_ssf_conformance_verified=False,
)


@dataclass(frozen=True, slots=True)
class OktaRecoveredIdentityEvent:
    """Minimized event normalized from the Okta System Log compensating feed."""

    provider_event_id: str
    provider_event_type: str
    signal_type: IdentitySignalType
    subject: str
    effective_at: datetime


@dataclass(frozen=True, slots=True)
class OktaSystemLogRecoveryPage:
    events: tuple[OktaRecoveredIdentityEvent, ...]
    next_cursor_url: str
    scanned_count: int
    ignored_count: int
    caught_up: bool


class OktaSystemLogRecoveryClient:
    """Strict cursor-polling adapter for the documented Okta SSF source events.

    This is a compensating read from the near-real-time, read-only System Log API. It is not SSF
    replay. The caller must persist ``next_cursor_url`` only after durably applying the whole page.
    Empty polling pages mean the cursor has caught up at that instant, not that future delivery is
    guaranteed.
    """

    def __init__(
        self,
        *,
        okta_origin: str,
        transport: SsfHttpTransport,
        authorization_provider: Callable[[], SecretStr],
        initial_since: datetime,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._origin = _validated_origin(okta_origin)
        self._transport = transport
        self._authorization_provider = authorization_provider
        self._clock = clock
        now = self._now()
        since = _aware_utc(initial_since)
        if not now - timedelta(days=89) <= since <= now:
            raise ValueError("Okta recovery start must be within the supported retention window")
        self._initial_since = since
        self._since_value = _rfc3339(since)
        self._initial_url = self._url(
            {
                "filter": _EVENT_FILTER,
                "limit": str(_PAGE_LIMIT),
                "since": self._since_value,
                "sortOrder": "ASCENDING",
            }
        )

    @property
    def initial_cursor_url(self) -> str:
        return self._initial_url

    def fetch_page(self, *, cursor_url: str | None = None) -> OktaSystemLogRecoveryPage:
        url = self._initial_url if cursor_url is None else self._validated_cursor(cursor_url)
        try:
            token = self._authorization_provider()
            if not isinstance(token, SecretStr) or not token.get_secret_value():
                raise OktaRecoveryError
            response = self._transport.request(
                method="GET",
                url=url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token.get_secret_value()}",
                },
            )
        except OktaRecoveryError:
            raise
        except SsfTransportError as exc:
            raise OktaRecoveryError(retryable=True) from exc
        except Exception as exc:
            raise OktaRecoveryError from exc

        if response.status_code != 200:
            raise OktaRecoveryError(
                retryable=response.status_code in {429, 502, 503, 504},
            )
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json" or len(response.body) > _MAX_BODY_BYTES:
            raise OktaRecoveryError
        next_url = self._validated_cursor(
            _next_link(response.headers.get("link")),
            require_after=True,
        )
        events, scanned, ignored = self._parse_events(response.body)
        return OktaSystemLogRecoveryPage(
            events=events,
            next_cursor_url=next_url,
            scanned_count=scanned,
            ignored_count=ignored,
            caught_up=scanned == 0,
        )

    def _parse_events(
        self,
        body: bytes,
    ) -> tuple[tuple[OktaRecoveredIdentityEvent, ...], int, int]:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OktaRecoveryError from exc
        if not isinstance(payload, list) or len(payload) > _PAGE_LIMIT:
            raise OktaRecoveryError

        recovered: list[OktaRecoveredIdentityEvent] = []
        seen_ids: set[str] = set()
        ignored = 0
        now = self._now()
        for raw in payload:
            if not isinstance(raw, dict):
                raise OktaRecoveryError
            event_id = _event_uuid(raw.get("uuid"))
            if event_id in seen_ids:
                raise OktaRecoveryError
            seen_ids.add(event_id)
            event_type = raw.get("eventType")
            if not isinstance(event_type, str) or event_type not in OKTA_SYSTEM_LOG_EVENT_TYPES:
                raise OktaRecoveryError
            effective_at = _published(raw.get("published"), now=now)
            if effective_at < self._initial_since:
                raise OktaRecoveryError
            outcome = raw.get("outcome")
            if not isinstance(outcome, dict) or not isinstance(outcome.get("result"), str):
                raise OktaRecoveryError
            if outcome["result"] not in _OUTCOME_RESULTS:
                raise OktaRecoveryError
            if outcome["result"] != "SUCCESS":
                ignored += 1
                continue
            subject = _user_target(raw.get("target"))
            recovered.append(
                OktaRecoveredIdentityEvent(
                    provider_event_id=event_id,
                    provider_event_type=event_type,
                    signal_type=OKTA_SYSTEM_LOG_EVENT_TYPES[event_type],
                    subject=subject,
                    # Published time is deliberately conservative when occurrence time is absent.
                    effective_at=effective_at,
                )
            )
        return tuple(recovered), len(payload), ignored

    def _validated_cursor(self, value: str, *, require_after: bool = False) -> str:
        if not isinstance(value, str) or not 1 <= len(value) <= _MAX_CURSOR_BYTES:
            raise OktaRecoveryError
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or _origin(parsed) != self._origin
            or parsed.path != _SYSTEM_LOG_PATH
        ):
            raise OktaRecoveryError
        try:
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise OktaRecoveryError from exc
        if not set(query).issubset({"after", "filter", "limit", "since", "sortOrder"}):
            raise OktaRecoveryError
        if (
            query.get("filter") != [_EVENT_FILTER]
            or query.get("limit") != [str(_PAGE_LIMIT)]
            or query.get("sortOrder") != ["ASCENDING"]
            or "until" in query
            or ("after" in query and not _safe_cursor_value(query["after"]))
            or ("since" in query and query["since"] != [self._since_value])
            or (require_after and "after" not in query)
            or ("after" not in query and value != self._initial_url)
        ):
            raise OktaRecoveryError
        return value

    def _url(self, query: Mapping[str, str]) -> str:
        return f"{self._origin}{_SYSTEM_LOG_PATH}?{urlencode(query)}"

    def _now(self) -> datetime:
        try:
            return _aware_utc(self._clock())
        except ValueError as exc:
            raise OktaRecoveryError from exc


def _validated_origin(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValueError("Okta origin is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Okta origin is invalid")
    try:
        return _origin(parsed)
    except ValueError as exc:
        raise ValueError("Okta origin is invalid") from exc


def _origin(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("Origin hostname is missing")
    port = parsed.port
    return f"https://{hostname.lower()}{f':{port}' if port not in {None, 443} else ''}"


def _next_link(value: str | None) -> str:
    if value is None or not 1 <= len(value) <= _MAX_LINK_BYTES or "\r" in value or "\n" in value:
        raise OktaRecoveryError
    matches: list[str] = []
    for match in re.finditer(r"<([^<>]+)>\s*((?:;[^,]*)?)", value):
        parameters = match.group(2)
        relations = re.findall(r";\s*rel\s*=\s*\"?([^\";,\s]+)\"?", parameters, re.I)
        if any(relation.casefold() == "next" for relation in relations):
            matches.append(match.group(1))
    if len(matches) != 1:
        raise OktaRecoveryError
    return matches[0]


def _safe_cursor_value(values: list[str]) -> bool:
    return (
        len(values) == 1
        and 1 <= len(values[0]) <= 1024
        and not any(ord(character) < 0x20 for character in values[0])
    )


def _event_uuid(value: object) -> str:
    if not isinstance(value, str):
        raise OktaRecoveryError
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise OktaRecoveryError from exc
    if str(parsed) != value.casefold():
        raise OktaRecoveryError
    return str(parsed)


def _published(value: object, *, now: datetime) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise OktaRecoveryError
    try:
        published = datetime.fromisoformat(value.replace("Z", "+00:00"))
        published = _aware_utc(published)
    except ValueError as exc:
        raise OktaRecoveryError from exc
    if published > now + timedelta(seconds=120):
        raise OktaRecoveryError
    return published


def _user_target(value: object) -> str:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        raise OktaRecoveryError
    if any(not isinstance(target, dict) for target in value):
        raise OktaRecoveryError
    users = [target for target in value if _is_user_target(target)]
    if len(users) != 1:
        raise OktaRecoveryError
    subject = users[0].get("id")
    if not isinstance(subject, str) or _OKTA_ID.fullmatch(subject) is None:
        raise OktaRecoveryError
    return subject


def _is_user_target(value: object) -> bool:
    return isinstance(value, dict) and value.get("type") == "User"


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _rfc3339(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")

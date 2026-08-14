from __future__ import annotations

import json
import math
import re
import secrets
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from itertools import islice
from threading import RLock
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import SecretStr

SSF_PUSH_METHOD = "urn:ietf:rfc:8935"
SSF_FINAL_VERSION = "1_0"
OAUTH_AUTHORIZATION_SCHEME = "urn:ietf:rfc:6749"

_JSON_MEDIA_TYPE = "application/json"
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RETRY_AFTER_SECONDS = 86_400
_RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})
_STREAM_ID = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_SUBJECT_ID = re.compile(r"^[A-Za-z0-9._~:@+-]{1,128}$")
_MEMBER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")


class SsfTransportError(RuntimeError):
    """Detail-free failure at the outbound SSF HTTP boundary."""


class SsfOperationError(RuntimeError):
    """Non-enumerating discovery or stream-operation failure."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        retry_after_seconds: int | None = None,
    ) -> None:
        if (
            retry_after_seconds is not None
            and not 0 <= retry_after_seconds <= _MAX_RETRY_AFTER_SECONDS
        ):
            raise ValueError("SSF retry-after value is invalid")
        super().__init__(message)
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True, slots=True)
class SsfHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = b""


class SsfHttpTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> SsfHttpResponse: ...


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


class UrllibSsfHttpTransport:
    """Bounded HTTPS transport restricted to administrator-approved origins.

    The caller owns credential acquisition. This transport never logs request headers or bodies and
    refuses redirects so an authorization header cannot be forwarded to a substituted endpoint.
    """

    def __init__(
        self,
        *,
        allowed_origins: Iterable[str],
        timeout_seconds: float = 3.0,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        max_request_bytes: int = _MAX_REQUEST_BYTES,
    ) -> None:
        origins = frozenset(_validated_origin(value) for value in allowed_origins)
        if not origins:
            raise ValueError("At least one trusted SSF origin is required")
        if not 0 < timeout_seconds <= 10:
            raise ValueError("SSF timeout must be greater than zero and no more than 10 seconds")
        if not 1 <= max_response_bytes <= _MAX_RESPONSE_BYTES:
            raise ValueError("SSF response limit must be between 1 byte and 256 KiB")
        if not 1 <= max_request_bytes <= _MAX_REQUEST_BYTES:
            raise ValueError("SSF request limit must be between 1 byte and 64 KiB")
        self._allowed_origins = origins
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_request_bytes = max_request_bytes
        self._opener = build_opener(_RejectRedirects())

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> SsfHttpResponse:
        if method not in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
            raise SsfTransportError("SSF HTTP method is not allowed")
        if _url_origin(url) not in self._allowed_origins:
            raise SsfTransportError("SSF endpoint is outside the trusted origin set")
        if body is not None and len(body) > self._max_request_bytes:
            raise SsfTransportError("SSF request exceeded the configured limit")
        if any("\r" in value or "\n" in value for value in headers.values()):
            raise SsfTransportError("SSF request header is invalid")
        request_headers = {**headers, "User-Agent": "northstar-polaris/0.1"}
        request = Request(  # noqa: S310 - exact HTTPS origins are allowlisted above.
            url,
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                final_url = cast(str, response.geturl())
                if final_url != url:
                    raise SsfTransportError("SSF redirects are prohibited")
                raw = self._read_bounded(response)
                status_code = cast(int, response.status)
                response_headers = {
                    str(name).casefold(): str(value) for name, value in response.headers.items()
                }
        except SsfTransportError:
            raise
        except (HTTPError, URLError, OSError, TimeoutError, ValueError) as exc:
            raise SsfTransportError("SSF HTTP request failed") from exc
        return SsfHttpResponse(
            status_code=status_code,
            headers=response_headers,
            body=raw,
        )

    def _read_bounded(self, response: Any) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) > self._max_response_bytes:
            raise SsfTransportError("SSF response exceeded the configured limit")
        raw = cast(bytes, response.read(self._max_response_bytes + 1))
        if len(raw) > self._max_response_bytes:
            raise SsfTransportError("SSF response exceeded the configured limit")
        return raw


@dataclass(frozen=True, slots=True)
class SsfTransmitterConfiguration:
    issuer: str
    jwks_uri: str
    delivery_methods_supported: tuple[str, ...]
    configuration_endpoint: str
    status_endpoint: str
    verification_endpoint: str
    add_subject_endpoint: str
    remove_subject_endpoint: str
    critical_subject_members: tuple[str, ...]
    authorization_scheme_urns: tuple[str, ...]
    default_subjects: str | None


class SsfStreamStatusValue(StrEnum):
    ENABLED = "enabled"
    PAUSED = "paused"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class SsfStreamStatus:
    stream_id: str
    status: SsfStreamStatusValue
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class SsfStreamConfiguration:
    stream_id: str
    issuer: str
    audience: str
    delivery_endpoint: str
    events_supported: tuple[str, ...] | None
    events_requested: tuple[str, ...]
    events_delivered: tuple[str, ...]
    description: str | None
    min_verification_interval: int | None
    inactivity_timeout: int | None


class SsfSubjectOperation(StrEnum):
    ADD = "ADD"
    REMOVE = "REMOVE"


@dataclass(frozen=True, slots=True)
class SsfSubjectOperationAccepted:
    """Non-enumerating acknowledgement, not proof that subject events will be delivered."""

    stream_id: str
    operation: SsfSubjectOperation


@dataclass(frozen=True, slots=True)
class PendingSsfVerification:
    """An accepted asynchronous request, not proof that a verification SET was received."""

    stream_id: str
    state: str


class SsfStreamOperationsClient:
    """Strict final-SSF discovery and Northstar stream-management contract.

    This local contract deliberately requires final version metadata, signed SET key discovery,
    push delivery, explicit no-default subjects, exact receiver/audience/event bindings, and the
    management endpoints needed to configure and verify a stream. It does not claim
    interoperability with a named provider.
    """

    def __init__(
        self,
        *,
        issuer: str,
        transport: SsfHttpTransport,
        authorization_provider: Callable[[], SecretStr],
        expected_audience: str,
        receiver_push_endpoint: str,
        requested_event_types: Iterable[str],
        subject_issuer: str,
        allowed_endpoint_origins: Iterable[str] | None = None,
        authorization_scheme_urn: str = OAUTH_AUTHORIZATION_SCHEME,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        _validated_https_endpoint(issuer)
        origin_values = (
            allowed_endpoint_origins
            if allowed_endpoint_origins is not None
            else (_url_origin(issuer),)
        )
        trusted_origins = frozenset(_validated_origin(value) for value in origin_values)
        if not trusted_origins:
            raise ValueError("At least one trusted SSF endpoint origin is required")
        if not _nonempty_string(authorization_scheme_urn, maximum=256):
            raise ValueError("SSF authorization scheme URN is invalid")
        if not _safe_text(expected_audience, maximum=512):
            raise ValueError("SSF expected audience is invalid")
        _validated_https_endpoint(receiver_push_endpoint)
        _validated_https_endpoint(subject_issuer)
        requested_events = _event_types(requested_event_types, field="requested events")
        self._issuer = issuer
        self._discovery_url = _ssf_discovery_url(issuer)
        self._transport = transport
        self._authorization_provider = authorization_provider
        self._trusted_origins = trusted_origins
        self._authorization_scheme_urn = authorization_scheme_urn
        self._expected_audience = expected_audience
        self._receiver_push_endpoint = receiver_push_endpoint
        self._requested_event_types = requested_events
        self._subject_issuer = subject_issuer
        self._clock = clock
        self._configuration: SsfTransmitterConfiguration | None = None
        self._lock = RLock()

    @property
    def discovery_url(self) -> str:
        return self._discovery_url

    def discover(self) -> SsfTransmitterConfiguration:
        with self._lock:
            self._configuration = None
        response = self._request(
            method="GET",
            url=self._discovery_url,
            headers={"Accept": _JSON_MEDIA_TYPE},
        )
        payload = _json_object_response(
            response,
            expected_status=200,
            require_no_store=False,
            now=self._now(),
        )
        try:
            configuration = self._validate_configuration(payload)
        except (TypeError, ValueError) as exc:
            raise SsfOperationError("SSF transmitter configuration is invalid") from exc
        with self._lock:
            self._configuration = configuration
        return configuration

    def read_status(self, stream_id: str) -> SsfStreamStatus:
        stream = _validated_stream_id(stream_id)
        configuration = self._current_configuration()
        response = self._request(
            method="GET",
            url=f"{configuration.status_endpoint}?stream_id={quote(stream, safe='')}",
            headers={
                "Accept": _JSON_MEDIA_TYPE,
                "Authorization": self._authorization_header(),
            },
        )
        payload = _json_object_response(
            response,
            expected_status=200,
            require_no_store=True,
            now=self._now(),
        )
        return self._validated_status(payload, expected_stream_id=stream)

    def create_stream(self, *, description: str | None = None) -> SsfStreamConfiguration:
        requested_description = _validated_description(description)
        body: dict[str, object] = {
            "delivery": {
                "method": SSF_PUSH_METHOD,
                "endpoint_url": self._receiver_push_endpoint,
            },
            "events_requested": list(self._requested_event_types),
        }
        if requested_description is not None:
            body["description"] = requested_description
        configuration = self._current_configuration()
        response = self._json_management_request(
            method="POST",
            url=configuration.configuration_endpoint,
            body=body,
        )
        payload = _json_object_response(
            response,
            expected_status=201,
            require_no_store=True,
            now=self._now(),
        )
        return self._validated_stream_configuration(payload)

    def read_configuration(self, stream_id: str) -> SsfStreamConfiguration:
        stream = _validated_stream_id(stream_id)
        configuration = self._current_configuration()
        response = self._request(
            method="GET",
            url=f"{configuration.configuration_endpoint}?stream_id={quote(stream, safe='')}",
            headers={
                "Accept": _JSON_MEDIA_TYPE,
                "Authorization": self._authorization_header(),
            },
        )
        payload = _json_object_response(
            response,
            expected_status=200,
            require_no_store=True,
            now=self._now(),
        )
        return self._validated_stream_configuration(payload, expected_stream_id=stream)

    def update_configuration(
        self,
        current: SsfStreamConfiguration,
        *,
        events_requested: Iterable[str] | None = None,
        description: str | None = None,
    ) -> SsfStreamConfiguration:
        self._validate_current_configuration(current)
        if events_requested is None and description is None:
            raise ValueError("SSF configuration update requires a property")
        body: dict[str, object] = {
            "stream_id": current.stream_id,
            "events_delivered": list(current.events_delivered),
        }
        expected_events = current.events_requested
        if events_requested is not None:
            expected_events = self._allowed_requested_events(events_requested)
            body["events_requested"] = list(expected_events)
        if description is not None:
            body["description"] = _validated_description(description)
        response = self._json_management_request(
            method="PATCH",
            url=self._current_configuration().configuration_endpoint,
            body=body,
        )
        payload = _json_object_response(
            response,
            expected_status=200,
            require_no_store=True,
            now=self._now(),
        )
        return self._validated_stream_configuration(
            payload,
            expected_stream_id=current.stream_id,
            expected_requested_events=expected_events,
        )

    def replace_configuration(
        self,
        current: SsfStreamConfiguration,
        *,
        events_requested: Iterable[str],
        description: str | None = None,
    ) -> SsfStreamConfiguration:
        self._validate_current_configuration(current)
        expected_events = self._allowed_requested_events(events_requested)
        body: dict[str, object] = {
            "stream_id": current.stream_id,
            "delivery": {
                "method": SSF_PUSH_METHOD,
                "endpoint_url": self._receiver_push_endpoint,
            },
            "events_requested": list(expected_events),
            "events_delivered": list(current.events_delivered),
        }
        requested_description = _validated_description(description)
        if requested_description is not None:
            body["description"] = requested_description
        response = self._json_management_request(
            method="PUT",
            url=self._current_configuration().configuration_endpoint,
            body=body,
        )
        payload = _json_object_response(
            response,
            expected_status=200,
            require_no_store=True,
            now=self._now(),
        )
        return self._validated_stream_configuration(
            payload,
            expected_stream_id=current.stream_id,
            expected_requested_events=expected_events,
        )

    def delete_stream(self, stream_id: str) -> None:
        stream = _validated_stream_id(stream_id)
        configuration = self._current_configuration()
        response = self._request(
            method="DELETE",
            url=f"{configuration.configuration_endpoint}?stream_id={quote(stream, safe='')}",
            headers={
                "Accept": _JSON_MEDIA_TYPE,
                "Authorization": self._authorization_header(),
            },
        )
        _require_empty_response(response, expected_status=204)

    def update_status(
        self,
        stream_id: str,
        status: SsfStreamStatusValue,
        *,
        reason: str | None = None,
    ) -> SsfStreamStatus:
        stream = _validated_stream_id(stream_id)
        if not isinstance(status, SsfStreamStatusValue):
            raise ValueError("SSF stream status is invalid")
        validated_reason = _validated_reason(reason)
        body: dict[str, object] = {"stream_id": stream, "status": status.value}
        if validated_reason is not None:
            body["reason"] = validated_reason
        response = self._json_management_request(
            method="POST",
            url=self._current_configuration().status_endpoint,
            body=body,
        )
        payload = _json_object_response(
            response,
            expected_status=200,
            require_no_store=True,
            now=self._now(),
        )
        updated = self._validated_status(payload, expected_stream_id=stream)
        if updated.status is not status or updated.reason != validated_reason:
            raise SsfOperationError("SSF stream status response is invalid")
        return updated

    def add_subject(self, stream_id: str, subject_id: str) -> SsfSubjectOperationAccepted:
        return self._mutate_subject(
            stream_id,
            subject_id,
            operation=SsfSubjectOperation.ADD,
        )

    def remove_subject(self, stream_id: str, subject_id: str) -> SsfSubjectOperationAccepted:
        return self._mutate_subject(
            stream_id,
            subject_id,
            operation=SsfSubjectOperation.REMOVE,
        )

    def trigger_verification(
        self,
        stream_id: str,
        *,
        state: str | None = None,
    ) -> PendingSsfVerification:
        stream = _validated_stream_id(stream_id)
        correlation_state = secrets.token_urlsafe(32) if state is None else state
        if not _nonempty_string(correlation_state, maximum=1024) or any(
            ord(char) < 0x20 for char in correlation_state
        ):
            raise ValueError("SSF verification state is invalid")
        configuration = self._current_configuration()
        body = json.dumps(
            {"stream_id": stream, "state": correlation_state},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        response = self._request(
            method="POST",
            url=configuration.verification_endpoint,
            headers={
                "Accept": _JSON_MEDIA_TYPE,
                "Authorization": self._authorization_header(),
                "Content-Type": _JSON_MEDIA_TYPE,
            },
            body=body,
        )
        if response.status_code != 204 or response.body or not _has_no_store(response.headers):
            raise SsfOperationError("SSF verification request failed")
        return PendingSsfVerification(stream_id=stream, state=correlation_state)

    def _mutate_subject(
        self,
        stream_id: str,
        subject_id: str,
        *,
        operation: SsfSubjectOperation,
    ) -> SsfSubjectOperationAccepted:
        stream = _validated_stream_id(stream_id)
        subject = _validated_subject_id(subject_id)
        configuration = self._current_configuration()
        endpoint = (
            configuration.add_subject_endpoint
            if operation is SsfSubjectOperation.ADD
            else configuration.remove_subject_endpoint
        )
        body: dict[str, object] = {
            "stream_id": stream,
            "subject": {
                "format": "iss_sub",
                "iss": self._subject_issuer,
                "sub": subject,
            },
        }
        if operation is SsfSubjectOperation.ADD:
            body["verified"] = False
        response = self._json_management_request(method="POST", url=endpoint, body=body)
        if operation is SsfSubjectOperation.ADD:
            _require_empty_response(response, expected_status=(200, 204))
        else:
            _require_empty_response(response, expected_status=204)
        return SsfSubjectOperationAccepted(stream_id=stream, operation=operation)

    def _json_management_request(
        self,
        *,
        method: str,
        url: str,
        body: Mapping[str, object],
    ) -> SsfHttpResponse:
        encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        return self._request(
            method=method,
            url=url,
            headers={
                "Accept": _JSON_MEDIA_TYPE,
                "Authorization": self._authorization_header(),
                "Content-Type": _JSON_MEDIA_TYPE,
            },
            body=encoded,
        )

    def _validated_status(
        self,
        payload: Mapping[str, object],
        *,
        expected_stream_id: str,
    ) -> SsfStreamStatus:
        try:
            returned_stream = payload.get("stream_id")
            if returned_stream != expected_stream_id:
                raise ValueError("SSF status stream ID did not match the request")
            raw_status = payload.get("status")
            if not isinstance(raw_status, str):
                raise ValueError("SSF stream status is invalid")
            status = SsfStreamStatusValue(raw_status)
            reason = _validated_reason(cast(str | None, payload.get("reason")))
            return SsfStreamStatus(
                stream_id=expected_stream_id,
                status=status,
                reason=reason,
            )
        except (TypeError, ValueError) as exc:
            raise SsfOperationError("SSF stream status response is invalid") from exc

    def _validated_stream_configuration(
        self,
        payload: Mapping[str, object],
        *,
        expected_stream_id: str | None = None,
        expected_requested_events: tuple[str, ...] | None = None,
    ) -> SsfStreamConfiguration:
        try:
            stream_id = _validated_stream_id(cast(str, payload.get("stream_id")))
            if expected_stream_id is not None and stream_id != expected_stream_id:
                raise ValueError("SSF configuration stream ID did not match the request")
            if payload.get("iss") != self._issuer:
                raise ValueError("SSF stream issuer did not match transmitter metadata")
            audience = _single_audience(payload.get("aud"))
            if audience != self._expected_audience:
                raise ValueError("SSF stream audience did not exactly match the receiver")
            delivery = payload.get("delivery")
            if not isinstance(delivery, Mapping) or delivery.get("method") != SSF_PUSH_METHOD:
                raise ValueError("SSF stream delivery method is invalid")
            if delivery.get("endpoint_url") != self._receiver_push_endpoint:
                raise ValueError("SSF stream delivery endpoint is invalid")
            events_supported = _optional_event_types(payload.get("events_supported"))
            returned_requested = _event_types(
                payload.get("events_requested"), field="requested events"
            )
            expected = expected_requested_events or self._requested_event_types
            if set(returned_requested) != set(expected):
                raise ValueError("SSF requested events do not match local policy")
            returned_delivered = _event_types(
                payload.get("events_delivered"), field="delivered events"
            )
            if set(returned_delivered) != set(expected):
                raise ValueError("SSF transmitter does not deliver every required event")
            if events_supported is not None and not set(expected).issubset(events_supported):
                raise ValueError("SSF requested events are not supported")
            description = _validated_description(cast(str | None, payload.get("description")))
            min_interval = _optional_seconds(
                payload.get("min_verification_interval"),
                field="minimum verification interval",
            )
            inactivity_timeout = _optional_seconds(
                payload.get("inactivity_timeout"),
                field="inactivity timeout",
            )
            return SsfStreamConfiguration(
                stream_id=stream_id,
                issuer=self._issuer,
                audience=self._expected_audience,
                delivery_endpoint=self._receiver_push_endpoint,
                events_supported=events_supported,
                events_requested=expected,
                events_delivered=expected,
                description=description,
                min_verification_interval=min_interval,
                inactivity_timeout=inactivity_timeout,
            )
        except (TypeError, ValueError) as exc:
            raise SsfOperationError("SSF stream configuration response is invalid") from exc

    def _validate_current_configuration(self, current: SsfStreamConfiguration) -> None:
        if (
            current.issuer != self._issuer
            or current.audience != self._expected_audience
            or current.delivery_endpoint != self._receiver_push_endpoint
            or current.events_requested != self._requested_event_types
            or current.events_delivered != current.events_requested
        ):
            raise ValueError("SSF current stream configuration is outside local policy")
        _validated_stream_id(current.stream_id)

    def _allowed_requested_events(self, values: Iterable[str]) -> tuple[str, ...]:
        requested = _event_types(values, field="requested events")
        if set(requested) != set(self._requested_event_types):
            raise ValueError("SSF requested events must exactly match local policy")
        return self._requested_event_types

    def _current_configuration(self) -> SsfTransmitterConfiguration:
        with self._lock:
            configuration = self._configuration
        if configuration is None:
            raise SsfOperationError("SSF transmitter configuration has not been discovered")
        return configuration

    def _authorization_header(self) -> str:
        try:
            header = self._authorization_provider().get_secret_value()
        except Exception as exc:
            raise SsfOperationError("SSF management authorization is unavailable") from exc
        if not _nonempty_string(header, maximum=8192) or "\r" in header or "\n" in header:
            raise SsfOperationError("SSF management authorization is invalid")
        return header

    def _request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> SsfHttpResponse:
        if _url_origin(url) not in self._trusted_origins:
            raise SsfOperationError("SSF endpoint is outside the trusted origin set")
        try:
            response = self._transport.request(
                method=method,
                url=url,
                headers=headers,
                body=body,
            )
        except Exception as exc:
            raise SsfOperationError("SSF operation is unavailable", retryable=True) from exc
        if len(response.body) > _MAX_RESPONSE_BYTES:
            raise SsfOperationError("SSF response exceeded the configured limit")
        return response

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise SsfOperationError("SSF operation clock is invalid")
        return now.astimezone(UTC)

    def _validate_configuration(
        self,
        payload: Mapping[str, object],
    ) -> SsfTransmitterConfiguration:
        if payload.get("spec_version") != SSF_FINAL_VERSION:
            raise ValueError("Final SSF version metadata is required")
        if payload.get("issuer") != self._issuer:
            raise ValueError("SSF metadata issuer did not exactly match configured issuer")
        jwks_uri = _required_endpoint(payload, "jwks_uri", self._trusted_origins)
        configuration_endpoint = _required_endpoint(
            payload, "configuration_endpoint", self._trusted_origins
        )
        status_endpoint = _required_endpoint(payload, "status_endpoint", self._trusted_origins)
        verification_endpoint = _required_endpoint(
            payload, "verification_endpoint", self._trusted_origins
        )
        add_subject_endpoint = _required_endpoint(
            payload, "add_subject_endpoint", self._trusted_origins
        )
        remove_subject_endpoint = _required_endpoint(
            payload, "remove_subject_endpoint", self._trusted_origins
        )
        delivery_methods = _unique_strings(
            payload.get("delivery_methods_supported"),
            field="delivery methods",
            maximum_items=16,
        )
        if SSF_PUSH_METHOD not in delivery_methods:
            raise ValueError("SSF push delivery is not supported")
        critical_members = _unique_strings(
            payload.get("critical_subject_members", ()),
            field="critical subject members",
            maximum_items=32,
            pattern=_MEMBER_NAME,
            allow_empty=True,
        )
        raw_schemes = payload.get("authorization_schemes")
        if not isinstance(raw_schemes, Sequence) or isinstance(raw_schemes, (str, bytes)):
            raise ValueError("SSF authorization schemes are invalid")
        if not 1 <= len(raw_schemes) <= 16:
            raise ValueError("SSF authorization schemes are invalid")
        schemes: list[str] = []
        for scheme in raw_schemes:
            if not isinstance(scheme, Mapping):
                raise ValueError("SSF authorization scheme is invalid")
            spec_urn = scheme.get("spec_urn")
            if not _nonempty_string(spec_urn, maximum=256) or spec_urn in schemes:
                raise ValueError("SSF authorization scheme is invalid")
            schemes.append(cast(str, spec_urn))
        if self._authorization_scheme_urn not in schemes:
            raise ValueError("Required SSF authorization scheme is not supported")
        default_subjects = payload.get("default_subjects")
        if default_subjects != "NONE":
            raise ValueError("SSF default-subject behavior must be explicit NONE")
        return SsfTransmitterConfiguration(
            issuer=self._issuer,
            jwks_uri=jwks_uri,
            delivery_methods_supported=delivery_methods,
            configuration_endpoint=configuration_endpoint,
            status_endpoint=status_endpoint,
            verification_endpoint=verification_endpoint,
            add_subject_endpoint=add_subject_endpoint,
            remove_subject_endpoint=remove_subject_endpoint,
            critical_subject_members=critical_members,
            authorization_scheme_urns=tuple(schemes),
            default_subjects=default_subjects,
        )


def _ssf_discovery_url(issuer: str) -> str:
    parsed = urlsplit(_validated_https_endpoint(issuer))
    issuer_path = parsed.path.rstrip("/")
    suffix = issuer_path if issuer_path else ""
    return f"{_url_origin(issuer)}/.well-known/ssf-configuration{suffix}"


def _json_object_response(
    response: SsfHttpResponse,
    *,
    expected_status: int,
    require_no_store: bool,
    now: datetime,
) -> Mapping[str, object]:
    if response.status_code != expected_status:
        retryable = response.status_code in _RETRYABLE_STATUS_CODES
        raise SsfOperationError(
            "SSF endpoint returned an unsuccessful status",
            retryable=retryable,
            retry_after_seconds=(
                _retry_after_seconds(response.headers, now=now) if retryable else None
            ),
        )
    content_type = _header(response.headers, "content-type")
    if (
        content_type is None
        or content_type.partition(";")[0].strip().casefold() != _JSON_MEDIA_TYPE
    ):
        raise SsfOperationError("SSF response media type is invalid")
    if require_no_store and not _has_no_store(response.headers):
        raise SsfOperationError("SSF response cache policy is invalid")
    try:
        payload: object = json.loads(response.body, object_pairs_hook=_reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SsfOperationError("SSF response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise SsfOperationError("SSF response was not a JSON object")
    return cast(Mapping[str, object], payload)


def _retry_after_seconds(headers: Mapping[str, str], *, now: datetime) -> int | None:
    raw = _header(headers, "retry-after")
    if raw is None or not raw or len(raw) > 128 or raw != raw.strip():
        return None
    if raw.isascii() and raw.isdigit():
        value = int(raw)
        return value if value <= _MAX_RETRY_AFTER_SECONDS else None
    try:
        retry_at = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None or retry_at.utcoffset() is None:
        return None
    delay = max(0, math.ceil((retry_at.astimezone(UTC) - now.astimezone(UTC)).total_seconds()))
    return delay if delay <= _MAX_RETRY_AFTER_SECONDS else None


def _require_empty_response(
    response: SsfHttpResponse,
    *,
    expected_status: int | tuple[int, ...],
) -> None:
    statuses = (expected_status,) if isinstance(expected_status, int) else expected_status
    if response.status_code not in statuses or response.body or not _has_no_store(response.headers):
        raise SsfOperationError("SSF management request failed")


def _reject_duplicate_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON member")
        result[name] = value
    return result


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.casefold()
    for header_name, value in headers.items():
        if header_name.casefold() == wanted:
            return value
    return None


def _has_no_store(headers: Mapping[str, str]) -> bool:
    cache_control = _header(headers, "cache-control")
    return cache_control is not None and "no-store" in {
        directive.partition("=")[0].strip().casefold() for directive in cache_control.split(",")
    }


def _required_endpoint(
    payload: Mapping[str, object],
    name: str,
    trusted_origins: frozenset[str],
) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise ValueError(f"SSF {name} is required")
    return _trusted_endpoint(value, trusted_origins)


def _trusted_endpoint(value: str, trusted_origins: frozenset[str]) -> str:
    _validated_https_endpoint(value)
    if _url_origin(value) not in trusted_origins:
        raise ValueError("SSF endpoint origin is not trusted")
    return value


def _unique_strings(
    value: object,
    *,
    field: str,
    maximum_items: int,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"SSF {field} are invalid")
    if len(value) > maximum_items or (not allow_empty and not value):
        raise ValueError(f"SSF {field} are invalid")
    result: list[str] = []
    for item in value:
        if (
            not _nonempty_string(item, maximum=512)
            or item in result
            or (pattern is not None and pattern.fullmatch(cast(str, item)) is None)
        ):
            raise ValueError(f"SSF {field} are invalid")
        result.append(cast(str, item))
    return tuple(result)


def _event_types(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        raise ValueError(f"SSF {field} are invalid")
    bounded = tuple(islice(value, 33))
    values = _unique_strings(bounded, field=field, maximum_items=32)
    if any(not _absolute_event_uri(item) for item in values):
        raise ValueError(f"SSF {field} are invalid")
    return values


def _optional_event_types(value: object) -> tuple[str, ...] | None:
    return None if value is None else _event_types(value, field="supported events")


def _absolute_event_uri(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme in {"https", "urn"} and not parsed.fragment


def _single_audience(value: object) -> str:
    if _safe_text(value, maximum=512):
        return cast(str, value)
    if (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes))
        and len(value) == 1
        and _safe_text(value[0], maximum=512)
    ):
        return cast(str, value[0])
    raise ValueError("SSF stream audience is invalid")


def _validated_subject_id(value: str) -> str:
    if _SUBJECT_ID.fullmatch(value) is None:
        raise ValueError("SSF subject ID is invalid")
    return value


def _validated_description(value: str | None) -> str | None:
    if value is None:
        return None
    if not _safe_text(value, maximum=512):
        raise ValueError("SSF stream description is invalid")
    return value


def _validated_reason(value: str | None) -> str | None:
    if value is None:
        return None
    if not _safe_text(value, maximum=512):
        raise ValueError("SSF stream status reason is invalid")
    return value


def _optional_seconds(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86400:
        raise ValueError(f"SSF {field} is invalid")
    return value


def _validated_stream_id(value: str) -> str:
    if not isinstance(value, str) or _STREAM_ID.fullmatch(value) is None:
        raise ValueError("SSF stream ID is invalid")
    return value


def _nonempty_string(value: object, *, maximum: int) -> bool:
    return isinstance(value, str) and value == value.strip() and 0 < len(value) <= maximum


def _safe_text(value: object, *, maximum: int) -> bool:
    return _nonempty_string(value, maximum=maximum) and not any(
        ord(character) < 0x20 for character in cast(str, value)
    )


def _validated_origin(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Trusted SSF origins must not include a path, query, or fragment")
    return _url_origin(origin)


def _validated_https_endpoint(url: str) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("SSF endpoint port is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("SSF endpoints must be canonical HTTPS URLs")
    return url


def _url_origin(url: str) -> str:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("SSF endpoint port is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("SSF request must use a canonical HTTPS URL")
    hostname = parsed.hostname.lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != 443:
        host = f"{host}:{port}"
    return f"https://{host}"

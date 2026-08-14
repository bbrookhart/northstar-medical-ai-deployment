from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Literal, Never, Protocol

from polaris.security.identity_signals import (
    IdentitySignalValidationError,
    SharedSignalsReceiver,
)
from polaris.services.audit import AuditLedger
from polaris.services.state import PolarisStateStore

SET_MEDIA_TYPE = "application/secevent+jwt"
JSON_MEDIA_TYPE = "application/json"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

SignalDeliveryErrorCode = Literal[
    "invalid_request",
    "invalid_key",
    "invalid_issuer",
    "invalid_audience",
    "invalid_state",
    "authentication_failed",
    "access_denied",
]


class SignalTransportAuthenticationError(Exception):
    """Non-enumerating failure to authenticate the HTTP SET transmitter."""


class SignalTransmitterAuthenticator(Protocol):
    def authenticate(self, authorization: str | None) -> str: ...

    def ready(self) -> bool: ...


class HashedBearerTransmitterAuthenticator:
    """Local test adapter; production should terminate approved workload auth at a trusted edge."""

    def __init__(self, *, transmitter_id: str, expected_token_sha256: str) -> None:
        if _IDENTIFIER.fullmatch(transmitter_id) is None:
            raise ValueError("Signal transmitter ID is invalid")
        if _SHA256.fullmatch(expected_token_sha256) is None:
            raise ValueError("Signal transmitter token hash must be lowercase SHA-256")
        self._transmitter_id = transmitter_id
        self._expected_token_sha256 = expected_token_sha256

    def authenticate(self, authorization: str | None) -> str:
        if authorization is None or not authorization.startswith("Bearer "):
            raise SignalTransportAuthenticationError
        token = authorization.removeprefix("Bearer ")
        if token != token.strip() or not 32 <= len(token) <= 2048:
            raise SignalTransportAuthenticationError
        presented = hashlib.sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(presented, self._expected_token_sha256):
            raise SignalTransportAuthenticationError
        return self._transmitter_id

    def ready(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class SignalDeliveryContext:
    stream_id: str
    transmitter_id: str


@dataclass(frozen=True, slots=True)
class SignalDeliveryError(Exception):
    error_code: SignalDeliveryErrorCode
    description: str


class SharedSignalsPushService:
    """Bounded RFC 8935-shaped push boundary for one configured SSF event stream."""

    def __init__(
        self,
        *,
        receiver: SharedSignalsReceiver,
        authenticator: SignalTransmitterAuthenticator,
        audit: AuditLedger,
        stream_id: str,
        max_body_bytes: int = 64 * 1024,
    ) -> None:
        if _IDENTIFIER.fullmatch(stream_id) is None:
            raise ValueError("Signal stream ID is invalid")
        if receiver.stream_id != stream_id:
            raise ValueError("Push delivery and receiver stream IDs must match")
        if receiver.state_store is not audit.state_store:
            raise ValueError("Push delivery and audit must share one state store")
        if not 1024 <= max_body_bytes <= 1024 * 1024:
            raise ValueError("Signal delivery body limit must be between 1 KiB and 1 MiB")
        self._receiver = receiver
        self._authenticator = authenticator
        self._audit = audit
        self._stream_id = stream_id
        self._max_body_bytes = max_body_bytes

    @property
    def max_body_bytes(self) -> int:
        return self._max_body_bytes

    @property
    def state_store(self) -> PolarisStateStore:
        return self._receiver.state_store

    def ready(self) -> bool:
        return self._authenticator.ready()

    def authenticate_request(
        self,
        *,
        stream_id: str,
        authorization: str | None,
        content_type: str | None,
        accept: str | None,
        correlation_id: str,
    ) -> SignalDeliveryContext:
        try:
            transmitter_id = self._authenticator.authenticate(authorization)
        except SignalTransportAuthenticationError as exc:
            self._audit_rejection(
                actor="identity-signal-endpoint",
                outcome="IDENTITY_SIGNAL_TRANSPORT_AUTHENTICATION_FAILED",
                correlation_id=correlation_id,
            )
            raise SignalDeliveryError(
                "authentication_failed",
                "SET transmitter authentication failed",
            ) from exc

        if stream_id != self._stream_id:
            self._audit_rejection(
                actor=transmitter_id,
                outcome="IDENTITY_SIGNAL_TRANSPORT_ACCESS_DENIED",
                correlation_id=correlation_id,
            )
            raise SignalDeliveryError(
                "access_denied",
                "SET transmitter is not authorized for this stream",
            )
        if content_type != SET_MEDIA_TYPE or accept != JSON_MEDIA_TYPE:
            self._audit_rejection(
                actor=transmitter_id,
                outcome="IDENTITY_SIGNAL_TRANSPORT_INVALID_REQUEST",
                correlation_id=correlation_id,
            )
            raise SignalDeliveryError(
                "invalid_request",
                "SET delivery headers are invalid",
            )
        return SignalDeliveryContext(stream_id=stream_id, transmitter_id=transmitter_id)

    def deliver(
        self,
        context: SignalDeliveryContext,
        body: bytes,
        *,
        correlation_id: str,
    ) -> None:
        if context.stream_id != self._stream_id:
            raise SignalDeliveryError("access_denied", "SET stream context is invalid")
        if not body or len(body) > self._max_body_bytes:
            self._invalid_body(context, correlation_id)
        try:
            set_token = body.decode("ascii")
        except UnicodeDecodeError as exc:
            self._invalid_body(context, correlation_id, cause=exc)
        if set_token != set_token.strip():
            self._invalid_body(context, correlation_id)
        try:
            self._receiver.accept(
                set_token,
                correlation_id=correlation_id,
                transmitter_id=context.transmitter_id,
            )
        except IdentitySignalValidationError as exc:
            raise SignalDeliveryError(exc.delivery_error_code, "SET validation failed") from exc

    def audit_payload_too_large(
        self,
        context: SignalDeliveryContext,
        *,
        correlation_id: str,
    ) -> None:
        self._audit_rejection(
            actor=context.transmitter_id,
            outcome="IDENTITY_SIGNAL_TRANSPORT_PAYLOAD_TOO_LARGE",
            correlation_id=correlation_id,
        )

    def _invalid_body(
        self,
        context: SignalDeliveryContext,
        correlation_id: str,
        *,
        cause: Exception | None = None,
    ) -> Never:
        self._audit_rejection(
            actor=context.transmitter_id,
            outcome="IDENTITY_SIGNAL_TRANSPORT_INVALID_REQUEST",
            correlation_id=correlation_id,
        )
        error = SignalDeliveryError("invalid_request", "SET request body is invalid")
        if cause is not None:
            raise error from cause
        raise error

    def _audit_rejection(self, *, actor: str, outcome: str, correlation_id: str) -> None:
        self._audit.append(
            actor=actor,
            event_type="identity.signal.transport",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata={"stream_id": self._stream_id},
        )

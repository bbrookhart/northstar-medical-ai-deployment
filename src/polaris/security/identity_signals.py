from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

import jwt
from jwt import InvalidTokenError
from jwt.exceptions import InvalidAudienceError, InvalidIssuerError, InvalidSignatureError
from pydantic import ValidationError

from polaris.domain import (
    IdentitySignalRecord,
    IdentitySignalTarget,
    IdentitySignalType,
    IdentityStreamCheckpoint,
    IdentityStreamStatusValue,
    IdentitySubjectState,
    IdentityTokenRevocation,
)
from polaris.errors import AuthenticationError, DependencyUnavailableError, PolarisError
from polaris.security.auth import JwksProvider
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.state import PolarisStateStore, StateIntegrityError, StateTransaction


class IdentitySignalValidationError(PolarisError):
    def __init__(
        self,
        delivery_error_code: Literal[
            "invalid_request",
            "invalid_key",
            "invalid_issuer",
            "invalid_audience",
            "invalid_state",
            "access_denied",
        ] = "invalid_request",
    ) -> None:
        self.delivery_error_code = delivery_error_code
        super().__init__(
            code="IDENTITY_SIGNAL_INVALID",
            message="Identity security signal is invalid",
            status_code=400,
        )


class IdentitySignalUnavailable(DependencyUnavailableError):
    def __init__(self) -> None:
        super().__init__("IDENTITY_SIGNAL_UNAVAILABLE")


class IdentityStreamVerificationHandler(Protocol):
    @property
    def stream_id(self) -> str: ...

    @property
    def state_store(self) -> PolarisStateStore: ...

    def confirm(
        self,
        transaction: StateTransaction,
        signal: IdentitySignalRecord,
    ) -> None: ...


class IdentityStreamStatusHandler(Protocol):
    @property
    def stream_id(self) -> str: ...

    @property
    def state_store(self) -> PolarisStateStore: ...

    def confirm(
        self,
        transaction: StateTransaction,
        signal: IdentitySignalRecord,
    ) -> None: ...


class IdentityStreamHealthProvider(Protocol):
    @property
    def stream_id(self) -> str: ...

    @property
    def state_store(self) -> PolarisStateStore: ...

    def assert_healthy(self) -> None: ...

    def ready(self) -> bool: ...


class StateBackedRevocationProvider:
    """Durable local enforcement view for verified identity security signals."""

    def __init__(
        self,
        state: PolarisStateStore,
        *,
        stream_id: str,
        max_staleness: timedelta,
        clock: Callable[[], datetime] = utc_now,
        stream_health: IdentityStreamHealthProvider | None = None,
    ) -> None:
        if max_staleness <= timedelta(0) or max_staleness > timedelta(days=1):
            raise ValueError("Identity signal staleness must be positive and at most one day")
        self._state = state
        self._stream_id = stream_id
        self._max_staleness = max_staleness
        self._clock = clock
        if stream_health is not None and (
            stream_health.state_store is not state or stream_health.stream_id != stream_id
        ):
            raise ValueError("Identity stream health provider must share state and stream")
        self._stream_health = stream_health

    @property
    def state_store(self) -> PolarisStateStore:
        return self._state

    @property
    def stream_id(self) -> str:
        return self._stream_id

    def record_stream_success(self, observed_at: datetime | None = None) -> None:
        observed = observed_at or self._clock()
        if observed.tzinfo is None or observed > self._clock() + timedelta(seconds=120):
            raise ValueError("Identity stream checkpoint time is invalid")
        with self._state.transaction() as transaction:
            current = transaction.get_identity_stream_checkpoint(self._stream_id)
            if current is None or observed > current.observed_at:
                transaction.save_identity_stream_checkpoint(
                    IdentityStreamCheckpoint(stream_id=self._stream_id, observed_at=observed)
                )

    def assert_not_revoked(
        self,
        *,
        token_id: str,
        subject: str,
        issued_at: datetime,
    ) -> None:
        now = self._clock()
        if issued_at.tzinfo is None:
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")
        if self._stream_health is not None:
            self._stream_health.assert_healthy()
        with self._state.transaction() as transaction:
            checkpoint = transaction.get_identity_stream_checkpoint(self._stream_id)
            if (
                checkpoint is None
                or not -timedelta(seconds=120)
                <= (now - checkpoint.observed_at)
                <= self._max_staleness
            ):
                raise IdentitySignalUnavailable
            token_revocation = transaction.get_identity_token_revocation(token_id)
            subject_state = transaction.get_identity_subject_state(subject)
        if token_revocation is not None or (
            subject_state is not None and issued_at <= subject_state.invalid_before
        ):
            raise AuthenticationError("AUTH_INVALID_TOKEN", "Bearer token is invalid")

    def ready(self) -> bool:
        if not self._state.verify_integrity():
            return False
        if self._stream_health is not None and not self._stream_health.ready():
            return False
        try:
            with self._state.transaction() as transaction:
                checkpoint = transaction.get_identity_stream_checkpoint(self._stream_id)
            if checkpoint is None:
                return False
            age = self._clock() - checkpoint.observed_at
            return -timedelta(seconds=120) <= age <= self._max_staleness
        except (StateIntegrityError, DependencyUnavailableError):
            return False


class SharedSignalsReceiver:
    """Strict local receiver for a bounded subset of final OpenID SSF/CAEP 1.0."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_provider: JwksProvider,
        revocations: StateBackedRevocationProvider,
        audit: AuditLedger,
        max_set_age: timedelta = timedelta(minutes=5),
        leeway_seconds: int = 30,
        clock: Callable[[], datetime] = utc_now,
        verification_handler: IdentityStreamVerificationHandler | None = None,
        status_handler: IdentityStreamStatusHandler | None = None,
    ) -> None:
        if not issuer.startswith("https://"):
            raise ValueError("Identity signal issuer must use https")
        if not audience:
            raise ValueError("Identity signal audience is required")
        if max_set_age <= timedelta(0) or max_set_age > timedelta(hours=1):
            raise ValueError("Maximum SET age must be positive and at most one hour")
        if not 0 <= leeway_seconds <= 120:
            raise ValueError("Identity signal leeway must be between 0 and 120 seconds")
        if revocations.state_store is not audit.state_store:
            raise ValueError("Identity signals and audit must share one transactional state store")
        if verification_handler is not None and (
            verification_handler.state_store is not revocations.state_store
            or verification_handler.stream_id != revocations.stream_id
        ):
            raise ValueError("Identity signal verification handler must share state and stream")
        if status_handler is not None and (
            status_handler.state_store is not revocations.state_store
            or status_handler.stream_id != revocations.stream_id
        ):
            raise ValueError("Identity signal status handler must share state and stream")
        self._issuer = issuer
        self._audience = audience
        self._jwks = jwks_provider
        self._revocations = revocations
        self._audit = audit
        self._max_set_age = max_set_age
        self._leeway = timedelta(seconds=leeway_seconds)
        self._clock = clock
        self._verification_handler = verification_handler
        self._status_handler = status_handler

    @property
    def stream_id(self) -> str:
        return self._revocations.stream_id

    @property
    def state_store(self) -> PolarisStateStore:
        return self._revocations.state_store

    def accept(
        self,
        set_token: str,
        *,
        correlation_id: str,
        transmitter_id: str = "direct-local-adapter",
    ) -> bool:
        try:
            signal = self._validate(set_token, transmitter_id=transmitter_id)
        except IdentitySignalValidationError:
            self._audit.append(
                actor=transmitter_id,
                event_type="identity.signal",
                outcome="IDENTITY_SIGNAL_REJECTED",
                correlation_id=correlation_id,
            )
            raise

        deferred_error: PolarisError | None = None
        applied = False
        try:
            with self._revocations.state_store.transaction() as transaction:
                existing = transaction.get_identity_signal(signal.event_id)
                if existing is not None and existing.payload_hash != signal.payload_hash:
                    self._audit.append(
                        actor=transmitter_id,
                        event_type="identity.signal",
                        outcome="IDENTITY_SIGNAL_REPLAY_COLLISION",
                        correlation_id=correlation_id,
                        metadata={"event_id": signal.event_id},
                    )
                    deferred_error = StateIntegrityError()
                elif existing is not None:
                    self._audit.append(
                        actor=transmitter_id,
                        event_type="identity.signal",
                        outcome="IDENTITY_SIGNAL_IDEMPOTENT_REPLAY",
                        correlation_id=correlation_id,
                        metadata={"event_id": signal.event_id},
                    )
                else:
                    transaction.save_identity_signal(signal)
                    self._apply_enforcement_state(transaction, signal)
                    self._revocations.record_stream_success(signal.received_at)
                    self._audit.append(
                        actor=transmitter_id,
                        event_type="identity.signal",
                        outcome="IDENTITY_SIGNAL_APPLIED",
                        correlation_id=correlation_id,
                        metadata={
                            "event_id": signal.event_id,
                            "event_type": signal.event_type.value,
                            "target": signal.target.value,
                        },
                    )
                    applied = True
        except IdentitySignalValidationError as exc:
            self._audit.append(
                actor=transmitter_id,
                event_type="identity.signal",
                outcome=(
                    "IDENTITY_SIGNAL_ACCESS_DENIED"
                    if exc.delivery_error_code == "access_denied"
                    else "IDENTITY_SIGNAL_INVALID_STATE"
                ),
                correlation_id=correlation_id,
            )
            raise
        if deferred_error is not None:
            raise deferred_error
        return applied

    def record_stream_success(self) -> None:
        self._revocations.record_stream_success()

    def _validate(self, set_token: str, *, transmitter_id: str) -> IdentitySignalRecord:
        try:
            header = jwt.get_unverified_header(set_token)
            if header.get("alg") != "RS256" or header.get("typ") != "secevent+jwt":
                raise IdentitySignalValidationError
            if any(name in header for name in ("jku", "x5u", "x5c")) or header.get("crit"):
                raise IdentitySignalValidationError
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise IdentitySignalValidationError
            claims = jwt.decode(
                set_token,
                self._jwks.signing_key(kid),
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "require": ["iss", "aud", "iat", "jti", "sub_id", "events"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
            if claims.get("aud") != self._audience or any(
                name in claims for name in ("sub", "exp", "nbf")
            ):
                raise IdentitySignalValidationError
            issued_at = _numeric_date(claims["iat"])
            now = self._clock()
            if issued_at - now > self._leeway or now - issued_at > self._max_set_age:
                raise IdentitySignalValidationError
            events = claims["events"]
            if not isinstance(events, dict) or len(events) != 1:
                raise IdentitySignalValidationError
            event_type_value, event = next(iter(events.items()))
            if not isinstance(event_type_value, str) or not isinstance(event, dict):
                raise IdentitySignalValidationError
            event_type = IdentitySignalType(event_type_value)
            event_time = _numeric_date(event.get("event_timestamp", claims["iat"]))
            if event_time - now > self._leeway:
                raise IdentitySignalValidationError
            (
                target,
                subject,
                token_id,
                verification_state_hash,
                stream_status,
                stream_status_reason_hash,
            ) = self._target(
                event_type,
                claims["sub_id"],
                event,
            )
            return IdentitySignalRecord(
                event_id=claims["jti"],
                stream_id=self._revocations.stream_id,
                transmitter_id=transmitter_id,
                issuer=claims["iss"],
                audience=claims["aud"],
                event_type=event_type,
                target=target,
                subject=subject,
                token_id=token_id,
                verification_state_hash=verification_state_hash,
                stream_status=stream_status,
                stream_status_reason_hash=stream_status_reason_hash,
                event_time=event_time,
                received_at=now,
                payload_hash=hashlib.sha256(set_token.encode()).hexdigest(),
            )
        except IdentitySignalValidationError:
            raise
        except AuthenticationError as exc:
            raise IdentitySignalValidationError("invalid_key") from exc
        except InvalidSignatureError as exc:
            raise IdentitySignalValidationError("invalid_key") from exc
        except InvalidIssuerError as exc:
            raise IdentitySignalValidationError("invalid_issuer") from exc
        except InvalidAudienceError as exc:
            raise IdentitySignalValidationError("invalid_audience") from exc
        except (InvalidTokenError, KeyError, TypeError, ValueError, ValidationError) as exc:
            raise IdentitySignalValidationError from exc

    def _target(
        self,
        event_type: IdentitySignalType,
        subject_data: object,
        event: dict[str, Any],
    ) -> tuple[
        IdentitySignalTarget,
        str | None,
        str | None,
        str | None,
        IdentityStreamStatusValue | None,
        str | None,
    ]:
        if not isinstance(subject_data, dict):
            raise IdentitySignalValidationError
        subject_format = subject_data.get("format")
        if event_type is IdentitySignalType.SESSION_REVOKED:
            if (
                subject_format != "iss_sub"
                or set(subject_data) != {"format", "iss", "sub"}
                or not _valid_session_revoked(event, subject_data)
            ):
                raise IdentitySignalValidationError
            return IdentitySignalTarget.SUBJECT, self._subject(subject_data), None, None, None, None

        if event_type is IdentitySignalType.CREDENTIAL_CHANGE:
            if (
                subject_format != "iss_sub"
                or set(subject_data) != {"format", "iss", "sub"}
                or not _valid_credential_change(event, subject_data)
            ):
                raise IdentitySignalValidationError
            return IdentitySignalTarget.SUBJECT, self._subject(subject_data), None, None, None, None

        if event_type is IdentitySignalType.STREAM_VERIFICATION:
            if (
                subject_format != "opaque"
                or set(subject_data) != {"format", "id"}
                or subject_data.get("id") != self._revocations.stream_id
                or not set(event).issubset({"state"})
            ):
                raise IdentitySignalValidationError("invalid_state")
            if "state" not in event:
                return IdentitySignalTarget.STREAM, None, None, None, None, None
            state = event["state"]
            if (
                not isinstance(state, str)
                or not 1 <= len(state) <= 1024
                or any(ord(character) < 0x20 for character in state)
            ):
                raise IdentitySignalValidationError("invalid_state")
            return (
                IdentitySignalTarget.STREAM,
                None,
                None,
                hashlib.sha256(state.encode()).hexdigest(),
                None,
                None,
            )

        if event_type is IdentitySignalType.STREAM_UPDATED:
            if (
                subject_format != "opaque"
                or set(subject_data) != {"format", "id"}
                or subject_data.get("id") != self._revocations.stream_id
                or not set(event).issubset({"status", "reason", "event_timestamp"})
            ):
                raise IdentitySignalValidationError("invalid_state")
            raw_status = event.get("status")
            if not isinstance(raw_status, str):
                raise IdentitySignalValidationError("invalid_state")
            try:
                stream_status = IdentityStreamStatusValue(raw_status)
            except ValueError as exc:
                raise IdentitySignalValidationError("invalid_state") from exc
            reason = event.get("reason")
            if reason is not None and (
                not isinstance(reason, str)
                or reason != reason.strip()
                or not 1 <= len(reason) <= 512
                or any(ord(character) < 0x20 for character in reason)
            ):
                raise IdentitySignalValidationError("invalid_state")
            return (
                IdentitySignalTarget.STREAM,
                None,
                None,
                None,
                stream_status,
                hashlib.sha256(reason.encode()).hexdigest() if reason is not None else None,
            )

        claims = event.get("claims")
        if not isinstance(claims, dict) or not claims:
            raise IdentitySignalValidationError
        if subject_format == "iss_sub" and set(subject_data) == {"format", "iss", "sub"}:
            return IdentitySignalTarget.SUBJECT, self._subject(subject_data), None, None, None, None
        if subject_format == "jwt_id" and set(subject_data) == {"format", "iss", "jti"}:
            if subject_data.get("iss") != self._issuer:
                raise IdentitySignalValidationError
            token_id = subject_data.get("jti")
            if not isinstance(token_id, str):
                raise IdentitySignalValidationError
            return IdentitySignalTarget.TOKEN, None, token_id, None, None, None
        raise IdentitySignalValidationError

    def _subject(self, subject_data: dict[str, Any]) -> str:
        if subject_data.get("iss") != self._issuer:
            raise IdentitySignalValidationError
        subject = subject_data.get("sub")
        if not isinstance(subject, str):
            raise IdentitySignalValidationError
        return subject

    def _apply_enforcement_state(
        self,
        transaction: StateTransaction,
        signal: IdentitySignalRecord,
    ) -> None:
        if signal.target is IdentitySignalTarget.STREAM:
            if signal.event_type is IdentitySignalType.STREAM_VERIFICATION:
                if self._verification_handler is None:
                    raise IdentitySignalValidationError("invalid_state")
                self._verification_handler.confirm(transaction, signal)
                return
            if (
                signal.event_type is not IdentitySignalType.STREAM_UPDATED
                or self._status_handler is None
            ):
                raise IdentitySignalValidationError("invalid_state")
            self._status_handler.confirm(transaction, signal)
            return
        if signal.target is IdentitySignalTarget.SUBJECT:
            if signal.subject is None:
                raise StateIntegrityError
            current = transaction.get_identity_subject_state(signal.subject)
            if current is None or signal.event_time > current.invalid_before:
                transaction.save_identity_subject_state(
                    IdentitySubjectState(
                        subject=signal.subject,
                        invalid_before=signal.event_time,
                        signal_id=signal.event_id,
                    )
                )
            return
        if signal.token_id is None:
            raise StateIntegrityError
        if transaction.get_identity_token_revocation(signal.token_id) is None:
            transaction.save_identity_token_revocation(
                IdentityTokenRevocation(
                    token_id=signal.token_id,
                    revoked_at=signal.event_time,
                    signal_id=signal.event_id,
                )
            )


def _numeric_date(value: object) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IdentitySignalValidationError
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise IdentitySignalValidationError from exc


def _valid_session_revoked(event: dict[str, Any], subject_data: dict[str, Any]) -> bool:
    allowed_fields = {
        "event_timestamp",
        "initiating_entity",
        "reason_admin",
        "reason_user",
        "subject",
    }
    return set(event).issubset(allowed_fields) and _valid_optional_caep_fields(
        event,
        subject_data,
    )


def _valid_credential_change(
    event: dict[str, Any],
    subject_data: dict[str, Any],
) -> bool:
    """Accept the bounded CAEP credential-change vocabulary used for revocation.

    Provider-specific descriptive fields are deliberately ignored after their type and size are
    checked. Any credential change invalidates locally issued subject sessions; Polaris does not
    attempt to infer a weaker action from a friendly name or reason string.
    """

    allowed_fields = {
        "change_type",
        "credential_type",
        "event_timestamp",
        "friendly_name",
        "initiating_entity",
        "reason_admin",
        "reason_user",
        "subject",
    }
    if not set(event).issubset(allowed_fields):
        return False
    credential_type = event.get("credential_type")
    change_type = event.get("change_type")
    if (
        not isinstance(credential_type, str)
        or not 1 <= len(credential_type) <= 64
        or not isinstance(change_type, str)
        or change_type not in {"create", "revoke", "update", "delete"}
    ):
        return False
    friendly_name = event.get("friendly_name")
    if friendly_name is not None and (
        not isinstance(friendly_name, str)
        or not 1 <= len(friendly_name) <= 128
        or any(ord(character) < 0x20 for character in friendly_name)
    ):
        return False
    return _valid_optional_caep_fields(event, subject_data)


def _valid_optional_caep_fields(
    event: dict[str, Any],
    subject_data: dict[str, Any],
) -> bool:
    if "subject" in event and event["subject"] != subject_data:
        return False
    for name in ("initiating_entity",):
        value = event.get(name)
        if value is not None and (
            not isinstance(value, str)
            or not 1 <= len(value) <= 64
            or any(ord(character) < 0x20 for character in value)
        ):
            return False
    for name in ("reason_admin", "reason_user"):
        value = event.get(name)
        if value is not None and not _valid_localized_reason(value):
            return False
    return True


def _valid_localized_reason(value: object) -> bool:
    if not isinstance(value, dict) or not 1 <= len(value) <= 10:
        return False
    return all(
        isinstance(language, str)
        and 1 <= len(language) <= 35
        and isinstance(reason, str)
        and 1 <= len(reason) <= 256
        and not any(ord(character) < 0x20 for character in reason)
        for language, reason in value.items()
    )

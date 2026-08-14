from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from polaris.domain import (
    IdentitySignalRecord,
    IdentitySignalTarget,
    IdentitySignalType,
    IdentityStreamUnsolicitedVerificationState,
    IdentityStreamVerification,
    IdentityStreamVerificationStatus,
)
from polaris.errors import DependencyUnavailableError
from polaris.security.identity_signals import IdentitySignalValidationError
from polaris.security.ssf_operations import PendingSsfVerification, SsfOperationError
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.state import PolarisStateStore, StateIntegrityError, StateTransaction


class SsfVerificationRequester(Protocol):
    def trigger_verification(
        self,
        stream_id: str,
        *,
        state: str | None = None,
    ) -> PendingSsfVerification: ...


class SsfStreamHealthStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    STALE = "STALE"


class SsfUnsolicitedVerificationPolicy(StrEnum):
    REJECT = "REJECT"
    ACCEPT_DELIVERY_ONLY = "ACCEPT_DELIVERY_ONLY"


@dataclass(frozen=True, slots=True)
class SsfStreamHealth:
    stream_id: str
    status: SsfStreamHealthStatus
    latest_verification_id: str | None
    last_verified_at: datetime | None
    pending_verification_id: str | None = None
    deadline_at: datetime | None = None


class SsfVerificationUnavailable(DependencyUnavailableError):
    def __init__(self) -> None:
        super().__init__("SSF_VERIFICATION_UNAVAILABLE")


class DurableSsfVerificationCoordinator:
    """Durable, single-use final-SSF verification request and receipt coordinator.

    The plaintext correlation state exists only long enough to send the request. Durable state keeps
    its SHA-256 digest, lifecycle timestamps, and the accepted verification signal ID.
    """

    def __init__(
        self,
        *,
        requester: SsfVerificationRequester,
        state: PolarisStateStore,
        audit: AuditLedger,
        stream_id: str,
        verification_timeout: timedelta = timedelta(seconds=30),
        max_verified_age: timedelta = timedelta(minutes=5),
        unsolicited_policy: SsfUnsolicitedVerificationPolicy = (
            SsfUnsolicitedVerificationPolicy.REJECT
        ),
        unsolicited_window: timedelta = timedelta(minutes=1),
        max_unsolicited_per_window: int = 5,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if audit.state_store is not state:
            raise ValueError("SSF verification and audit must share one transactional state store")
        if not timedelta(seconds=1) <= verification_timeout <= timedelta(minutes=10):
            raise ValueError("SSF verification timeout must be between 1 second and 10 minutes")
        if not timedelta(seconds=1) <= max_verified_age <= timedelta(days=1):
            raise ValueError("SSF verified age must be between 1 second and 1 day")
        if not isinstance(unsolicited_policy, SsfUnsolicitedVerificationPolicy):
            raise ValueError("SSF unsolicited verification policy is invalid")
        if not timedelta(seconds=1) <= unsolicited_window <= timedelta(hours=1):
            raise ValueError("SSF unsolicited verification window is invalid")
        if not 1 <= max_unsolicited_per_window <= 100:
            raise ValueError("SSF unsolicited verification limit must be between 1 and 100")
        self._requester = requester
        self._state = state
        self._audit = audit
        self._stream_id = stream_id
        self._verification_timeout = verification_timeout
        self._max_verified_age = max_verified_age
        self._unsolicited_policy = unsolicited_policy
        self._unsolicited_window = unsolicited_window
        self._max_unsolicited_per_window = max_unsolicited_per_window
        self._clock = clock

    @property
    def stream_id(self) -> str:
        return self._stream_id

    @property
    def state_store(self) -> PolarisStateStore:
        return self._state

    def request(self, *, correlation_id: str) -> IdentityStreamVerification:
        requested_at = self._now()
        plaintext_state = secrets.token_urlsafe(32)
        verification = IdentityStreamVerification(
            verification_id=f"VRF-{secrets.token_hex(16)}",
            stream_id=self._stream_id,
            state_hash=_state_hash(plaintext_state),
            status=IdentityStreamVerificationStatus.REQUESTING,
            requested_at=requested_at,
            deadline_at=requested_at + self._verification_timeout,
        )
        with self._state.transaction() as transaction:
            transaction.save_identity_stream_verification(verification)
            self._audit.append(
                actor="ssf-verification-coordinator",
                event_type="identity.stream.verify",
                outcome="SSF_VERIFICATION_REQUESTING",
                correlation_id=correlation_id,
                metadata={"verification_id": verification.verification_id},
            )

        try:
            pending = self._requester.trigger_verification(
                self._stream_id,
                state=plaintext_state,
            )
            if pending.stream_id != self._stream_id or not hmac.compare_digest(
                pending.state,
                plaintext_state,
            ):
                raise SsfOperationError("SSF verification response binding is invalid")
        except Exception as exc:
            current = self._record_dispatch_failure(verification, correlation_id=correlation_id)
            if current.status is IdentityStreamVerificationStatus.VERIFIED:
                return current
            raise SsfOperationError("SSF verification request failed") from exc

        result = self._record_dispatch_acceptance(verification, correlation_id=correlation_id)
        if result.status is IdentityStreamVerificationStatus.EXPIRED:
            raise SsfVerificationUnavailable
        return result

    def confirm(
        self,
        transaction: StateTransaction,
        signal: IdentitySignalRecord,
    ) -> None:
        if (
            signal.target is not IdentitySignalTarget.STREAM
            or signal.event_type is not IdentitySignalType.STREAM_VERIFICATION
            or signal.stream_id != self._stream_id
        ):
            raise IdentitySignalValidationError("invalid_state")
        if signal.verification_state_hash is None:
            self._accept_unsolicited(transaction, signal)
            return
        verification = transaction.get_identity_stream_verification_by_state(
            self._stream_id,
            signal.verification_state_hash,
        )
        now = self._now()
        if (
            verification is None
            or verification.status
            not in {
                IdentityStreamVerificationStatus.REQUESTING,
                IdentityStreamVerificationStatus.PENDING,
            }
            or now >= verification.deadline_at
        ):
            raise IdentitySignalValidationError("invalid_state")
        confirmed = _transition(
            verification,
            status=IdentityStreamVerificationStatus.VERIFIED,
            completed_at=now,
            signal_id=signal.event_id,
        )
        transaction.save_identity_stream_verification(confirmed)
        self._audit.append(
            actor=signal.transmitter_id,
            event_type="identity.stream.verify",
            outcome="SSF_VERIFICATION_CONFIRMED",
            correlation_id=signal.event_id,
            metadata={"verification_id": verification.verification_id},
        )

    def _accept_unsolicited(
        self,
        transaction: StateTransaction,
        signal: IdentitySignalRecord,
    ) -> None:
        if self._unsolicited_policy is SsfUnsolicitedVerificationPolicy.REJECT:
            raise IdentitySignalValidationError("access_denied")
        received_at = signal.received_at
        if received_at.tzinfo is None or received_at.utcoffset() is None:
            raise IdentitySignalValidationError("invalid_state")
        current = transaction.get_identity_stream_unsolicited_verification_state(self._stream_id)
        if current is None or received_at - current.window_started_at >= self._unsolicited_window:
            updated = IdentityStreamUnsolicitedVerificationState(
                stream_id=self._stream_id,
                window_started_at=received_at,
                accepted_count=1,
                last_received_at=received_at,
                last_signal_id=signal.event_id,
            )
        else:
            if (
                received_at < current.last_received_at
                or current.accepted_count >= self._max_unsolicited_per_window
            ):
                raise IdentitySignalValidationError("access_denied")
            updated = current.model_copy(
                update={
                    "accepted_count": current.accepted_count + 1,
                    "last_received_at": received_at,
                    "last_signal_id": signal.event_id,
                }
            )
        transaction.save_identity_stream_unsolicited_verification_state(updated)
        self._audit.append(
            actor=signal.transmitter_id,
            event_type="identity.stream.verify",
            outcome="SSF_UNSOLICITED_VERIFICATION_ACCEPTED",
            correlation_id=signal.event_id,
            metadata={
                "accepted_in_window": str(updated.accepted_count),
                "policy": self._unsolicited_policy.value,
            },
        )

    def health(self) -> SsfStreamHealth:
        now = self._now()
        with self._state.transaction() as transaction:
            latest = transaction.latest_identity_stream_verification(self._stream_id)
            if (
                latest is not None
                and latest.status
                in {
                    IdentityStreamVerificationStatus.REQUESTING,
                    IdentityStreamVerificationStatus.PENDING,
                }
                and now >= latest.deadline_at
            ):
                latest = self._expire(transaction, latest, now)
            verified = transaction.latest_verified_identity_stream_verification(self._stream_id)
        return self._health_from(latest=latest, verified=verified, now=now)

    def assert_healthy(self) -> None:
        if self.health().status is not SsfStreamHealthStatus.HEALTHY:
            raise SsfVerificationUnavailable

    def ready(self) -> bool:
        if not self._state.verify_integrity():
            return False
        try:
            return self.health().status is SsfStreamHealthStatus.HEALTHY
        except (DependencyUnavailableError, StateIntegrityError):
            return False

    def _record_dispatch_acceptance(
        self,
        verification: IdentityStreamVerification,
        *,
        correlation_id: str,
    ) -> IdentityStreamVerification:
        now = self._now()
        with self._state.transaction() as transaction:
            current = self._required(transaction, verification.verification_id)
            if current.status is IdentityStreamVerificationStatus.VERIFIED:
                accepted = _transition(current, accepted_at=now)
                transaction.save_identity_stream_verification(accepted)
                return accepted
            if current.status is not IdentityStreamVerificationStatus.REQUESTING:
                raise StateIntegrityError
            if now >= current.deadline_at:
                expired = _transition(
                    current,
                    status=IdentityStreamVerificationStatus.EXPIRED,
                    accepted_at=now,
                    completed_at=now,
                )
                transaction.save_identity_stream_verification(expired)
                self._audit_transition(
                    outcome="SSF_VERIFICATION_EXPIRED",
                    verification=expired,
                    correlation_id=correlation_id,
                )
                return expired
            pending = _transition(
                current,
                status=IdentityStreamVerificationStatus.PENDING,
                accepted_at=now,
            )
            transaction.save_identity_stream_verification(pending)
            self._audit_transition(
                outcome="SSF_VERIFICATION_PENDING",
                verification=pending,
                correlation_id=correlation_id,
            )
            return pending

    def _record_dispatch_failure(
        self,
        verification: IdentityStreamVerification,
        *,
        correlation_id: str,
    ) -> IdentityStreamVerification:
        now = self._now()
        with self._state.transaction() as transaction:
            current = self._required(transaction, verification.verification_id)
            if current.status is IdentityStreamVerificationStatus.VERIFIED:
                return current
            if current.status is not IdentityStreamVerificationStatus.REQUESTING:
                raise StateIntegrityError
            failed = _transition(
                current,
                status=IdentityStreamVerificationStatus.FAILED,
                completed_at=now,
            )
            transaction.save_identity_stream_verification(failed)
            self._audit_transition(
                outcome="SSF_VERIFICATION_DISPATCH_FAILED",
                verification=failed,
                correlation_id=correlation_id,
            )
            return failed

    def _expire(
        self,
        transaction: StateTransaction,
        verification: IdentityStreamVerification,
        now: datetime,
    ) -> IdentityStreamVerification:
        if verification.status is IdentityStreamVerificationStatus.REQUESTING:
            expired = _transition(
                verification,
                status=IdentityStreamVerificationStatus.FAILED,
                completed_at=now,
            )
            outcome = "SSF_VERIFICATION_DISPATCH_TIMED_OUT"
        else:
            expired = _transition(
                verification,
                status=IdentityStreamVerificationStatus.EXPIRED,
                completed_at=now,
            )
            outcome = "SSF_VERIFICATION_EXPIRED"
        transaction.save_identity_stream_verification(expired)
        self._audit_transition(
            outcome=outcome,
            verification=expired,
            correlation_id=verification.verification_id,
        )
        return expired

    def _health_from(
        self,
        *,
        latest: IdentityStreamVerification | None,
        verified: IdentityStreamVerification | None,
        now: datetime,
    ) -> SsfStreamHealth:
        verified_at = verified.completed_at if verified is not None else None
        verified_is_fresh = (
            verified_at is not None and timedelta(0) <= now - verified_at <= self._max_verified_age
        )
        if latest is None:
            status = SsfStreamHealthStatus.UNKNOWN
        elif latest.status in {
            IdentityStreamVerificationStatus.FAILED,
            IdentityStreamVerificationStatus.EXPIRED,
        }:
            status = SsfStreamHealthStatus.UNHEALTHY
        elif (
            latest.status
            in {
                IdentityStreamVerificationStatus.REQUESTING,
                IdentityStreamVerificationStatus.PENDING,
            }
            and not verified_is_fresh
        ):
            status = SsfStreamHealthStatus.PENDING
        elif verified_is_fresh:
            status = SsfStreamHealthStatus.HEALTHY
        else:
            status = SsfStreamHealthStatus.STALE
        pending = (
            latest
            if latest is not None
            and latest.status
            in {
                IdentityStreamVerificationStatus.REQUESTING,
                IdentityStreamVerificationStatus.PENDING,
            }
            else None
        )
        return SsfStreamHealth(
            stream_id=self._stream_id,
            status=status,
            latest_verification_id=latest.verification_id if latest is not None else None,
            last_verified_at=verified_at,
            pending_verification_id=pending.verification_id if pending is not None else None,
            deadline_at=pending.deadline_at if pending is not None else None,
        )

    def _audit_transition(
        self,
        *,
        outcome: str,
        verification: IdentityStreamVerification,
        correlation_id: str,
    ) -> None:
        self._audit.append(
            actor="ssf-verification-coordinator",
            event_type="identity.stream.verify",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata={"verification_id": verification.verification_id},
        )

    @staticmethod
    def _required(
        transaction: StateTransaction,
        verification_id: str,
    ) -> IdentityStreamVerification:
        verification = transaction.get_identity_stream_verification(verification_id)
        if verification is None:
            raise StateIntegrityError
        return verification

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise SsfVerificationUnavailable
        return now.astimezone(UTC)


def _state_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _transition(
    verification: IdentityStreamVerification,
    **updates: object,
) -> IdentityStreamVerification:
    payload = verification.model_dump()
    payload.update(updates)
    return IdentityStreamVerification.model_validate(payload)

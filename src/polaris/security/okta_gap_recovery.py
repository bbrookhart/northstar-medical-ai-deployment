from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from polaris.domain import (
    IdentityGapIncidentStatus,
    IdentityGapRecoveredEvent,
    IdentityGapRecoveryState,
    IdentityStreamStatusValue,
    IdentityStreamVerificationStatus,
    IdentitySubjectState,
)
from polaris.security.okta_recovery import (
    OktaRecoveredIdentityEvent,
    OktaSystemLogRecoveryClient,
)
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.state import StateIntegrityError, StateTransaction

_MAX_OBSERVATION_AGE = timedelta(minutes=15)
_MAX_VERIFICATION_AGE = timedelta(minutes=15)


class GapRecoveryPageOutcome(StrEnum):
    APPLIED = "APPLIED"
    CAUGHT_UP = "CAUGHT_UP"
    CURSOR_CONFLICT = "CURSOR_CONFLICT"


class GapRecoveryExitCriterion(StrEnum):
    """The runbook's exit conditions, each independently observable."""

    PAGES_APPLIED = "PAGES_APPLIED"
    CAUGHT_UP_CURSOR_COMMITTED = "CAUGHT_UP_CURSOR_COMMITTED"
    STREAM_STATUS_ENABLED = "STREAM_STATUS_ENABLED"
    FRESH_CORRELATED_VERIFICATION = "FRESH_CORRELATED_VERIFICATION"
    STATE_INTEGRITY = "STATE_INTEGRITY"
    AUDIT_INTEGRITY = "AUDIT_INTEGRITY"


@dataclass(frozen=True, slots=True)
class GapRecoveryPageResult:
    incident_id: str
    outcome: GapRecoveryPageOutcome
    cursor_sequence: int
    scanned: int
    applied: int
    duplicates: int
    ignored: int
    caught_up: bool


@dataclass(frozen=True, slots=True)
class GapRecoveryExitDecision:
    incident_id: str
    recovered: bool
    unmet: tuple[GapRecoveryExitCriterion, ...]


class OktaGapRecoveryController:
    """Durable application of the compensating Okta System Log feed.

    `OktaSystemLogRecoveryClient` validates and normalizes a provider page; this controller performs
    the transaction the gap-recovery runbook requires around it. Each page is applied exactly once
    against the cursor sequence its worker read, so a duplicate or stale worker cannot reapply a
    page or rewind the cursor.

    Two properties are deliberate. Recovered events may only *invalidate*: the System Log is not an
    authorization source, and no role, entitlement, or claim survives normalization. And applying a
    page never advances the SSF stream checkpoint — a compensating read cannot manufacture the
    delivery freshness that authentication depends on.
    """

    def __init__(
        self,
        *,
        client: OktaSystemLogRecoveryClient,
        stream_id: str,
        audit: AuditLedger,
        clock: Callable[[], datetime] = utc_now,
        max_observation_age: timedelta = _MAX_OBSERVATION_AGE,
        max_verification_age: timedelta = _MAX_VERIFICATION_AGE,
    ) -> None:
        if not stream_id:
            raise ValueError("Gap recovery requires a configured stream")
        if max_observation_age <= timedelta(0) or max_observation_age > timedelta(days=1):
            raise ValueError("Observation freshness must be positive and at most one day")
        if max_verification_age <= timedelta(0) or max_verification_age > timedelta(days=1):
            raise ValueError("Verification freshness must be positive and at most one day")
        self._client = client
        self._stream_id = stream_id
        self._audit = audit
        self._state = audit.state_store
        self._clock = clock
        self._max_observation_age = max_observation_age
        self._max_verification_age = max_verification_age

    @property
    def stream_id(self) -> str:
        return self._stream_id

    def open_incident(self, *, incident_id: str, correlation_id: str) -> IdentityGapRecoveryState:
        """Record a gap incident bound to the initial validated cursor.

        Authorization health is not changed here. The incident records that a gap is suspected; the
        existing checkpoint, status, and verification contracts keep failing closed on their own.
        """

        now = self._clock()
        incident = IdentityGapRecoveryState(
            incident_id=incident_id,
            stream_id=self._stream_id,
            status=IdentityGapIncidentStatus.OPEN,
            cursor_sequence=0,
            next_cursor_url=self._client.initial_cursor_url,
            opened_at=now,
            updated_at=now,
            pages_applied=0,
            events_applied=0,
            events_ignored=0,
            events_duplicate=0,
        )
        with self._state.transaction() as transaction:
            transaction.save_identity_gap_recovery_state(incident)
            self._audit.append(
                actor="okta-gap-recovery",
                event_type="identity.gap_recovery",
                outcome="GAP_INCIDENT_OPENED",
                correlation_id=correlation_id,
                metadata={"incident_id": incident_id, "stream_id": self._stream_id},
            )
        return incident

    def apply_next_page(self, *, incident_id: str, correlation_id: str) -> GapRecoveryPageResult:
        """Fetch one page outside the transaction, then apply it atomically or not at all."""

        with self._state.transaction() as transaction:
            incident = transaction.get_identity_gap_recovery_state(incident_id)
        if (
            incident is None
            or incident.stream_id != self._stream_id
            or incident.closed_at is not None
        ):
            raise StateIntegrityError
        expected_sequence = incident.cursor_sequence

        page = self._client.fetch_page(cursor_url=incident.next_cursor_url)
        now = self._clock()

        with self._state.transaction() as transaction:
            current = transaction.get_identity_gap_recovery_state(incident_id)
            if current is None or current.closed_at is not None:
                raise StateIntegrityError
            if current.cursor_sequence != expected_sequence:
                # Another worker committed this cursor first. Its page is already durable, so this
                # worker must discard its own copy rather than apply it a second time.
                self._audit.append(
                    actor="okta-gap-recovery",
                    event_type="identity.gap_recovery",
                    outcome="GAP_RECOVERY_CURSOR_CONFLICT",
                    correlation_id=correlation_id,
                    metadata={
                        "incident_id": incident_id,
                        "expected_sequence": str(expected_sequence),
                        "observed_sequence": str(current.cursor_sequence),
                    },
                )
                return GapRecoveryPageResult(
                    incident_id=incident_id,
                    outcome=GapRecoveryPageOutcome.CURSOR_CONFLICT,
                    cursor_sequence=current.cursor_sequence,
                    scanned=0,
                    applied=0,
                    duplicates=0,
                    ignored=0,
                    caught_up=False,
                )

            sequence = current.cursor_sequence + 1
            applied = 0
            duplicates = 0
            for event in page.events:
                if (
                    transaction.get_identity_gap_recovered_event(event.provider_event_id)
                    is not None
                ):
                    duplicates += 1
                    continue
                self._apply_event(
                    transaction,
                    event,
                    incident_id=incident_id,
                    cursor_sequence=sequence,
                    applied_at=now,
                )
                applied += 1

            updated = IdentityGapRecoveryState(
                incident_id=incident_id,
                stream_id=self._stream_id,
                status=IdentityGapIncidentStatus.RECOVERING,
                cursor_sequence=sequence,
                next_cursor_url=page.next_cursor_url,
                opened_at=current.opened_at,
                updated_at=now,
                pages_applied=sequence,
                events_applied=current.events_applied + applied,
                events_ignored=current.events_ignored + page.ignored_count,
                events_duplicate=current.events_duplicate + duplicates,
                last_page_at=now,
                caught_up_at=(
                    current.caught_up_at
                    if current.caught_up_at is not None
                    else (now if page.caught_up else None)
                ),
            )
            transaction.save_identity_gap_recovery_state(updated)
            self._audit.append(
                actor="okta-gap-recovery",
                event_type="identity.gap_recovery",
                outcome="GAP_RECOVERY_PAGE_APPLIED",
                correlation_id=correlation_id,
                metadata={
                    "incident_id": incident_id,
                    "cursor_sequence": str(sequence),
                    # The cursor itself is provider-opaque state, not telemetry. Only its digest
                    # leaves the state boundary so page progression stays auditable.
                    "cursor_digest": _digest(page.next_cursor_url),
                    "scanned": str(page.scanned_count),
                    "applied": str(applied),
                    "duplicates": str(duplicates),
                    "ignored": str(page.ignored_count),
                    "caught_up": str(page.caught_up).lower(),
                },
            )

        return GapRecoveryPageResult(
            incident_id=incident_id,
            outcome=(
                GapRecoveryPageOutcome.CAUGHT_UP
                if page.caught_up
                else GapRecoveryPageOutcome.APPLIED
            ),
            cursor_sequence=sequence,
            scanned=page.scanned_count,
            applied=applied,
            duplicates=duplicates,
            ignored=page.ignored_count,
            caught_up=page.caught_up,
        )

    def evaluate_exit(self, *, incident_id: str, correlation_id: str) -> GapRecoveryExitDecision:
        """Close the incident only when every runbook exit condition holds at once.

        An empty page, a status read, or a verification receipt is individually insufficient. The
        incident stays open and the decision names every condition that failed.
        """

        now = self._clock()
        integrity = self._state.verify_integrity()
        audit_intact = self._audit.verify()
        with self._state.transaction() as transaction:
            incident = transaction.get_identity_gap_recovery_state(incident_id)
            if (
                incident is None
                or incident.stream_id != self._stream_id
                or incident.closed_at is not None
            ):
                raise StateIntegrityError
            observed = transaction.get_identity_stream_observed_state(self._stream_id)
            verification = transaction.latest_verified_identity_stream_verification(self._stream_id)

            unmet: list[GapRecoveryExitCriterion] = []
            if incident.cursor_sequence < 1:
                unmet.append(GapRecoveryExitCriterion.PAGES_APPLIED)
            if incident.caught_up_at is None:
                unmet.append(GapRecoveryExitCriterion.CAUGHT_UP_CURSOR_COMMITTED)
            if (
                observed is None
                or observed.status is not IdentityStreamStatusValue.ENABLED
                or not _fresh(observed.observed_at, now, self._max_observation_age)
            ):
                unmet.append(GapRecoveryExitCriterion.STREAM_STATUS_ENABLED)
            if (
                verification is None
                or verification.status is not IdentityStreamVerificationStatus.VERIFIED
                or verification.completed_at is None
                # A receipt that predates the incident proves nothing about the gap.
                or verification.completed_at < incident.opened_at
                or not _fresh(verification.completed_at, now, self._max_verification_age)
            ):
                unmet.append(GapRecoveryExitCriterion.FRESH_CORRELATED_VERIFICATION)
            if not integrity:
                unmet.append(GapRecoveryExitCriterion.STATE_INTEGRITY)
            if not audit_intact:
                unmet.append(GapRecoveryExitCriterion.AUDIT_INTEGRITY)

            if unmet:
                self._audit.append(
                    actor="okta-gap-recovery",
                    event_type="identity.gap_recovery",
                    outcome="GAP_RECOVERY_EXIT_DENIED",
                    correlation_id=correlation_id,
                    metadata={
                        "incident_id": incident_id,
                        "unmet": ",".join(criterion.value for criterion in unmet),
                    },
                )
                return GapRecoveryExitDecision(
                    incident_id=incident_id,
                    recovered=False,
                    unmet=tuple(unmet),
                )

            transaction.save_identity_gap_recovery_state(
                incident.model_copy(
                    update={
                        "status": IdentityGapIncidentStatus.RECOVERED,
                        "updated_at": now,
                        "closed_at": now,
                    }
                )
            )
            self._audit.append(
                actor="okta-gap-recovery",
                event_type="identity.gap_recovery",
                outcome="GAP_RECOVERY_COMPLETED",
                correlation_id=correlation_id,
                metadata={
                    "incident_id": incident_id,
                    "pages_applied": str(incident.pages_applied),
                    "events_applied": str(incident.events_applied),
                },
            )
        return GapRecoveryExitDecision(incident_id=incident_id, recovered=True, unmet=())

    def _apply_event(
        self,
        transaction: StateTransaction,
        event: OktaRecoveredIdentityEvent,
        *,
        incident_id: str,
        cursor_sequence: int,
        applied_at: datetime,
    ) -> None:
        transaction.save_identity_gap_recovered_event(
            IdentityGapRecoveredEvent(
                provider_event_id=event.provider_event_id,
                incident_id=incident_id,
                stream_id=self._stream_id,
                provider_event_type=event.provider_event_type,
                signal_type=event.signal_type,
                subject=event.subject,
                effective_at=event.effective_at,
                applied_at=applied_at,
                cursor_sequence=cursor_sequence,
            )
        )
        current = transaction.get_identity_subject_state(event.subject)
        if current is None or event.effective_at > current.invalid_before:
            transaction.save_identity_subject_state(
                IdentitySubjectState(
                    subject=event.subject,
                    invalid_before=event.effective_at,
                    recovered_event_id=event.provider_event_id,
                )
            )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fresh(observed_at: datetime, now: datetime, maximum_age: timedelta) -> bool:
    return -timedelta(seconds=120) <= now - observed_at <= maximum_age

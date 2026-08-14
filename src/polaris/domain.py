from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")]
SafeText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


class PurposeOfUse(StrEnum):
    TREATMENT = "TREATMENT"
    HEALTHCARE_OPERATIONS = "HEALTHCARE_OPERATIONS"
    SECURITY = "SECURITY"
    TRAINING = "TRAINING"


class DataSensitivity(StrEnum):
    GENERAL = "GENERAL"
    SUD_PART2 = "SUD_PART2"


class ConsentDecision(StrEnum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class AuthorizationOperation(StrEnum):
    POLICY_QUERY = "policy.query"
    PATIENT_READ = "patient.read"
    ACTION_PROPOSE = "action.propose"
    ACTION_APPROVE = "action.approve"
    ACTION_EXECUTE = "action.execute"
    AUDIT_READ = "audit.read"


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: Identifier
    token_id: Identifier
    client_id: Identifier
    scopes: frozenset[Identifier]
    roles: frozenset[str]
    facilities: frozenset[Identifier]
    assigned_patients: frozenset[Identifier]


class IdentitySignalType(StrEnum):
    SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    TOKEN_CLAIMS_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"  # noqa: S105 - standardized event URI
    STREAM_VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification"
    STREAM_UPDATED = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"


class IdentityStreamStatusValue(StrEnum):
    ENABLED = "enabled"
    PAUSED = "paused"
    DISABLED = "disabled"


class IdentitySignalTarget(StrEnum):
    SUBJECT = "SUBJECT"
    TOKEN = "TOKEN"  # noqa: S105 - target discriminator, not a credential
    STREAM = "STREAM"


class IdentitySignalRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: Identifier
    stream_id: Identifier
    transmitter_id: Identifier
    issuer: str = Field(pattern=r"^https://[^?#]+$", max_length=200)
    audience: str = Field(min_length=1, max_length=200)
    event_type: IdentitySignalType
    target: IdentitySignalTarget
    subject: Identifier | None = None
    token_id: Identifier | None = None
    verification_state_hash: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    stream_status: IdentityStreamStatusValue | None = None
    stream_status_reason_hash: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )
    event_time: datetime
    received_at: datetime
    payload_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_target(self) -> IdentitySignalRecord:
        if self.target is IdentitySignalTarget.SUBJECT and (
            self.subject is None
            or self.token_id is not None
            or self.verification_state_hash is not None
            or self.stream_status is not None
            or self.stream_status_reason_hash is not None
        ):
            raise ValueError("Subject signals require only a subject")
        if self.target is IdentitySignalTarget.TOKEN and (
            self.token_id is None
            or self.subject is not None
            or self.verification_state_hash is not None
            or self.stream_status is not None
            or self.stream_status_reason_hash is not None
        ):
            raise ValueError("Token signals require only a token ID")
        if self.target is IdentitySignalTarget.STREAM:
            common_invalid = self.subject is not None or self.token_id is not None
            verification_invalid = self.event_type is IdentitySignalType.STREAM_VERIFICATION and (
                self.stream_status is not None or self.stream_status_reason_hash is not None
            )
            status_invalid = self.event_type is IdentitySignalType.STREAM_UPDATED and (
                self.verification_state_hash is not None
                or self.stream_status is None
                or (self.stream_status_reason_hash is not None and self.stream_status is None)
            )
            if (
                common_invalid
                or self.event_type
                not in {
                    IdentitySignalType.STREAM_VERIFICATION,
                    IdentitySignalType.STREAM_UPDATED,
                }
                or verification_invalid
                or status_invalid
            ):
                raise ValueError("Stream signal target is inconsistent with its event type")
        return self


class IdentitySubjectState(BaseModel):
    """Monotonic subject invalidation watermark attributed to exactly one source.

    A signed SET and a compensating provider-log record are both allowed to invalidate, but they are
    never conflated: `signal_id` names a verified security event token, `recovered_event_id` names a
    minimized System Log record applied during gap recovery.
    """

    model_config = ConfigDict(frozen=True)

    subject: Identifier
    invalid_before: datetime
    signal_id: Identifier | None = None
    recovered_event_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_source(self) -> IdentitySubjectState:
        if (self.signal_id is None) == (self.recovered_event_id is None):
            raise ValueError("Subject invalidation requires exactly one attributable source")
        return self


class IdentityTokenRevocation(BaseModel):
    model_config = ConfigDict(frozen=True)

    token_id: Identifier
    revoked_at: datetime
    signal_id: Identifier


class IdentityStreamCheckpoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    stream_id: Identifier
    observed_at: datetime


class IdentityStreamUnsolicitedVerificationState(BaseModel):
    """Durable fixed-window receipt state for transmitter-initiated verification events."""

    model_config = ConfigDict(frozen=True)

    stream_id: Identifier
    window_started_at: datetime
    accepted_count: int = Field(ge=1, le=100)
    last_received_at: datetime
    last_signal_id: Identifier

    @model_validator(mode="after")
    def validate_window(self) -> IdentityStreamUnsolicitedVerificationState:
        if (
            any(
                value.tzinfo is None or value.utcoffset() is None
                for value in (self.window_started_at, self.last_received_at)
            )
            or self.last_received_at < self.window_started_at
        ):
            raise ValueError("Unsolicited verification window is invalid")
        return self


class IdentityStreamVerificationStatus(StrEnum):
    REQUESTING = "REQUESTING"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class IdentityStreamVerification(BaseModel):
    """Durable single-use SSF verification challenge without the plaintext state value."""

    model_config = ConfigDict(frozen=True)

    verification_id: Identifier
    stream_id: Identifier
    state_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: IdentityStreamVerificationStatus
    requested_at: datetime
    deadline_at: datetime
    accepted_at: datetime | None = None
    completed_at: datetime | None = None
    signal_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> IdentityStreamVerification:
        timestamps = (
            self.requested_at,
            self.deadline_at,
            self.accepted_at,
            self.completed_at,
        )
        if any(
            value is not None and (value.tzinfo is None or value.utcoffset() is None)
            for value in timestamps
        ):
            raise ValueError("Verification timestamps must be timezone-aware")
        if self.deadline_at <= self.requested_at:
            raise ValueError("Verification deadline must follow its request")
        if self.accepted_at is not None and self.accepted_at < self.requested_at:
            raise ValueError("Verification acceptance precedes its request")
        if self.completed_at is not None and self.completed_at < self.requested_at:
            raise ValueError("Verification completion precedes its request")
        if self.status is IdentityStreamVerificationStatus.REQUESTING and any(
            value is not None for value in (self.accepted_at, self.completed_at, self.signal_id)
        ):
            raise ValueError("Requesting verification has no acceptance or completion")
        if self.status is IdentityStreamVerificationStatus.PENDING and (
            self.accepted_at is None or self.completed_at is not None or self.signal_id is not None
        ):
            raise ValueError("Pending verification requires only acceptance")
        if self.status is IdentityStreamVerificationStatus.VERIFIED and (
            self.completed_at is None or self.signal_id is None
        ):
            raise ValueError("Verified stream requires a completion and signal")
        if self.status is IdentityStreamVerificationStatus.FAILED and (
            self.accepted_at is not None or self.completed_at is None or self.signal_id is not None
        ):
            raise ValueError("Failed verification requires only completion")
        if self.status is IdentityStreamVerificationStatus.EXPIRED and (
            self.accepted_at is None
            or self.completed_at is None
            or self.signal_id is not None
            or self.completed_at < self.deadline_at
        ):
            raise ValueError("Expired verification requires accepted timeout completion")
        return self


class IdentityStreamStatusOperationStatus(StrEnum):
    REQUESTING = "REQUESTING"
    CONFIRMED = "CONFIRMED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class IdentityStreamStatusOperation(BaseModel):
    """Durable desired stream status without retaining an optional plaintext reason."""

    model_config = ConfigDict(frozen=True)

    operation_id: Identifier
    stream_id: Identifier
    desired_status: IdentityStreamStatusValue
    status: IdentityStreamStatusOperationStatus
    reason_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    requested_at: datetime
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> IdentityStreamStatusOperation:
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("Stream status operation time must be timezone-aware")
        if self.completed_at is not None and (
            self.completed_at.tzinfo is None
            or self.completed_at.utcoffset() is None
            or self.completed_at < self.requested_at
        ):
            raise ValueError("Stream status completion time is invalid")
        if (self.status is IdentityStreamStatusOperationStatus.REQUESTING) != (
            self.completed_at is None
        ):
            raise ValueError("Stream status operation lifecycle is inconsistent")
        return self


class IdentityStreamStatusReconciliationStatus(StrEnum):
    REQUESTING = "REQUESTING"
    OBSERVED = "OBSERVED"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"


class IdentityStreamStatusReconciliationFailure(StrEnum):
    NON_RETRYABLE = "NON_RETRYABLE"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    RETRY_BUDGET_EXHAUSTED = "RETRY_BUDGET_EXHAUSTED"


class IdentityStreamStatusReconciliation(BaseModel):
    """Durable status-read attempt used to resolve drift or an ambiguous status write."""

    model_config = ConfigDict(frozen=True)

    reconciliation_id: Identifier
    stream_id: Identifier
    operation_id: Identifier
    status: IdentityStreamStatusReconciliationStatus
    requested_at: datetime
    completed_at: datetime | None = None
    attempts: int = Field(ge=0, le=5)
    observed_status: IdentityStreamStatusValue | None = None
    observed_reason_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    failure: IdentityStreamStatusReconciliationFailure | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> IdentityStreamStatusReconciliation:
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("Stream reconciliation request time must be timezone-aware")
        if self.completed_at is not None and (
            self.completed_at.tzinfo is None
            or self.completed_at.utcoffset() is None
            or self.completed_at < self.requested_at
        ):
            raise ValueError("Stream reconciliation completion time is invalid")
        if self.status is IdentityStreamStatusReconciliationStatus.REQUESTING:
            if (
                self.completed_at is not None
                or self.attempts != 0
                or self.observed_status is not None
                or self.observed_reason_hash is not None
                or self.failure is not None
            ):
                raise ValueError("Requesting reconciliation has no result")
            return self
        if self.completed_at is None or self.attempts == 0:
            raise ValueError("Completed reconciliation requires attempts and completion")
        if self.status is IdentityStreamStatusReconciliationStatus.FAILED:
            if (
                self.failure is None
                or self.observed_status is not None
                or self.observed_reason_hash is not None
            ):
                raise ValueError("Failed reconciliation requires only a failure code")
            return self
        if self.observed_status is None or self.failure is not None:
            raise ValueError("Observed reconciliation requires only an observed status")
        return self


class IdentityStreamRecoveryOutcome(StrEnum):
    RECOVERED = "RECOVERED"
    DRIFTED = "DRIFTED"
    FAILED = "FAILED"
    UNCONFIGURED = "UNCONFIGURED"
    SUPERSEDED = "SUPERSEDED"


class IdentityStreamRecoveryAlertLevel(StrEnum):
    CLEAR = "CLEAR"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class IdentityStreamRecoverySchedule(BaseModel):
    """Restart-safe cadence, lease, and minimized alert state for status recovery."""

    model_config = ConfigDict(frozen=True)

    stream_id: Identifier
    sequence: int = Field(ge=1, le=2_147_483_647)
    active_run_id: Identifier | None = None
    active_started_at: datetime | None = None
    lease_expires_at: datetime | None = None
    last_run_id: Identifier | None = None
    last_completed_at: datetime | None = None
    next_due_at: datetime
    consecutive_failures: int = Field(ge=0, le=100)
    last_outcome: IdentityStreamRecoveryOutcome | None = None
    last_reconciliation_id: Identifier | None = None
    alert_level: IdentityStreamRecoveryAlertLevel

    @model_validator(mode="after")
    def validate_lifecycle(self) -> IdentityStreamRecoverySchedule:
        timestamps = (
            self.active_started_at,
            self.lease_expires_at,
            self.last_completed_at,
            self.next_due_at,
        )
        if any(
            value is not None and (value.tzinfo is None or value.utcoffset() is None)
            for value in timestamps
        ):
            raise ValueError("Stream recovery timestamps must be timezone-aware")
        active = (self.active_run_id, self.active_started_at, self.lease_expires_at)
        if any(value is None for value in active) != all(value is None for value in active):
            raise ValueError("Stream recovery lease is incomplete")
        if (
            self.active_started_at is not None
            and self.lease_expires_at is not None
            and self.lease_expires_at <= self.active_started_at
        ):
            raise ValueError("Stream recovery lease interval is invalid")
        history = (self.last_run_id, self.last_completed_at, self.last_outcome)
        if any(value is None for value in history) != all(value is None for value in history):
            raise ValueError("Stream recovery history is incomplete")
        if self.last_completed_at is None:
            if (
                self.consecutive_failures != 0
                or self.last_reconciliation_id is not None
                or self.alert_level is not IdentityStreamRecoveryAlertLevel.CLEAR
            ):
                raise ValueError("Initial stream recovery state must be clear")
        else:
            if self.next_due_at < self.last_completed_at:
                raise ValueError("Stream recovery next due time is invalid")
            if self.last_outcome is IdentityStreamRecoveryOutcome.RECOVERED:
                if (
                    self.consecutive_failures != 0
                    or self.alert_level is not IdentityStreamRecoveryAlertLevel.CLEAR
                    or self.last_reconciliation_id is None
                ):
                    raise ValueError("Recovered stream recovery state is inconsistent")
            elif self.consecutive_failures == 0 or (
                self.alert_level is IdentityStreamRecoveryAlertLevel.CLEAR
            ):
                raise ValueError("Unresolved stream recovery state must alert")
            if (
                self.last_outcome
                in {
                    IdentityStreamRecoveryOutcome.DRIFTED,
                    IdentityStreamRecoveryOutcome.SUPERSEDED,
                }
                and self.last_reconciliation_id is None
            ):
                raise ValueError("Observed stream recovery outcome requires reconciliation")
            if (
                self.last_outcome
                in {
                    IdentityStreamRecoveryOutcome.FAILED,
                    IdentityStreamRecoveryOutcome.UNCONFIGURED,
                }
                and self.last_reconciliation_id is not None
            ):
                raise ValueError("Unobserved stream recovery outcome cannot bind reconciliation")
        if (
            self.active_started_at is not None
            and self.last_completed_at is not None
            and self.active_started_at < self.last_completed_at
        ):
            raise ValueError("Stream recovery run cannot predate prior completion")
        return self


class IdentityStreamObservedState(BaseModel):
    """Latest monotonic observation, attributed to one response or signed signal."""

    model_config = ConfigDict(frozen=True)

    stream_id: Identifier
    status: IdentityStreamStatusValue
    reason_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime
    signal_id: Identifier | None = None
    operation_id: Identifier | None = None
    reconciliation_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_source(self) -> IdentityStreamObservedState:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("Stream status observation time must be timezone-aware")
        if (
            sum(
                value is not None
                for value in (self.signal_id, self.operation_id, self.reconciliation_id)
            )
            != 1
        ):
            raise ValueError("Stream status observation requires exactly one source")
        return self


class IdentityGapIncidentStatus(StrEnum):
    OPEN = "OPEN"
    RECOVERING = "RECOVERING"
    RECOVERED = "RECOVERED"
    ABANDONED = "ABANDONED"


INVALIDATING_IDENTITY_SIGNAL_TYPES: frozenset[IdentitySignalType] = frozenset(
    {IdentitySignalType.SESSION_REVOKED, IdentitySignalType.CREDENTIAL_CHANGE}
)


class IdentityGapRecoveryState(BaseModel):
    """Durable per-incident cursor and application counters for compensating gap recovery.

    ``cursor_sequence`` is the compare-and-swap token. A page may only be applied against the
    sequence the worker read, and every commit advances it by exactly one, so a duplicate or stale
    worker cannot apply the same page twice or rewind the cursor.
    """

    model_config = ConfigDict(frozen=True)

    incident_id: Identifier
    stream_id: Identifier
    status: IdentityGapIncidentStatus
    cursor_sequence: int = Field(ge=0, le=2_147_483_647)
    next_cursor_url: str = Field(min_length=1, max_length=4096)
    opened_at: datetime
    updated_at: datetime
    pages_applied: int = Field(ge=0, le=1_000_000)
    events_applied: int = Field(ge=0, le=10_000_000)
    events_ignored: int = Field(ge=0, le=10_000_000)
    events_duplicate: int = Field(ge=0, le=10_000_000)
    last_page_at: datetime | None = None
    caught_up_at: datetime | None = None
    closed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> IdentityGapRecoveryState:
        timestamps = (
            self.opened_at,
            self.updated_at,
            self.last_page_at,
            self.caught_up_at,
            self.closed_at,
        )
        if any(
            value is not None and (value.tzinfo is None or value.utcoffset() is None)
            for value in timestamps
        ):
            raise ValueError("Gap recovery timestamps must be timezone-aware")
        if self.updated_at < self.opened_at:
            raise ValueError("Gap recovery update precedes its incident")
        for value in (self.last_page_at, self.caught_up_at, self.closed_at):
            if value is not None and not self.opened_at <= value <= self.updated_at:
                raise ValueError("Gap recovery lifecycle time is outside the incident")
        if self.cursor_sequence == 0 and (
            self.pages_applied != 0
            or self.events_applied != 0
            or self.events_ignored != 0
            or self.events_duplicate != 0
            or self.last_page_at is not None
            or self.caught_up_at is not None
        ):
            raise ValueError("An unstarted gap recovery incident has applied nothing")
        if self.cursor_sequence != self.pages_applied:
            raise ValueError("Gap recovery cursor sequence must count applied pages")
        if self.last_page_at is None and self.cursor_sequence != 0:
            raise ValueError("Applied gap recovery pages require an application time")
        if self.status is IdentityGapIncidentStatus.OPEN and self.cursor_sequence != 0:
            raise ValueError("An open gap recovery incident has applied no page")
        if self.status is IdentityGapIncidentStatus.RECOVERED and (
            self.caught_up_at is None or self.closed_at is None
        ):
            raise ValueError("A recovered gap incident must have caught up and closed")
        if self.status is IdentityGapIncidentStatus.ABANDONED and self.closed_at is None:
            raise ValueError("An abandoned gap incident must be closed")
        if (
            self.status in {IdentityGapIncidentStatus.OPEN, IdentityGapIncidentStatus.RECOVERING}
            and self.closed_at is not None
        ):
            raise ValueError("An unresolved gap incident is not closed")
        return self


class IdentityGapRecoveredEvent(BaseModel):
    """One minimized provider record applied exactly once during compensating gap recovery.

    Recovered events may only invalidate. The provider feed is not an authorization source, so no
    role, entitlement, or claim value survives normalization into this record.
    """

    model_config = ConfigDict(frozen=True)

    provider_event_id: Identifier
    incident_id: Identifier
    stream_id: Identifier
    provider_event_type: str = Field(min_length=1, max_length=128)
    signal_type: IdentitySignalType
    subject: Identifier
    effective_at: datetime
    applied_at: datetime
    cursor_sequence: int = Field(ge=1, le=2_147_483_647)

    @model_validator(mode="after")
    def validate_invalidating_event(self) -> IdentityGapRecoveredEvent:
        if any(
            value.tzinfo is None or value.utcoffset() is None
            for value in (self.effective_at, self.applied_at)
        ):
            raise ValueError("Recovered event timestamps must be timezone-aware")
        if self.signal_type not in INVALIDATING_IDENTITY_SIGNAL_TYPES:
            raise ValueError("Recovered provider events may only invalidate")
        return self


class AuthorizationRequest(BaseModel):
    """Immutable, payload-free input contract for every deterministic policy decision."""

    model_config = ConfigDict(frozen=True)

    principal: Principal
    purpose: PurposeOfUse
    operation: AuthorizationOperation
    patient_id: Identifier | None = None
    facility_id: Identifier | None = None
    sensitivities: frozenset[DataSensitivity] = frozenset()
    consent_decision: ConsentDecision | None = None
    requester_subject: Identifier | None = None
    action_patient_id: Identifier | None = None
    action_facility_id: Identifier | None = None


class PolicyDocument(BaseModel):
    model_config = ConfigDict(frozen=True)

    document_id: Identifier
    title: SafeText
    version: Identifier
    classification: Literal["INTERNAL", "CONFIDENTIAL"]
    allowed_roles: frozenset[str]
    approved: bool
    content: str = Field(min_length=1, max_length=10_000)
    checksum: str = Field(pattern=r"^[a-f0-9]{64}$")


class Citation(BaseModel):
    document_id: Identifier
    title: SafeText
    version: Identifier
    excerpt: SafeText


class PolicyQueryRequest(BaseModel):
    question: SafeText


class PolicyQueryResponse(BaseModel):
    answer: str
    citations: list[Citation]
    abstained: bool
    normalized_input: bool


class SyntheticPatient(BaseModel):
    model_config = ConfigDict(frozen=True)

    patient_id: Identifier
    display_name: SafeText
    facility_id: Identifier
    preferred_language: Identifier
    sensitivities: frozenset[DataSensitivity]
    consent_decision: ConsentDecision
    recent_encounter_date: date
    care_coordination_flags: tuple[str, ...]


class PatientSummary(BaseModel):
    patient_id: Identifier
    display_name: SafeText
    facility_id: Identifier
    preferred_language: Identifier
    recent_encounter_date: date
    care_coordination_flags: tuple[str, ...]
    synthetic_data: Literal[True] = True


class FollowUpAction(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_type: Literal["administrative_follow_up"] = "administrative_follow_up"
    patient_id: Identifier
    facility_id: Identifier
    queue: Literal["care_coordination"] = "care_coordination"
    due_date: date
    summary: SafeText


class ActionProposalRequest(BaseModel):
    action: FollowUpAction


class ProposalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


class ActionProposal(BaseModel):
    proposal_id: Identifier
    action: FollowUpAction
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    requester: Principal
    purpose: PurposeOfUse
    status: ProposalStatus
    created_at: datetime
    expires_at: datetime


class ActionProposalView(BaseModel):
    proposal_id: Identifier
    action: FollowUpAction
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: ProposalStatus
    created_at: datetime
    expires_at: datetime


class ApprovalDecision(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class ActionApprovalRequest(BaseModel):
    decision: ApprovalDecision
    expected_action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    comment: Annotated[str, StringConstraints(strip_whitespace=True, max_length=300)] = ""


class ApprovalReceipt(BaseModel):
    approval_id: Identifier
    proposal_id: Identifier
    decision: ApprovalDecision
    approver_subject: Identifier
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_at: datetime
    expires_at: datetime
    policy_version: Identifier
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


class ActionExecutionRequest(BaseModel):
    expected_action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ActionExecutionResult(BaseModel):
    execution_id: Identifier
    proposal_id: Identifier
    task_id: Identifier
    executed_at: datetime
    idempotent_replay: bool


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True)

    allowed: bool
    code: Identifier
    policy_version: Identifier
    obligations: frozenset[Identifier] = frozenset()


class AuditEvent(BaseModel):
    sequence: int = Field(ge=1)
    occurred_at: datetime
    actor: Identifier
    event_type: Identifier
    outcome: Identifier
    correlation_id: Identifier
    metadata: dict[str, str]
    previous_hash: str = Field(pattern=r"^(GENESIS|[a-f0-9]{64})$")
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class AuditVerification(BaseModel):
    valid: bool
    event_count: int = Field(ge=0)

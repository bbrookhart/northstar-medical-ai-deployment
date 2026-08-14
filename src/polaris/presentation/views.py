from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from polaris.domain import Identifier, SafeText


class Severity(StrEnum):
    """Display severity. Never the only carrier of meaning — every view also states it in words."""

    INFO = "INFO"
    CAUTION = "CAUTION"
    BLOCKED = "BLOCKED"


class WorkflowState(StrEnum):
    """The states a reviewer must be able to tell apart, in the words the UI must use.

    `DRAFT` and `PENDING_APPROVAL` are distinct on purpose: a drafted action that nobody has
    submitted must never look like one awaiting a decision.
    """

    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"

    @property
    def implies_completion(self) -> bool:
        """Only a confirmed execution means the work happened."""

        return self is WorkflowState.EXECUTED


_STATE_LABELS: dict[WorkflowState, str] = {
    WorkflowState.DRAFT: "Draft — not submitted for approval",
    WorkflowState.PENDING_APPROVAL: "Awaiting independent approval — nothing has happened yet",
    WorkflowState.APPROVED: "Approved — not yet executed",
    WorkflowState.REJECTED: "Rejected — no action was taken",
    WorkflowState.EXPIRED: "Expired — no action was taken",
    WorkflowState.EXECUTED: "Executed — the task was created",
    WorkflowState.FAILED: "Failed — no action was taken",
}

_STATE_SEVERITY: dict[WorkflowState, Severity] = {
    WorkflowState.DRAFT: Severity.INFO,
    WorkflowState.PENDING_APPROVAL: Severity.CAUTION,
    WorkflowState.APPROVED: Severity.CAUTION,
    WorkflowState.REJECTED: Severity.INFO,
    WorkflowState.EXPIRED: Severity.CAUTION,
    WorkflowState.EXECUTED: Severity.INFO,
    WorkflowState.FAILED: Severity.BLOCKED,
}


def state_label(state: WorkflowState) -> str:
    return _STATE_LABELS[state]


def state_severity(state: WorkflowState) -> Severity:
    return _STATE_SEVERITY[state]


class SourceView(BaseModel):
    """One cited source, with its version, shown as text rather than as a link."""

    model_config = ConfigDict(frozen=True)

    document_id: Identifier
    title: SafeText
    version: Identifier
    excerpt: str = Field(min_length=1, max_length=2_000)
    source_reference: str = Field(min_length=1, max_length=300)
    contains_active_content: bool = False


class UncertaintyView(BaseModel):
    """Why an answer is or is not authoritative, stated rather than implied by omission."""

    model_config = ConfigDict(frozen=True)

    abstained: bool
    label: SafeText
    conflicting_topics: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_conflict(self) -> UncertaintyView:
        if self.conflicting_topics and not self.abstained:
            raise ValueError("A conflicting-source result must be presented as an abstention")
        return self


class AnswerView(BaseModel):
    """A drafted answer with its provenance and its limits attached, not separable from them."""

    model_config = ConfigDict(frozen=True)

    answer: str = Field(max_length=4_000)
    sources: tuple[SourceView, ...]
    uncertainty: UncertaintyView
    corpus_version: Identifier
    generated_by: SafeText
    severity: Severity = Severity.INFO
    text_alternative: SafeText

    @model_validator(mode="after")
    def validate_grounding(self) -> AnswerView:
        if not self.uncertainty.abstained and not self.sources:
            raise ValueError("A non-abstained answer must show its sources")
        if self.uncertainty.abstained and self.answer and not self.uncertainty.label:
            raise ValueError("An abstention must say why")
        return self


class ActionApprovalView(BaseModel):
    """Everything an approver must see before deciding, derived from the canonical action.

    The digest shown here is recomputed from the same canonical action the fields are drawn from, so
    a surface cannot display one action while the approver signs another. `verify_display_binding`
    is the check that proves it for a given view.
    """

    model_config = ConfigDict(frozen=True)

    proposal_id: Identifier
    state: WorkflowState
    state_label: SafeText
    severity: Severity
    requester: Identifier
    patient_id: Identifier
    facility_id: Identifier
    queue: SafeText
    due_date: date
    summary: str = Field(min_length=1, max_length=2_000)
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_at: datetime
    destination: SafeText
    reauthentication_required: bool = True
    warnings: tuple[str, ...] = ()
    text_alternative: SafeText

    @model_validator(mode="after")
    def validate_presentation(self) -> ActionApprovalView:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("Approval expiry must be timezone-aware")
        if self.state.implies_completion:
            raise ValueError("An approval preview cannot present a completed action")
        if not self.reauthentication_required:
            raise ValueError("Approval always requires reauthentication in v1")
        if self.state_label != state_label(self.state):
            raise ValueError("Approval state label must match its state")
        if self.severity is not state_severity(self.state):
            raise ValueError("Approval severity must match its state")
        return self

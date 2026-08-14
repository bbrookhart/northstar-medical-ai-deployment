from __future__ import annotations

from polaris.domain import ActionProposal, FollowUpAction, ProposalStatus
from polaris.presentation.rendering import contains_active_content, render_inert
from polaris.presentation.views import (
    ActionApprovalView,
    WorkflowState,
    state_label,
    state_severity,
)
from polaris.security.digest import action_digest

_STATE_MAP: dict[ProposalStatus, WorkflowState] = {
    ProposalStatus.PENDING: WorkflowState.PENDING_APPROVAL,
    ProposalStatus.APPROVED: WorkflowState.APPROVED,
    ProposalStatus.REJECTED: WorkflowState.REJECTED,
    ProposalStatus.EXPIRED: WorkflowState.EXPIRED,
    ProposalStatus.EXECUTED: WorkflowState.EXECUTED,
}

_DESTINATION = "Northstar care-coordination queue (administrative task, no clinical record change)"


class ApprovalPreviewError(ValueError):
    pass


def build_approval_view(proposal: ActionProposal) -> ActionApprovalView:
    """Render the approval preview from the canonical action, recomputing its digest.

    Both the displayed fields and the displayed digest come from the same `FollowUpAction`, so they
    cannot disagree. The digest stored on the proposal is compared against that recomputation, which
    means a stored digest that no longer matches its action is refused rather than displayed.
    """

    state = _STATE_MAP[proposal.status]
    if state.implies_completion:
        raise ApprovalPreviewError("An executed proposal has no approval preview")

    action = proposal.action
    recomputed = action_digest(action)
    if recomputed != proposal.action_digest:
        raise ApprovalPreviewError("Proposal digest does not match its canonical action")

    summary_warning = contains_active_content(action.summary)
    warnings: list[str] = []
    if summary_warning:
        warnings.append(
            "The drafted summary contained characters that are not displayed literally. "
            "Read the rendered text carefully before approving."
        )
    if state is WorkflowState.EXPIRED:
        warnings.append("This proposal expired and can no longer be approved.")

    return ActionApprovalView(
        proposal_id=proposal.proposal_id,
        state=state,
        state_label=state_label(state),
        severity=state_severity(state),
        requester=proposal.requester.subject,
        patient_id=action.patient_id,
        facility_id=action.facility_id,
        queue=action.queue,
        due_date=action.due_date,
        summary=render_inert(action.summary),
        action_digest=recomputed,
        expires_at=proposal.expires_at,
        destination=_DESTINATION,
        warnings=tuple(warnings),
        text_alternative=_text_alternative(action, state),
    )


def verify_display_binding(view: ActionApprovalView, action: FollowUpAction) -> bool:
    """Confirm the preview describes exactly the action that would execute.

    A trusted surface calls this immediately before submitting a decision. Any divergence between
    what was shown and what is about to be signed — a changed patient, facility, date, or summary —
    fails here rather than being approved.
    """

    return (
        view.action_digest == action_digest(action)
        and view.patient_id == action.patient_id
        and view.facility_id == action.facility_id
        and view.queue == action.queue
        and view.due_date == action.due_date
        and view.summary == render_inert(action.summary)
    )


def _text_alternative(action: FollowUpAction, state: WorkflowState) -> str:
    """A single spoken-order sentence for assistive technology and for a non-visual review."""

    return (
        f"{state_label(state)}. Administrative follow-up task for patient "
        f"{action.patient_id} at facility {action.facility_id}, due {action.due_date.isoformat()}, "
        f"routed to the {action.queue} queue. Approval requires reauthentication."
    )[:500]

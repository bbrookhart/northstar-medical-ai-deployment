from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from polaris.domain import (
    ActionProposal,
    Citation,
    FollowUpAction,
    Principal,
    ProposalStatus,
    PurposeOfUse,
    RetrievalOutcome,
)
from polaris.presentation.answer import build_answer_view
from polaris.presentation.approval import (
    ApprovalPreviewError,
    build_approval_view,
    verify_display_binding,
)
from polaris.presentation.emergency import (
    FIXED_EMERGENCY_GUIDANCE,
    EmergencyOutcome,
    check_emergency_language,
)
from polaris.presentation.rendering import contains_active_content, render_inert
from polaris.presentation.views import (
    ActionApprovalView,
    AnswerView,
    Severity,
    SourceView,
    UncertaintyView,
    WorkflowState,
    state_label,
    state_severity,
)
from polaris.security.digest import action_digest

NOW = datetime(2026, 8, 14, tzinfo=UTC)


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("<script>alert(1)</script>", "<script>"),
        ('" onerror="alert(1)', 'onerror="'),
        ("Click javascript:alert(1) now", "javascript:"),
        ("Fetch data:text/html;base64,PHN2Zz4=", "data:"),
        ("Escape \x1b[31mred\x1b[0m sequence", "\x1b["),
        ("Reversed ‮txet‬ here", "‮"),
        ("Null\x00byte", "\x00"),
    ],
)
def test_untrusted_text_renders_inert(raw: str, must_not_contain: str) -> None:
    assert must_not_contain not in render_inert(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "<script>alert(1)</script>",
        "Click javascript:alert(1) now",
        "Fetch data:text/html;base64,PHN2Zz4=",
        "Escape \x1b[31mred\x1b[0m sequence",
        "Reversed ‮txet‬ here",
        "Null\x00byte",
    ],
)
def test_unusual_source_content_is_flagged_for_the_reviewer(raw: str) -> None:
    assert contains_active_content(raw) is True


def test_ordinary_punctuation_is_not_flagged_as_active_content() -> None:
    """The warning has to stay meaningful, so quoting and apostrophes do not raise it.

    Quotes only matter to a renderer that interpolates unescaped text into an attribute, which the
    escaping already prevents. Flagging every quoted phrase would train reviewers to ignore it.
    """

    quoted = 'The policy defines a "routine follow-up" and the coordinator\'s duties.'

    assert contains_active_content(quoted) is False
    assert "&quot;" in render_inert(quoted)


def test_inert_rendering_preserves_readable_policy_text() -> None:
    original = "Workforce access must be limited to the information needed for the purpose."

    assert render_inert(original) == original
    assert contains_active_content(original) is False


def test_inert_rendering_bounds_length_and_marks_truncation() -> None:
    rendered = render_inert("policy " * 500, limit=100)

    assert len(rendered) == 100
    assert rendered.endswith("…")
    with pytest.raises(ValueError, match="at least one character"):
        render_inert("text", limit=0)


def test_approval_preview_is_bound_to_the_canonical_action() -> None:
    action = _action()
    proposal = _proposal(action)

    view = build_approval_view(proposal)

    assert view.action_digest == action_digest(action)
    assert view.patient_id == action.patient_id
    assert view.due_date == action.due_date
    assert view.reauthentication_required is True
    assert verify_display_binding(view, action) is True

    # Any divergence between what was displayed and what would be signed fails the binding.
    for mutated in (
        action.model_copy(update={"patient_id": "SYN-P2002"}),
        action.model_copy(update={"facility_id": "FAC-SOUTH"}),
        action.model_copy(update={"due_date": date(2026, 12, 25)}),
        action.model_copy(update={"summary": "Confirm a different task entirely."}),
    ):
        assert verify_display_binding(view, mutated) is False


def test_a_proposal_whose_stored_digest_drifted_is_refused_not_displayed() -> None:
    proposal = _proposal(_action()).model_copy(update={"action_digest": "0" * 64})

    with pytest.raises(ApprovalPreviewError, match="does not match its canonical action"):
        build_approval_view(proposal)


def test_an_executed_proposal_has_no_approval_preview() -> None:
    proposal = _proposal(_action()).model_copy(update={"status": ProposalStatus.EXECUTED})

    with pytest.raises(ApprovalPreviewError, match="no approval preview"):
        build_approval_view(proposal)


def test_untrusted_summary_content_is_rendered_inert_and_warned_about() -> None:
    action = _action(summary="Confirm booking <script>steal()</script> before Friday.")
    proposal = _proposal(action)

    view = build_approval_view(proposal)

    assert "<script>" not in view.summary
    assert view.warnings
    assert "not displayed literally" in view.warnings[0]
    assert verify_display_binding(view, action) is True


@pytest.mark.parametrize("state", list(WorkflowState))
def test_only_execution_implies_completion(state: WorkflowState) -> None:
    assert state.implies_completion is (state is WorkflowState.EXECUTED)
    # Severity is never the only carrier of meaning: every state also has a sentence.
    assert state_label(state)
    assert isinstance(state_severity(state), Severity)


def test_a_view_cannot_mislabel_its_own_state() -> None:
    view = build_approval_view(_proposal(_action()))

    with pytest.raises(ValidationError, match="state label must match"):
        ActionApprovalView.model_validate(
            {**view.model_dump(), "state_label": state_label(WorkflowState.EXECUTED)}
        )
    with pytest.raises(ValidationError, match="severity must match"):
        ActionApprovalView.model_validate({**view.model_dump(), "severity": Severity.INFO.value})
    with pytest.raises(ValidationError, match="always requires reauthentication"):
        ActionApprovalView.model_validate({**view.model_dump(), "reauthentication_required": False})


def test_an_abstention_cannot_be_presented_as_an_answer() -> None:
    view = build_answer_view(
        answer="",
        citations=(),
        outcome=RetrievalOutcome.ABSTAINED_NO_MATCH,
        corpus_version="2026.08.14",
        generated_by="polaris-deterministic-v1",
    )

    assert view.uncertainty.abstained is True
    assert view.severity is Severity.CAUTION
    assert "No approved source answers this" in view.uncertainty.label
    assert "did not" in view.text_alternative or "No approved source" in view.text_alternative

    # A confident answer with no sources cannot be constructed at all.
    with pytest.raises(ValidationError, match="must show its sources"):
        AnswerView(
            answer="The policy says yes.",
            sources=(),
            uncertainty=UncertaintyView(abstained=False, label="Drafted."),
            corpus_version="2026.08.14",
            generated_by="test",
            text_alternative="A confident answer with no sources.",
        )


def test_a_conflict_must_be_presented_as_an_abstention() -> None:
    view = build_answer_view(
        answer="",
        citations=(_citation("POL-CC-014"), _citation("POL-CC-021")),
        outcome=RetrievalOutcome.ABSTAINED_CONFLICT,
        corpus_version="2026.08.14",
        generated_by="polaris-deterministic-v1",
        conflicting_topics=("follow-up-task",),
    )

    assert view.uncertainty.abstained is True
    assert view.uncertainty.conflicting_topics == ("follow-up-task",)
    assert len(view.sources) == 2
    with pytest.raises(ValidationError, match="must be presented as an abstention"):
        UncertaintyView(abstained=False, label="Drafted.", conflicting_topics=("topic",))


def test_source_excerpts_are_rendered_inert_and_flagged() -> None:
    view = build_answer_view(
        answer="Approved sources apply.",
        citations=(_citation("POL-AI-001", excerpt="Read <b>this</b> carefully."),),
        outcome=RetrievalOutcome.ANSWERED,
        corpus_version="2026.08.14",
        generated_by="polaris-deterministic-v1",
    )

    source: SourceView = view.sources[0]
    assert "<b>" not in source.excerpt
    assert source.contains_active_content is True
    # The source reference is displayed as text, never as a live link.
    assert source.source_reference.startswith("POL-AI-001")


@pytest.mark.parametrize(
    "text",
    [
        "This is an emergency, the patient has chest pain",
        "Patient is unresponsive right now",
        "Should I call 911?",
        "urgent: bleeding heavily",
    ],
)
def test_emergency_language_returns_fixed_guidance_without_assessing_urgency(text: str) -> None:
    outcome = check_emergency_language(text)

    assert outcome.triggered is True
    assert outcome.guidance == FIXED_EMERGENCY_GUIDANCE
    assert "cannot assess how" in outcome.guidance
    # There is nowhere to record a severity, triage level, or confidence.
    assert set(EmergencyOutcome.__dataclass_fields__) == {"triggered", "guidance"}


def test_routine_administrative_text_does_not_trigger_emergency_routing() -> None:
    outcome = check_emergency_language("Confirm the routine follow-up appointment booking.")

    assert outcome.triggered is False
    assert outcome.guidance == ""


def test_the_approval_preview_endpoint_requires_approver_authorization(
    client: TestClient,
    headers: Callable[..., dict[str, str]],
) -> None:
    proposal = client.post(
        "/v1/actions/proposals",
        headers=headers(),
        json={
            "action": {
                "patient_id": "SYN-P1001",
                "facility_id": "FAC-NORTH",
                "due_date": "2026-09-01",
                "summary": "Confirm the routine follow-up appointment booking.",
            }
        },
    )
    assert proposal.status_code == 201
    proposal_id = proposal.json()["proposal_id"]
    digest = proposal.json()["action_digest"]

    denied = client.get(
        f"/v1/actions/proposals/{proposal_id}/preview",
        headers=headers(subject="user-care-1"),
    )
    assert denied.status_code == 403

    preview = client.get(
        f"/v1/actions/proposals/{proposal_id}/preview",
        headers=headers(subject="approver-1", roles=["task_approver"]),
    )

    assert preview.status_code == 200
    body = preview.json()
    assert body["action_digest"] == digest
    assert body["state"] == WorkflowState.PENDING_APPROVAL.value
    assert body["reauthentication_required"] is True
    assert "nothing has happened yet" in body["state_label"]
    assert body["text_alternative"]


def _action(summary: str = "Confirm the routine follow-up appointment booking.") -> FollowUpAction:
    return FollowUpAction(
        patient_id="SYN-P1001",
        facility_id="FAC-NORTH",
        due_date=date(2026, 9, 1),
        summary=summary,
    )


def _proposal(action: FollowUpAction) -> ActionProposal:
    return ActionProposal(
        proposal_id="PRP-preview-1",
        action=action,
        action_digest=action_digest(action),
        requester=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        status=ProposalStatus.PENDING,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def _citation(document_id: str, *, excerpt: str = "An approved policy excerpt.") -> Citation:
    return Citation(
        document_id=document_id,
        title=f"Policy {document_id}",
        version="2026.08.14",
        excerpt=excerpt,
    )


def _principal() -> Principal:
    return Principal(
        subject="user-care-1",
        token_id="token-preview-1",
        client_id="polaris-web",
        scopes=frozenset({"polaris.task.propose"}),
        roles=frozenset({"care_coordinator"}),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset({"SYN-P1001"}),
    )

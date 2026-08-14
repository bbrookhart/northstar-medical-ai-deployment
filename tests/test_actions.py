from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from polaris.config import Settings
from polaris.domain import ApprovalReceipt, ProposalStatus
from polaris.main import create_app


def _action(summary: str = "Confirm availability for routine follow-up") -> dict[str, object]:
    return {
        "action_type": "administrative_follow_up",
        "patient_id": "SYN-P1001",
        "facility_id": "FAC-NORTH",
        "queue": "care_coordination",
        "due_date": date(2026, 8, 20).isoformat(),
        "summary": summary,
    }


def _propose(
    client: TestClient, headers: Callable[..., dict[str, str]], summary: str | None = None
) -> dict[str, object]:
    response = client.post(
        "/v1/actions/proposals",
        headers=headers(),
        json={"action": _action(summary or "Confirm availability for routine follow-up")},
    )
    assert response.status_code == 201
    return cast(dict[str, object], response.json())


def test_happy_path_requires_independent_bound_approval_and_is_idempotent(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    proposal = _propose(client, headers)
    proposal_id = str(proposal["proposal_id"])
    digest = str(proposal["action_digest"])

    approval = client.post(
        f"/v1/actions/proposals/{proposal_id}/decision",
        headers=headers(subject="approver-1", roles=["task_approver"]),
        json={"decision": "APPROVE", "expected_action_digest": digest, "comment": "Reviewed"},
    )
    assert approval.status_code == 200
    assert approval.json()["action_digest"] == digest

    execute_headers = headers(subject="executor-1", roles=["task_executor"])
    first = client.post(
        f"/v1/actions/proposals/{proposal_id}/execute",
        headers=execute_headers,
        json={"expected_action_digest": digest},
    )
    second = client.post(
        f"/v1/actions/proposals/{proposal_id}/execute",
        headers=execute_headers,
        json={"expected_action_digest": digest},
    )

    assert first.status_code == 200
    assert first.json()["idempotent_replay"] is False
    assert second.status_code == 200
    assert second.json()["task_id"] == first.json()["task_id"]
    assert second.json()["idempotent_replay"] is True


def test_requester_cannot_approve_own_action(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    proposal = _propose(client, headers)
    response = client.post(
        f"/v1/actions/proposals/{proposal['proposal_id']}/decision",
        headers=headers(roles=["care_coordinator", "task_approver"]),
        json={
            "decision": "APPROVE",
            "expected_action_digest": proposal["action_digest"],
            "comment": "Self approval",
        },
    )

    assert response.status_code == 403
    assert response.json()["code"] == "APPROVER_INDEPENDENCE_DENIED"


def test_changed_digest_cannot_be_approved(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    proposal = _propose(client, headers)
    response = client.post(
        f"/v1/actions/proposals/{proposal['proposal_id']}/decision",
        headers=headers(subject="approver-1", roles=["task_approver"]),
        json={"decision": "APPROVE", "expected_action_digest": "0" * 64, "comment": ""},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "ACTION_DIGEST_MISMATCH"


def test_clinical_action_content_is_rejected(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    response = client.post(
        "/v1/actions/proposals",
        headers=headers(),
        json={"action": _action("Increase the medication dose to 20 mg")},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "ACTION_CLINICAL_CONTENT_DENIED"


def test_unapproved_and_wrong_role_execution_are_denied(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    proposal = _propose(client, headers)
    endpoint = f"/v1/actions/proposals/{proposal['proposal_id']}/execute"
    wrong_role = client.post(
        endpoint,
        headers=headers(),
        json={"expected_action_digest": proposal["action_digest"]},
    )
    unapproved = client.post(
        endpoint,
        headers=headers(subject="executor-1", roles=["task_executor"]),
        json={"expected_action_digest": proposal["action_digest"]},
    )

    assert wrong_role.status_code == 403
    assert wrong_role.json()["code"] == "ACTION_EXECUTION_DENIED"
    assert unapproved.status_code == 409
    assert unapproved.json()["code"] == "PROPOSAL_NOT_APPROVED"


class MutableClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current


def test_expired_proposal_cannot_be_approved(
    settings: Settings,
    headers: Callable[..., dict[str, str]],
) -> None:
    clock = MutableClock()
    expiring_settings = replace(settings, action_ttl_seconds=30)
    with TestClient(create_app(expiring_settings, clock=clock)) as local_client:
        proposal = _propose(local_client, headers)
        clock.current += timedelta(seconds=31)
        response = local_client.post(
            f"/v1/actions/proposals/{proposal['proposal_id']}/decision",
            headers=headers(subject="approver-1", roles=["task_approver"]),
            json={
                "decision": "APPROVE",
                "expected_action_digest": proposal["action_digest"],
                "comment": "Expired",
            },
        )
        services = cast(FastAPI, local_client.app).state.services
        persisted_status = services.actions.get_proposal(str(proposal["proposal_id"])).status
        audit_outcomes = [event.outcome for event in services.audit.snapshot()]

    assert response.status_code == 409
    assert response.json()["code"] == "PROPOSAL_EXPIRED"
    assert persisted_status is ProposalStatus.EXPIRED
    assert "PROPOSAL_EXPIRED" in audit_outcomes


def test_tampered_approval_receipt_blocks_execution(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    proposal = _propose(client, headers)
    proposal_id = str(proposal["proposal_id"])
    digest = str(proposal["action_digest"])
    approval = client.post(
        f"/v1/actions/proposals/{proposal_id}/decision",
        headers=headers(subject="approver-1", roles=["task_approver"]),
        json={"decision": "APPROVE", "expected_action_digest": digest, "comment": "Reviewed"},
    )
    assert approval.status_code == 200

    app = cast(FastAPI, client.app)
    receipt = ApprovalReceipt.model_validate(approval.json())
    with app.state.services.state.transaction() as transaction:
        transaction.save_approval(receipt.model_copy(update={"signature": "0" * 64}))

    execution = client.post(
        f"/v1/actions/proposals/{proposal_id}/execute",
        headers=headers(subject="executor-1", roles=["task_executor"]),
        json={"expected_action_digest": digest},
    )
    audit_outcomes = [event.outcome for event in app.state.services.audit.snapshot()]
    assert execution.status_code == 409
    assert execution.json()["code"] == "APPROVAL_INTEGRITY_FAILURE"
    assert "APPROVAL_INTEGRITY_FAILURE" in audit_outcomes


def test_approval_and_execution_require_operations_purpose_at_policy_boundary(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    proposal = _propose(client, headers)
    proposal_id = str(proposal["proposal_id"])
    digest = str(proposal["action_digest"])

    wrong_approval_purpose = client.post(
        f"/v1/actions/proposals/{proposal_id}/decision",
        headers=headers(
            subject="approver-1",
            roles=["task_approver"],
            purpose="TRAINING",
        ),
        json={"decision": "APPROVE", "expected_action_digest": digest, "comment": ""},
    )
    assert wrong_approval_purpose.status_code == 403
    assert wrong_approval_purpose.json()["code"] == "APPROVAL_PURPOSE_DENIED"

    approval = client.post(
        f"/v1/actions/proposals/{proposal_id}/decision",
        headers=headers(subject="approver-1", roles=["task_approver"]),
        json={"decision": "APPROVE", "expected_action_digest": digest, "comment": ""},
    )
    assert approval.status_code == 200

    wrong_execution_purpose = client.post(
        f"/v1/actions/proposals/{proposal_id}/execute",
        headers=headers(
            subject="executor-1",
            roles=["task_executor"],
            purpose="TRAINING",
        ),
        json={"expected_action_digest": digest},
    )
    assert wrong_execution_purpose.status_code == 403
    assert wrong_execution_purpose.json()["code"] == "ACTION_EXECUTION_DENIED"

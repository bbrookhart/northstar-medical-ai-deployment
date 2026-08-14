from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from polaris.domain import AuditEvent
from polaris.operations.detections import (
    RULES,
    DetectionCategory,
    DetectionSeverity,
    covered_categories,
    evaluate_detections,
)
from polaris.operations.gameday import run_game_day
from polaris.operations.telemetry import covered_event_types, summarize, validate_events

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 14, tzinfo=UTC)


def test_a_real_request_flow_emits_investigable_telemetry(
    client: TestClient,
    headers: Callable[..., dict[str, str]],
) -> None:
    """Every audit event a normal flow produces must be explicable and carry nothing prohibited."""

    client.post(
        "/v1/policies/query",
        headers=headers(),
        json={"question": "What approval is required for a care coordination follow-up task?"},
    )
    client.get("/v1/patients/SYN-P1001/summary", headers=headers())
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
    client.get(
        f"/v1/actions/proposals/{proposal.json()['proposal_id']}/preview",
        headers=headers(subject="approver-1", roles=["task_approver"]),
    )

    events = client.app.state.services.audit.snapshot()  # type: ignore[attr-defined]
    findings = validate_events(events)

    assert findings == (), summarize(findings)
    assert {event.event_type for event in events} & set(covered_event_types())


def test_prohibited_content_in_telemetry_is_detected() -> None:
    hostile = [
        _event(1, "policy.query", {"purpose": "X", "policy_version": "1", "corpus_version": "1"}),
        _event(
            2,
            "agent.run",
            {
                "run_id": "R",
                "model_id": "M",
                "corpus_version": "1",
                "detail": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
            },
        ),
        _event(
            3,
            "agent.run",
            {
                "run_id": "R",
                "model_id": "M",
                "corpus_version": "1",
                "detail": "<<<UNTRUSTED_SOURCE id=POL-AI-001.000",
            },
        ),
        _event(
            4,
            "agent.run",
            {
                "run_id": "R",
                "model_id": "M",
                "corpus_version": "1",
                "detail": "contact clinician@northstar.example.test",
            },
        ),
        _event(
            5,
            "agent.run",
            {
                "run_id": "R",
                "model_id": "M",
                "corpus_version": "1",
                "detail": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl",
            },
        ),
        _event(
            6,
            "agent.run",
            {"run_id": "R", "model_id": "M", "corpus_version": "1", "detail": "x" * 400},
        ),
    ]

    rules = {finding.rule for finding in validate_events(hostile)}

    assert "prohibited-credential" in rules
    assert "prohibited-jwt" in rules
    assert "prohibited-context-envelope" in rules
    assert "prohibited-email" in rules
    assert "bounded-value" in rules


def test_missing_required_context_is_detected() -> None:
    incomplete = [_event(1, "patient.read", {"patient_id": "SYN-P1001"})]

    findings = validate_events(incomplete)

    assert findings[0].rule == "required-context"
    assert "purpose" in findings[0].detail
    assert "policy_version" in findings[0].detail


def test_detections_cover_every_required_category() -> None:
    # REQ-OPS-003 names these categories; a missing one is a coverage gap by definition.
    assert covered_categories() == set(DetectionCategory)
    assert len({rule.rule_id for rule in RULES}) == len(RULES)
    assert all(rule.description and rule.threshold >= 1 for rule in RULES)


@pytest.mark.parametrize(
    ("event_type", "outcome", "metadata", "expected"),
    [
        ("patient.read", "PATIENT_NOT_AVAILABLE", {}, "DET-002"),
        ("action.propose", "ACTION_FACILITY_DENIED", {}, "DET-003"),
        ("agent.run", "AGENT_RUN_REFUSED", {"detail": "FABRICATED_CITATION"}, "DET-004"),
        ("agent.run", "AGENT_RUN_REFUSED", {"detail": "SENSITIVE_DISCLOSURE"}, "DET-006"),
        ("agent.run", "AGENT_RUN_HALTED", {}, "DET-008"),
        ("agent.capability", "AGENT_CAPABILITY_DISABLED", {"capability": "WRITE"}, "DET-010"),
    ],
)
def test_each_detection_fires_on_its_own_signal(
    event_type: str,
    outcome: str,
    metadata: dict[str, str],
    expected: str,
) -> None:
    rule = next(rule for rule in RULES if rule.rule_id == expected)
    events = [
        _event(index + 1, event_type, metadata, outcome=outcome, offset=index)
        for index in range(rule.threshold)
    ]

    fired = {detection.rule_id for detection in evaluate_detections(events)}

    assert expected in fired


def test_a_detection_below_its_threshold_does_not_fire() -> None:
    rule = next(rule for rule in RULES if rule.rule_id == "DET-002")
    events = [
        _event(index + 1, "patient.read", {}, outcome="PATIENT_NOT_AVAILABLE", offset=index)
        for index in range(rule.threshold - 1)
    ]

    assert evaluate_detections(events) == ()


def test_an_old_cluster_does_not_keep_a_rule_permanently_lit() -> None:
    rule = next(rule for rule in RULES if rule.rule_id == "DET-002")
    stale = [
        _event(index + 1, "patient.read", {}, outcome="PATIENT_NOT_AVAILABLE", offset=index * 600)
        for index in range(rule.threshold)
    ]

    assert evaluate_detections(stale) == ()


def test_critical_detections_are_declared_for_containment_relevant_signals() -> None:
    critical = {rule.category for rule in RULES if rule.severity is DetectionSeverity.CRITICAL}

    assert {
        DetectionCategory.IDENTITY_ABUSE,
        DetectionCategory.INJECTION_CANARY,
        DetectionCategory.DATA_LOSS,
        DetectionCategory.CONTROL_DISABLEMENT,
    } <= critical


def test_game_day_drills_meet_their_objectives(tmp_path: Path) -> None:
    report = run_game_day(tmp_path)

    unmet = [f"{result.drill_id}: {result.observed}" for result in report.results if not result.met]
    assert unmet == []
    assert {result.drill_id for result in report.results} == {
        "GD-01",
        "GD-02",
        "GD-03",
        "GD-04",
        "GD-05",
    }
    # Every drill states the scope it actually exercised, so a local result cannot read as a
    # production one.
    assert all(result.scope for result in report.results)


def test_the_generated_game_day_report_is_committed_and_current(tmp_path: Path) -> None:
    generated = json.loads(run_game_day(tmp_path).to_json())
    committed = json.loads((ROOT / "evidence/reports/M10-game-day.json").read_text())
    generated.pop("executed_at")
    committed.pop("executed_at")

    assert committed == generated
    assert "do not exercise the PostgreSQL failover" in committed["summary"]["scope"]


def _event(
    sequence: int,
    event_type: str,
    metadata: dict[str, str],
    *,
    outcome: str = "OK",
    offset: int = 0,
) -> AuditEvent:
    return AuditEvent(
        sequence=sequence,
        occurred_at=NOW + timedelta(seconds=offset),
        actor="user-care-1",
        event_type=event_type,
        outcome=outcome,
        correlation_id=f"corr-{sequence}",
        metadata=metadata,
        previous_hash="GENESIS" if sequence == 1 else "a" * 64,
        event_hash="b" * 64,
    )

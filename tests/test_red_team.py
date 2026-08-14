from __future__ import annotations

import json
from pathlib import Path

from polaris.assurance.attacks import BLOCKING_SEVERITIES, AttackClass, Severity
from polaris.assurance.redteam import CASES, run_campaign
from polaris.assurance.release_eval import DimensionStatus, build_release_evaluation

ROOT = Path(__file__).resolve().parents[1]


def test_the_campaign_covers_every_required_attack_class() -> None:
    covered = {case.attack_class for case in CASES}

    # REQ-SDL-004 names these classes; a campaign missing one is incomplete by definition.
    assert covered == set(AttackClass)
    assert len({case.case_id for case in CASES}) == len(CASES)
    # Every case names the control expected to stop it, so a pass in the wrong place is visible.
    assert all(case.expected_control for case in CASES)


def test_every_attack_is_contained_by_the_deterministic_stack() -> None:
    report = run_campaign()

    uncontained = [
        f"{result.case_id} [{result.severity.value}] {result.detail}"
        for result in report.results
        if not result.contained
    ]
    assert uncontained == []
    assert report.containment_rate == 1.0
    assert report.blocking_failures == ()
    assert report.passed is True


def test_critical_and_high_cases_admit_no_partial_credit() -> None:
    report = run_campaign()
    blocking = [result for result in report.results if result.severity in BLOCKING_SEVERITIES]

    assert len(blocking) >= 10
    assert all(result.contained for result in blocking)
    assert Severity.CRITICAL in {result.severity for result in blocking}


def test_the_campaign_report_is_deterministic() -> None:
    first = json.loads(run_campaign().to_json())
    second = json.loads(run_campaign().to_json())
    first.pop("executed_at")
    second.pop("executed_at")

    assert first == second


def test_the_release_evaluation_separates_blocking_gaps_from_missing_evidence() -> None:
    evaluation = build_release_evaluation(run_campaign())

    # No blocking gap: authorization, security, and grounding are assessed and the campaign held.
    assert evaluation.blocking_gaps == ()
    # But the release is still not ready, because four dimensions have no evidence at all.
    assert {dimension.name for dimension in evaluation.unassessed} == {
        "accessibility",
        "performance",
        "cost",
        "recovery",
    }
    assert evaluation.release_ready is False


def test_every_required_evaluation_dimension_is_declared() -> None:
    evaluation = build_release_evaluation(run_campaign())
    names = {dimension.name for dimension in evaluation.dimensions}

    # REQ-SDL-003 enumerates these dimensions.
    assert names == {
        "function",
        "authorization",
        "privacy",
        "security",
        "safety",
        "grounding",
        "robustness",
        "accessibility",
        "performance",
        "cost",
        "recovery",
    }
    for dimension in evaluation.dimensions:
        assert dimension.threshold
        assert dimension.note
        if dimension.status is not DimensionStatus.NOT_ASSESSED:
            assert dimension.evidence


def test_generated_assurance_reports_are_committed_and_current() -> None:
    campaign = run_campaign()
    evaluation = build_release_evaluation(campaign)

    committed_campaign = json.loads((ROOT / "evidence/reports/M09-red-team.json").read_text())
    committed_evaluation = json.loads(
        (ROOT / "evidence/reports/M09-release-evaluation.json").read_text()
    )
    generated_campaign = json.loads(campaign.to_json())
    committed_campaign.pop("executed_at")
    generated_campaign.pop("executed_at")

    assert committed_campaign == generated_campaign
    assert committed_evaluation == json.loads(evaluation.to_json())
    assert committed_evaluation["decision"]["release_ready"] is False

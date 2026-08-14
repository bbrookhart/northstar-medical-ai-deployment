from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from polaris.services.retrieval_eval import (
    QUALITY_PASS_RATE,
    SECURITY_PASS_RATE,
    EvaluationCase,
    EvaluationKind,
    build_evaluation_index,
    golden_cases,
    run_evaluation,
)

NOW = datetime(2026, 8, 14, tzinfo=UTC)
REPORT = Path("evidence/reports/M05-retrieval-evaluation.json")


class FixedClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


def test_golden_set_meets_security_and_quality_thresholds() -> None:
    report = run_evaluation(build_evaluation_index(clock=FixedClock(NOW)), clock=FixedClock(NOW))

    assert report.security_pass_rate == SECURITY_PASS_RATE
    assert report.quality_pass_rate >= QUALITY_PASS_RATE
    assert report.meets_thresholds is True
    assert [result.case_id for result in report.results if not result.passed] == []


def test_every_kind_is_represented_and_security_cases_admit_no_partial_credit() -> None:
    kinds = {case.kind for case in golden_cases()}

    assert kinds == set(EvaluationKind)
    # A single security failure must sink the run, so the threshold cannot be met by averaging.
    assert SECURITY_PASS_RATE == 1.0


def test_a_leaked_forbidden_document_fails_regardless_of_case_kind() -> None:
    index = build_evaluation_index(clock=FixedClock(NOW))
    # Ask a question the corpus answers well, but forbid the document that answers it.
    rigged = EvaluationCase(
        case_id="EVAL-RIG-001",
        kind=EvaluationKind.GROUNDED,
        question="How must workforce access be limited for an approved purpose?",
        roles=frozenset({"care_coordinator"}),
        expected_document_ids=frozenset({"POL-PRIV-007"}),
        forbidden_document_ids=frozenset({"POL-PRIV-007"}),
    )

    report = run_evaluation(index, [rigged], clock=FixedClock(NOW))

    assert report.results[0].passed is False
    assert "forbidden" in report.results[0].detail
    assert report.meets_thresholds is False


def test_generated_evaluation_report_is_committed_and_current() -> None:
    report = run_evaluation(build_evaluation_index(clock=FixedClock(NOW)), clock=FixedClock(NOW))
    committed = json.loads(REPORT.read_text())
    generated = json.loads(report.to_json())

    committed.pop("evaluated_at")
    generated.pop("evaluated_at")
    assert committed == generated
    assert committed["measured"]["meets_thresholds"] is True

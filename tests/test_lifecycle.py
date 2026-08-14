from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from polaris.lifecycle.audit_package import build_audit_package
from polaris.lifecycle.change_impact import ChangeKind, ImpactLevel, analyze_change
from polaris.lifecycle.retirement import deleted_tables, retained_tables, run_retirement
from polaris.services.container import CORPUS_ID, CORPUS_VERSION
from polaris.supplychain.aibom import build_aibom

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def baseline() -> dict[str, Any]:
    return build_aibom(ROOT, corpus_id=CORPUS_ID, corpus_version=CORPUS_VERSION)


def test_an_unchanged_bill_of_materials_requires_no_review(baseline: dict[str, Any]) -> None:
    report = analyze_change(baseline, copy.deepcopy(baseline))

    assert report.changes == ()
    assert report.requires_review is False


def test_introducing_a_hosted_provider_is_material(baseline: dict[str, Any]) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["models"][0]["hosted"] = True
    candidate["models"][0]["model_id"] = "hosted-provider-v1"

    report = analyze_change(baseline, candidate)

    kinds = {change.kind for change in report.changes}
    assert ChangeKind.MODEL in kinds
    assert all(change.impact is ImpactLevel.MATERIAL for change in report.material)
    assert any("due diligence" in action for action in report.required_actions)
    assert any("adversarial campaign" in action for action in report.required_actions)


def test_a_changed_system_contract_is_a_prompt_change(baseline: dict[str, Any]) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["models"][0]["system_contract_sha256"] = "f" * 64

    report = analyze_change(baseline, candidate)

    assert {change.kind for change in report.changes} == {ChangeKind.PROMPT}
    assert report.requires_review is True


def test_a_changed_corpus_names_what_moved(baseline: dict[str, Any]) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["corpora"][0]["manifest_sha256"] = "a" * 64
    candidate["corpora"][0]["admitted_documents"] = ["POL-AI-001", "POL-NEW-001"]

    report = analyze_change(baseline, candidate)

    corpus = next(change for change in report.changes if change.kind is ChangeKind.CORPUS)
    assert corpus.impact is ImpactLevel.MATERIAL
    assert "POL-NEW-001" in corpus.summary
    assert "POL-CC-014" in corpus.summary


def test_adding_a_write_tool_requires_safety_and_human_factors_review(
    baseline: dict[str, Any],
) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["tools"].append(
        {
            "name": "record.write",
            "version": "1",
            "kind": "WRITE",
            "operation": "action.propose",
            "arguments_schema_sha256": "b" * 64,
        }
    )

    report = analyze_change(baseline, candidate)

    tool = next(change for change in report.changes if change.kind is ChangeKind.TOOL)
    assert tool.impact is ImpactLevel.MATERIAL
    assert any("clinical-safety" in action for action in tool.required_actions)
    assert any("human-factors" in action for action in tool.required_actions)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"cross_session_memory": True}, "cross-session memory"),
        ({"max_steps": 99}, "max_steps was raised"),
        ({"max_write_proposals": 5}, "max_write_proposals was raised"),
    ],
)
def test_loosening_a_bound_is_an_autonomy_change(
    baseline: dict[str, Any],
    mutation: dict[str, Any],
    expected: str,
) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["bounds"].update(mutation)

    report = analyze_change(baseline, candidate)

    autonomy = next(change for change in report.changes if change.kind is ChangeKind.AUTONOMY)
    assert autonomy.impact is ImpactLevel.MATERIAL
    assert expected in autonomy.summary


def test_removing_a_kill_switch_is_an_autonomy_change(baseline: dict[str, Any]) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["kill_switches"] = ["MODEL", "READ"]

    report = analyze_change(baseline, candidate)

    autonomy = next(change for change in report.changes if change.kind is ChangeKind.AUTONOMY)
    assert "WRITE" in autonomy.summary


def test_lowering_an_evaluation_threshold_is_material(baseline: dict[str, Any]) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["evaluations"][0]["security_threshold"] = 0.5

    report = analyze_change(baseline, candidate)

    evaluation = next(change for change in report.changes if change.kind is ChangeKind.EVALUATION)
    assert evaluation.impact is ImpactLevel.MATERIAL
    # Lowering a threshold is how a failing evaluation gets made to pass, so it needs justifying.
    assert any("residual-risk" in action for action in evaluation.required_actions)


def test_every_change_kind_can_be_detected(baseline: dict[str, Any]) -> None:
    candidate = copy.deepcopy(baseline)
    candidate["models"][0]["model_id"] = "other-model"
    candidate["models"][0]["system_contract_sha256"] = "c" * 64
    candidate["corpora"][0]["manifest_sha256"] = "d" * 64
    candidate["tools"].append(
        {
            "name": "extra.read",
            "version": "1",
            "kind": "READ",
            "operation": "policy.query",
            "arguments_schema_sha256": "e" * 64,
        }
    )
    candidate["bounds"]["max_steps"] = 99
    candidate["evaluations"][0]["quality_threshold"] = 0.1
    candidate["application"]["lock_sha256"] = "f" * 64

    report = analyze_change(baseline, candidate)

    assert {change.kind for change in report.changes} == set(ChangeKind)
    assert report.requires_review is True


def test_retirement_deletes_operational_data_and_keeps_the_audit_record(tmp_path: Path) -> None:
    report = run_retirement(tmp_path)

    unmet = [f"{step.step_id}: {step.observed}" for step in report.steps if not step.met]
    assert unmet == []
    assert {step.step_id for step in report.steps} == {"RT-01", "RT-02", "RT-03", "RT-04", "RT-05"}
    # The audit chain and the revocation record are retained on purpose.
    assert "audit_events" in retained_tables()
    assert "agent_capability_states" in retained_tables()
    assert "audit_events" not in deleted_tables()
    assert "action_proposals" in deleted_tables()


def test_the_audit_package_indexes_every_existing_artifact_and_states_what_is_open() -> None:
    package = build_audit_package(ROOT)

    assert package.complete, [artifact.path for artifact in package.missing]
    assert len(package.artifacts) >= 20
    assert all(len(artifact.sha256) == 64 for artifact in package.artifacts)
    # An audit package that lists only what passed would be marketing.
    assert package.open_blockers
    assert any("gate not met" in gate for gate in package.unmet_gates)


def test_generated_lifecycle_reports_are_committed_and_current(tmp_path: Path) -> None:
    package = json.loads((ROOT / "evidence/reports/M11-audit-package.json").read_text())
    retirement = json.loads((ROOT / "evidence/reports/M11-retirement.json").read_text())
    generated = run_retirement(tmp_path).to_dict()
    generated.pop("executed_at")
    retirement.pop("executed_at")

    assert retirement == generated
    assert package["summary"]["complete"] is True
    assert package["unmet_gates"]

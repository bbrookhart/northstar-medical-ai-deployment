from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from polaris.governance.traceability import (
    TraceabilityValidationError,
    build_report,
    check_reports,
    validate_repository,
)

ROOT = Path(__file__).resolve().parents[1]


def test_repository_traceability_is_complete() -> None:
    bundle = validate_repository(ROOT)
    report = build_report(ROOT, bundle)

    assert report["validation"] == {"status": "PASS", "issue_count": 0}
    summary = report["summary"]
    assert isinstance(summary, dict)
    assert summary["requirements"] == {
        "total": 70,
        "covered": 70,
        "coverage_percent": 100.0,
    }
    assert summary["risks"]["total"] == 25
    assert summary["risks"]["controlled"] == 25
    assert summary["scenarios"] == {
        "total": 78,
        "mapped": 78,
        "coverage_percent": 100.0,
        "by_prefix": {"HAZ": 14, "MIS": 24, "PRI": 10, "THR": 30},
    }


def test_checked_reports_are_deterministic_and_current() -> None:
    bundle = validate_repository(ROOT, require_generated_evidence=True)
    check_reports(ROOT, build_report(ROOT, bundle))


def test_validator_rejects_orphaned_requirement(tmp_path: Path) -> None:
    test_root = _copy_validation_inputs(tmp_path)
    catalog_path = test_root / "governance" / "control-library.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["controls"][0]["requirement_ids"].remove("REQ-GOV-001")
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    with pytest.raises(
        TraceabilityValidationError, match="Requirement has no control: REQ-GOV-001"
    ):
        validate_repository(test_root)


def test_validator_rejects_missing_verified_test(tmp_path: Path) -> None:
    test_root = _copy_validation_inputs(tmp_path)
    catalog_path = test_root / "governance" / "verification-catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["verifications"][0]["test_locations"] = [
        "tests/test_traceability.py::test_does_not_exist"
    ]
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    with pytest.raises(TraceabilityValidationError, match="Verified test does not exist"):
        validate_repository(test_root)


def _copy_validation_inputs(tmp_path: Path) -> Path:
    test_root = tmp_path / "repository"
    for name in ("governance", "docs", "src", "tests", "evidence", "training"):
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, test_root / name)
    for name in ("README.md", "PROJECT_STATUS.md", ".env.example", "uv.lock"):
        shutil.copy2(ROOT / name, test_root / name)
    (test_root / ".github").mkdir()
    shutil.copytree(ROOT / ".github", test_root / ".github", dirs_exist_ok=True)
    return test_root

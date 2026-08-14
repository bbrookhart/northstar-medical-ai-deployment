from __future__ import annotations

import json
from pathlib import Path

import pytest

from polaris.portfolio.claims import FindingKind, verify_claims

ROOT = Path(__file__).resolve().parents[1]


def test_every_portfolio_and_training_claim_traces_to_an_artifact() -> None:
    report = verify_claims(ROOT)

    assert report.passed, [
        f"{finding.kind.value} {finding.document}: {finding.detail}" for finding in report.findings
    ]
    assert len(report.documents) >= 8
    assert report.references >= 50


def test_the_material_covers_both_the_portfolio_and_the_training_package() -> None:
    report = verify_claims(ROOT)

    assert any(document.startswith("portfolio/") for document in report.documents)
    assert any(document.startswith("training/labs/") for document in report.documents)
    # The three worked labs are the ones claimed complete in the curriculum.
    labs = {document for document in report.documents if document.startswith("training/labs/")}
    assert len(labs) == 3


def test_an_unresolved_identifier_is_a_finding(tmp_path: Path) -> None:
    root = _scaffold(tmp_path, "portfolio/claim.md", "See EVD-ZZZ-999 for details.\n")

    report = verify_claims(root)

    assert not report.passed
    assert report.findings[0].kind is FindingKind.UNRESOLVED_REFERENCE
    assert "EVD-ZZZ-999" in report.findings[0].detail


def test_a_broken_link_is_a_finding(tmp_path: Path) -> None:
    root = _scaffold(tmp_path, "portfolio/claim.md", "See [the record](missing-file.md).\n")

    report = verify_claims(root)

    assert report.findings[0].kind is FindingKind.MISSING_LINK_TARGET


def test_an_undeclared_command_is_a_finding(tmp_path: Path) -> None:
    root = _scaffold(tmp_path, "portfolio/claim.md", "Run `make deploy-to-production` first.\n")

    report = verify_claims(root)

    assert report.findings[0].kind is FindingKind.UNKNOWN_MAKE_TARGET


def test_prose_mentioning_make_is_not_treated_as_a_command(tmp_path: Path) -> None:
    """The checker's own first run flagged "make and defend decisions" as a command."""

    root = _scaffold(
        tmp_path,
        "portfolio/claim.md",
        "Learners make and defend decisions about the system.\n",
    )

    assert verify_claims(root).passed


@pytest.mark.parametrize(
    "claim",
    [
        "The system is HIPAA compliant today.",
        "This deployment is production ready.",
        "The pipeline is certified by an external body.",
        "The result is a completely secure assistant.",
        "We accept zero risk in this configuration.",
        "After this change all gates pass.",
    ],
)
def test_overstated_claims_are_rejected(tmp_path: Path, claim: str) -> None:
    root = _scaffold(tmp_path, "portfolio/claim.md", f"{claim}\n")

    report = verify_claims(root)

    assert not report.passed
    assert report.findings[0].kind is FindingKind.PROHIBITED_CLAIM


@pytest.mark.parametrize(
    "sentence",
    [
        "This is not production ready.",
        "No claim of HIPAA compliance is made.",
        "The system is not certified by anyone.",
        "It does not process real patient data.",
    ],
)
def test_denying_a_claim_is_permitted(tmp_path: Path, sentence: str) -> None:
    """Banning the words outright would forbid the honest sentence and reward silence."""

    root = _scaffold(tmp_path, "portfolio/claim.md", f"{sentence}\n")

    assert verify_claims(root).passed


def test_the_generated_claims_report_is_committed_and_current() -> None:
    committed = json.loads((ROOT / "evidence/reports/M12-portfolio-claims.json").read_text())

    assert committed == verify_claims(ROOT).to_dict()
    assert committed["summary"]["passed"] is True


def _scaffold(tmp_path: Path, relative: str, content: str) -> Path:
    root = tmp_path / "repo"
    (root / "portfolio").mkdir(parents=True)
    (root / "training").mkdir(parents=True)
    (root / "governance").mkdir(parents=True)
    (root / "docs/architecture/decisions").mkdir(parents=True)
    (root / "docs/assurance/exceptions").mkdir(parents=True)
    (root / "Makefile").write_text("verify:\n\techo ok\n")
    catalogs: tuple[tuple[str, dict[str, list[object]]], ...] = (
        ("evidence-catalog.json", {"evidence": []}),
        ("verification-catalog.json", {"verifications": []}),
        ("control-library.json", {"controls": []}),
        ("traceability.json", {}),
    )
    for name, payload in catalogs:
        (root / "governance" / name).write_text(json.dumps(payload))
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return root

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

_REQUIREMENT_ROW = re.compile(r"^\|\s*(REQ-[A-Z]+-\d{3})\s*\|\s*([^|]+)\|", re.MULTILINE)
_RISK_ROW = re.compile(r"^\|\s*(RSK-\d{3})\s*\|", re.MULTILINE)
_SCENARIO_ROW = re.compile(
    r"^\|\s*((?:THR-\d{3}|PRI-\d{2}|MIS-\d{2}|HAZ-\d{2}))\s*\|", re.MULTILINE
)
_TEST_LOCATION = re.compile(r"^(tests/[A-Za-z0-9_/-]+\.py)::(test_[A-Za-z0-9_]+)$")

ControlId = Annotated[str, Field(pattern=r"^CTL-[A-Z]{2,4}-\d{3}$")]
RequirementId = Annotated[str, Field(pattern=r"^REQ-[A-Z]{2,4}-\d{3}$")]
RiskId = Annotated[str, Field(pattern=r"^RSK-\d{3}$")]
VerificationId = Annotated[str, Field(pattern=r"^VER-[A-Z]{3}-\d{3}$")]
EvidenceId = Annotated[str, Field(pattern=r"^EVD-[A-Z0-9]{2,4}-\d{3}$")]
FrameworkSourceId = Annotated[str, Field(pattern=r"^SRC-[A-Z0-9-]+$")]
FrameworkReferenceId = Annotated[str, Field(pattern=r"^FW-[A-Z0-9-]+$")]
ScenarioId = Annotated[str, Field(pattern=r"^(?:THR-\d{3}|PRI-\d{2}|MIS-\d{2}|HAZ-\d{2})$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrameworkSource(StrictModel):
    id: FrameworkSourceId
    title: str
    url: str
    status: Literal["reviewed", "provisional"]
    note: str


class FrameworkReference(StrictModel):
    id: FrameworkReferenceId
    source_id: FrameworkSourceId
    reference: str


class FrameworkCatalog(StrictModel):
    schema_version: str
    catalog_id: str
    as_of_date: str
    mapping_notice: str
    sources: list[FrameworkSource]
    references: list[FrameworkReference]


class Control(StrictModel):
    id: ControlId
    title: str
    objective: str
    owner: str
    status: Literal["implemented", "partial", "planned"]
    control_type: str
    frequency: str
    requirement_ids: list[RequirementId] = Field(min_length=1)
    risk_ids: list[RiskId] = Field(min_length=1)
    implementation_refs: list[str] = Field(min_length=1)
    verification_ids: list[VerificationId] = Field(min_length=1)
    evidence_ids: list[EvidenceId] = Field(min_length=1)
    framework_reference_ids: list[FrameworkReferenceId] = Field(min_length=1)


class ControlCatalog(StrictModel):
    schema_version: str
    catalog_id: str
    as_of_date: str
    status_definitions: dict[str, str]
    controls: list[Control]


class Verification(StrictModel):
    id: VerificationId
    title: str
    kind: Literal[
        "automated_test",
        "command",
        "document_review",
        "planned_test",
        "planned_exercise",
        "planned_review",
        "planned_study",
    ]
    status: Literal["verified", "planned"]
    owner: str
    test_locations: list[str] = Field(default_factory=list)
    artifact_refs: list[str] = Field(default_factory=list)
    command: str | None = None
    acceptance: str | None = None


class VerificationCatalog(StrictModel):
    schema_version: str
    catalog_id: str
    as_of_date: str
    verifications: list[Verification]


class Evidence(StrictModel):
    id: EvidenceId
    title: str
    status: Literal["existing", "generated", "planned"]
    owner: str
    scope: str
    artifact_path: str | None = None
    planned_artifact_path: str | None = None


class EvidenceCatalog(StrictModel):
    schema_version: str
    catalog_id: str
    as_of_date: str
    claim_rule: str
    evidence: list[Evidence]


class ScenarioSource(StrictModel):
    prefix: Literal["THR", "PRI", "MIS", "HAZ"]
    path: str


class RequirementFamily(StrictModel):
    prefix: str = Field(pattern=r"^REQ-[A-Z]{2,4}-$")
    owner: str
    lifecycle_phase: str
    disposition: Literal["implemented", "partial", "planned", "deferred"]
    risk_ids: list[RiskId] = Field(min_length=1)


class ScenarioLink(StrictModel):
    scenario_id: ScenarioId
    risk_ids: list[RiskId] = Field(min_length=1)


class GateBlocker(StrictModel):
    id: str = Field(pattern=r"^BLK-\d{3}$")
    title: str
    finding_id: str
    owner: str
    blocks: list[str] = Field(min_length=1)


class TraceabilityCatalog(StrictModel):
    schema_version: str
    catalog_id: str
    as_of_date: str
    requirement_sources: list[str] = Field(min_length=1)
    risk_sources: list[str] = Field(min_length=1)
    scenario_sources: list[ScenarioSource] = Field(min_length=1)
    requirement_families: list[RequirementFamily] = Field(min_length=1)
    scenario_links: list[ScenarioLink] = Field(min_length=1)
    open_gate_blockers: list[GateBlocker]


class CatalogBundle(StrictModel):
    frameworks: FrameworkCatalog
    controls: ControlCatalog
    verifications: VerificationCatalog
    evidence: EvidenceCatalog
    traceability: TraceabilityCatalog


class TraceabilityValidationError(ValueError):
    def __init__(self, issues: list[str]) -> None:
        self.issues = sorted(set(issues))
        super().__init__("Traceability validation failed:\n- " + "\n- ".join(self.issues))


def _load_model[T: BaseModel](path: Path, model: type[T]) -> T:
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def load_catalogs(root: Path) -> CatalogBundle:
    governance = root / "governance"
    return CatalogBundle(
        frameworks=_load_model(governance / "framework-registry.json", FrameworkCatalog),
        controls=_load_model(governance / "control-library.json", ControlCatalog),
        verifications=_load_model(governance / "verification-catalog.json", VerificationCatalog),
        evidence=_load_model(governance / "evidence-catalog.json", EvidenceCatalog),
        traceability=_load_model(governance / "traceability.json", TraceabilityCatalog),
    )


def _duplicates(values: list[str]) -> set[str]:
    counts = Counter(values)
    return {value for value, count in counts.items() if count > 1}


def _safe_repo_path(root: Path, relative_path: str) -> Path | None:
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts:
        return None
    candidate = (root / path).resolve()
    return candidate if candidate.is_relative_to(root.resolve()) else None


def _markdown_ids(root: Path, paths: list[str], pattern: re.Pattern[str]) -> set[str]:
    found: set[str] = set()
    for relative_path in paths:
        found.update(pattern.findall((root / relative_path).read_text(encoding="utf-8")))
    return found


def _requirement_statements(root: Path, paths: list[str]) -> dict[str, str]:
    statements: dict[str, str] = {}
    for relative_path in paths:
        text = (root / relative_path).read_text(encoding="utf-8")
        statements.update(
            {
                identifier: statement.strip()
                for identifier, statement in _REQUIREMENT_ROW.findall(text)
            }
        )
    return statements


def _risk_ratings(root: Path, paths: list[str]) -> dict[str, str]:
    ratings: dict[str, str] = {}
    for relative_path in paths:
        for line in (root / relative_path).read_text(encoding="utf-8").splitlines():
            parts = [part.strip() for part in line.strip().strip("|").split("|")]
            if parts and re.fullmatch(r"RSK-\d{3}", parts[0]) and len(parts) >= 6:
                score = int(parts[5])
                ratings[parts[0]] = (
                    "Critical"
                    if score >= 20
                    else "High"
                    if score >= 12
                    else "Moderate"
                    if score >= 6
                    else "Low"
                )
    return ratings


def _add_reference_issues(
    issues: list[str], *, label: str, declared: set[str], referenced: set[str]
) -> None:
    for missing in sorted(referenced - declared):
        issues.append(f"{label} references unknown ID {missing}")


def validate_repository(root: Path, *, require_generated_evidence: bool = False) -> CatalogBundle:
    bundle = load_catalogs(root)
    issues: list[str] = []
    controls = bundle.controls.controls
    verifications = bundle.verifications.verifications
    evidence = bundle.evidence.evidence
    references = bundle.frameworks.references
    sources = bundle.frameworks.sources
    trace = bundle.traceability

    id_groups = {
        "control": [item.id for item in controls],
        "verification": [item.id for item in verifications],
        "evidence": [item.id for item in evidence],
        "framework source": [item.id for item in sources],
        "framework reference": [item.id for item in references],
        "scenario link": [item.scenario_id for item in trace.scenario_links],
        "blocker": [item.id for item in trace.open_gate_blockers],
    }
    for label, identifiers in id_groups.items():
        for duplicate in sorted(_duplicates(identifiers)):
            issues.append(f"Duplicate {label} ID {duplicate}")

    source_paths = [
        *trace.requirement_sources,
        *trace.risk_sources,
        *(source.path for source in trace.scenario_sources),
    ]
    for source_path in source_paths:
        resolved = _safe_repo_path(root, source_path)
        if resolved is None or not resolved.is_file():
            issues.append(f"Catalog source path is unsafe or missing: {source_path}")
    if issues:
        raise TraceabilityValidationError(issues)

    requirements = set(_requirement_statements(root, trace.requirement_sources))
    risks = _markdown_ids(root, trace.risk_sources, _RISK_ROW)
    scenario_paths = [source.path for source in trace.scenario_sources]
    scenarios = _markdown_ids(root, scenario_paths, _SCENARIO_ROW)
    control_requirements = {item for control in controls for item in control.requirement_ids}
    control_risks = {item for control in controls for item in control.risk_ids}
    scenario_ids = {link.scenario_id for link in trace.scenario_links}

    for missing in sorted(requirements - control_requirements):
        issues.append(f"Requirement has no control: {missing}")
    for unknown in sorted(control_requirements - requirements):
        issues.append(f"Control references unknown requirement: {unknown}")
    for missing in sorted(risks - control_risks):
        issues.append(f"Risk has no control: {missing}")
    for unknown in sorted(control_risks - risks):
        issues.append(f"Control references unknown risk: {unknown}")
    for missing in sorted(scenarios - scenario_ids):
        issues.append(f"Scenario has no risk mapping: {missing}")
    for unknown in sorted(scenario_ids - scenarios):
        issues.append(f"Traceability references unknown scenario: {unknown}")

    families_for: dict[str, RequirementFamily] = {}
    for requirement in requirements:
        matches = [
            family for family in trace.requirement_families if requirement.startswith(family.prefix)
        ]
        if len(matches) != 1:
            issues.append(
                f"Requirement must match exactly one accountability family: {requirement}"
            )
        else:
            families_for[requirement] = matches[0]

    verification_by_id = {item.id: item for item in verifications}
    evidence_by_id = {item.id: item for item in evidence}
    reference_ids = {item.id for item in references}
    source_ids = {item.id for item in sources}
    _add_reference_issues(
        issues,
        label="Framework reference",
        declared=source_ids,
        referenced={item.source_id for item in references},
    )

    for control in controls:
        _add_reference_issues(
            issues,
            label=control.id,
            declared=set(verification_by_id),
            referenced=set(control.verification_ids),
        )
        _add_reference_issues(
            issues,
            label=control.id,
            declared=set(evidence_by_id),
            referenced=set(control.evidence_ids),
        )
        _add_reference_issues(
            issues,
            label=control.id,
            declared=reference_ids,
            referenced=set(control.framework_reference_ids),
        )
        for implementation_ref in control.implementation_refs:
            path = _safe_repo_path(root, implementation_ref)
            if path is None or not path.exists():
                issues.append(
                    f"{control.id} implementation reference is unsafe or missing: "
                    f"{implementation_ref}"
                )
        linked_verifications = [
            verification_by_id[item]
            for item in control.verification_ids
            if item in verification_by_id
        ]
        linked_evidence = [
            evidence_by_id[item] for item in control.evidence_ids if item in evidence_by_id
        ]
        if control.status == "implemented":
            if not any(item.status == "verified" for item in linked_verifications):
                issues.append(f"Implemented control lacks verified verification: {control.id}")
            if not any(item.status == "existing" for item in linked_evidence):
                issues.append(f"Implemented control lacks existing evidence: {control.id}")
        if control.status == "planned":
            if any(item.status != "planned" for item in linked_verifications):
                issues.append(f"Planned control claims verified verification: {control.id}")
            if any(item.status != "planned" for item in linked_evidence):
                issues.append(f"Planned control claims existing/generated evidence: {control.id}")

    _add_reference_issues(
        issues,
        label="Requirement family",
        declared=risks,
        referenced={risk for family in trace.requirement_families for risk in family.risk_ids},
    )
    _add_reference_issues(
        issues,
        label="Scenario link",
        declared=risks,
        referenced={risk for link in trace.scenario_links for risk in link.risk_ids},
    )

    for verification in verifications:
        if verification.status == "planned" and not verification.acceptance:
            issues.append(f"Planned verification lacks acceptance criteria: {verification.id}")
        if verification.status == "verified" and verification.kind == "automated_test":
            if not verification.test_locations:
                issues.append(f"Automated verification has no test location: {verification.id}")
            for location in verification.test_locations:
                match = _TEST_LOCATION.fullmatch(location)
                if not match:
                    issues.append(f"Invalid test location for {verification.id}: {location}")
                    continue
                test_path, function_name = match.groups()
                path = _safe_repo_path(root, test_path)
                if (
                    path is None
                    or not path.is_file()
                    or not re.search(
                        rf"^(?:async\s+)?def\s+{re.escape(function_name)}\s*\(",
                        path.read_text(encoding="utf-8") if path and path.is_file() else "",
                        re.MULTILINE,
                    )
                ):
                    issues.append(f"Verified test does not exist for {verification.id}: {location}")
        if verification.status == "verified" and verification.kind == "document_review":
            for artifact_ref in verification.artifact_refs:
                path = _safe_repo_path(root, artifact_ref)
                if path is None or not path.is_file():
                    issues.append(
                        f"Review artifact is unsafe or missing for {verification.id}: "
                        f"{artifact_ref}"
                    )
        if (
            verification.status == "verified"
            and verification.kind == "command"
            and not verification.command
        ):
            issues.append(f"Command verification has no command: {verification.id}")

    for item in evidence:
        if item.status in {"existing", "generated"} and not item.artifact_path:
            issues.append(f"{item.status.title()} evidence lacks artifact path: {item.id}")
        if (
            item.status == "existing"
            and item.artifact_path
            and ((path := _safe_repo_path(root, item.artifact_path)) is None or not path.is_file())
        ):
            issues.append(
                f"Existing evidence is unsafe or missing: {item.id} -> {item.artifact_path}"
            )
        if (
            require_generated_evidence
            and item.status == "generated"
            and item.artifact_path
            and ((path := _safe_repo_path(root, item.artifact_path)) is None or not path.is_file())
        ):
            issues.append(
                f"Generated evidence is unsafe or missing: {item.id} -> {item.artifact_path}"
            )
        if item.status == "planned" and not item.planned_artifact_path:
            issues.append(f"Planned evidence lacks intended path: {item.id}")

    ratings = _risk_ratings(root, trace.risk_sources)
    for risk_id, rating in ratings.items():
        if rating in {"Critical", "High"} and risk_id not in control_risks:
            issues.append(f"{rating} risk has no treatment control: {risk_id}")

    if issues:
        raise TraceabilityValidationError(issues)
    return bundle


def build_report(root: Path, bundle: CatalogBundle | None = None) -> dict[str, object]:
    bundle = bundle or validate_repository(root)
    trace = bundle.traceability
    statements = _requirement_statements(root, trace.requirement_sources)
    ratings = _risk_ratings(root, trace.risk_sources)
    controls = bundle.controls.controls
    links = bundle.traceability.scenario_links
    scenario_paths = [source.path for source in trace.scenario_sources]
    scenarios = _markdown_ids(root, scenario_paths, _SCENARIO_ROW)

    requirement_rows: list[dict[str, object]] = []
    for requirement_id in sorted(statements):
        family = next(
            item for item in trace.requirement_families if requirement_id.startswith(item.prefix)
        )
        linked_controls = [item for item in controls if requirement_id in item.requirement_ids]
        requirement_rows.append(
            {
                "requirement_id": requirement_id,
                "statement": statements[requirement_id],
                "owner": family.owner,
                "lifecycle_phase": family.lifecycle_phase,
                "disposition": family.disposition,
                "risk_ids": sorted({risk for item in linked_controls for risk in item.risk_ids}),
                "control_ids": sorted(item.id for item in linked_controls),
                "verification_ids": sorted(
                    {value for item in linked_controls for value in item.verification_ids}
                ),
                "evidence_ids": sorted(
                    {value for item in linked_controls for value in item.evidence_ids}
                ),
                "framework_reference_ids": sorted(
                    {value for item in linked_controls for value in item.framework_reference_ids}
                ),
            }
        )

    risk_rows: list[dict[str, object]] = []
    for risk_id in sorted(ratings):
        linked_controls = [item for item in controls if risk_id in item.risk_ids]
        risk_rows.append(
            {
                "risk_id": risk_id,
                "inherent_rating": ratings[risk_id],
                "control_ids": sorted(item.id for item in linked_controls),
                "requirement_ids": sorted(
                    {value for item in linked_controls for value in item.requirement_ids}
                ),
                "scenario_ids": sorted(
                    item.scenario_id for item in links if risk_id in item.risk_ids
                ),
            }
        )

    by_prefix = Counter(item.split("-", maxsplit=1)[0] for item in scenarios)
    return {
        "report_id": "NS-RPT-M03-001",
        "as_of_date": trace.as_of_date,
        "validation": {"status": "PASS", "issue_count": 0},
        "scope": (
            "Local synthetic-data simulation; not pilot, production, compliance certification, "
            "or clinical validation."
        ),
        "summary": {
            "requirements": {
                "total": len(statements),
                "covered": len(requirement_rows),
                "coverage_percent": 100.0,
            },
            "risks": {
                "total": len(ratings),
                "controlled": len(risk_rows),
                "coverage_percent": 100.0,
                "by_rating": dict(sorted(Counter(ratings.values()).items())),
            },
            "scenarios": {
                "total": len(scenarios),
                "mapped": len(links),
                "coverage_percent": 100.0,
                "by_prefix": dict(sorted(by_prefix.items())),
            },
            "controls": {
                "total": len(controls),
                "by_status": dict(sorted(Counter(item.status for item in controls).items())),
            },
            "verifications": {
                "total": len(bundle.verifications.verifications),
                "by_status": dict(
                    sorted(
                        Counter(item.status for item in bundle.verifications.verifications).items()
                    )
                ),
            },
            "evidence": {
                "total": len(bundle.evidence.evidence),
                "by_status": dict(
                    sorted(Counter(item.status for item in bundle.evidence.evidence).items())
                ),
            },
            "framework_sources": {
                "total": len(bundle.frameworks.sources),
                "by_status": dict(
                    sorted(Counter(item.status for item in bundle.frameworks.sources).items())
                ),
            },
            "open_gate_blockers": len(trace.open_gate_blockers),
        },
        "requirements": requirement_rows,
        "risks": risk_rows,
        "scenarios": [
            item.model_dump(mode="json")
            for item in sorted(links, key=lambda value: value.scenario_id)
        ],
        "controls": [
            item.model_dump(mode="json") for item in sorted(controls, key=lambda value: value.id)
        ],
        "open_gate_blockers": [item.model_dump(mode="json") for item in trace.open_gate_blockers],
    }


def render_markdown_report(report: dict[str, object]) -> str:
    summary = report["summary"]
    assert isinstance(summary, dict)
    requirements = report["requirements"]
    blockers = report["open_gate_blockers"]
    assert isinstance(requirements, list)
    assert isinstance(blockers, list)
    lines = [
        "# NS-RPT-M03-001 — M03 Traceability and Coverage Report",
        "",
        f"**As of:** {report['as_of_date']}  ",
        "**Validation:** PASS  ",
        f"**Scope:** {report['scope']}",
        "",
        "## Coverage",
        "",
        "| Domain | Covered | Total | Coverage |",
        "|---|---:|---:|---:|",
    ]
    for key, covered_key in (
        ("requirements", "covered"),
        ("risks", "controlled"),
        ("scenarios", "mapped"),
    ):
        value = summary[key]
        assert isinstance(value, dict)
        coverage = value["coverage_percent"]
        lines.append(
            f"| {key.title()} | {value[covered_key]} | {value['total']} | {coverage:.1f}% |"
        )
    controls = summary["controls"]
    assert isinstance(controls, dict)
    lines.extend(["", "## Control status", "", f"Total controls: **{controls['total']}**.", ""])
    control_status = controls["by_status"]
    assert isinstance(control_status, dict)
    for status, count in control_status.items():
        lines.append(f"- {status.title()}: {count}")
    lines.extend(
        [
            "",
            "Status is deliberately conservative: `planned` and `partial` controls "
            "are not implementation claims.",
            "",
            "## Open gate blockers",
            "",
            "| ID | Blocker | Owner | Blocks |",
            "|---|---|---|---|",
        ]
    )
    for blocker in blockers:
        assert isinstance(blocker, dict)
        blocked_gates = ", ".join(blocker["blocks"])
        lines.append(
            f"| {blocker['id']} | {blocker['title']} | {blocker['owner']} | {blocked_gates} |"
        )
    lines.extend(
        [
            "",
            "## Requirement traceability",
            "",
            "| Requirement | Owner | Disposition | Risks | Controls | Verification | Evidence |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for row in requirements:
        assert isinstance(row, dict)
        lines.append(
            f"| {row['requirement_id']} | {row['owner']} | {row['disposition']} | "
            f"{', '.join(row['risk_ids'])} | {', '.join(row['control_ids'])} | "
            f"{', '.join(row['verification_ids'])} | {', '.join(row['evidence_ids'])} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This report proves catalog completeness and reference integrity for the repository "
            "baseline. It does not prove that planned controls operate, that residual risk is "
            "accepted, or that Polaris is ready for real PHI, clinical use, pilot, or production. "
            "The JSON companion is the canonical machine-readable report.",
            "",
        ]
    )
    return "\n".join(lines)


def report_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def report_paths(root: Path) -> tuple[Path, Path]:
    output = root / "evidence" / "reports"
    return output / "M03-traceability-report.json", output / "M03-traceability-report.md"


def write_reports(root: Path, report: dict[str, object]) -> tuple[Path, Path]:
    json_path, markdown_path = report_paths(root)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(report_json(report), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    return json_path, markdown_path


def check_reports(root: Path, report: dict[str, object]) -> None:
    json_path, markdown_path = report_paths(root)
    expected = {json_path: report_json(report), markdown_path: render_markdown_report(report)}
    stale = [
        str(path.relative_to(root))
        for path, content in expected.items()
        if not path.exists() or path.read_text(encoding="utf-8") != content
    ]
    if stale:
        raise TraceabilityValidationError(
            [f"Generated report is missing or stale: {path}" for path in stale]
        )

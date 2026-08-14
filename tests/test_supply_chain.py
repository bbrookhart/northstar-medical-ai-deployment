from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from polaris.services.container import CORPUS_ID, CORPUS_VERSION
from polaris.supplychain.aibom import build_aibom
from polaris.supplychain.policy import Severity, evaluate_release_policy
from polaris.supplychain.sbom import SupplyChainError, build_sbom, render

ROOT = Path(__file__).resolve().parents[1]


def test_the_repository_passes_its_own_release_supply_chain_policy() -> None:
    report = evaluate_release_policy(ROOT)

    assert report.passed, [
        f"{finding.check} {finding.location}: {finding.detail}" for finding in report.blockers
    ]
    assert report.checked_files >= 3


def test_the_sbom_describes_the_lockfile_not_the_environment() -> None:
    document = build_sbom(ROOT)

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    components = document["components"]
    assert components
    # Every component carries a PURL and at least one pinned artifact hash.
    for component in components:
        assert component["purl"].startswith("pkg:pypi/")
        assert component["hashes"]
        assert all(entry["alg"] == "SHA-256" for entry in component["hashes"])
        assert all(len(entry["content"]) == 64 for entry in component["hashes"])
    names = {component["name"] for component in components}
    assert {"fastapi", "pydantic", "uvicorn", "pyjwt"} <= names
    # Direct dependencies are distinguishable from transitive ones.
    direct = {
        component["name"]
        for component in components
        if {"name": "polaris:direct", "value": "true"} in component["properties"]
    }
    assert "fastapi" in direct
    assert direct < names


def test_the_sbom_is_byte_stable_across_runs() -> None:
    assert render(build_sbom(ROOT)) == render(build_sbom(ROOT))


def test_the_sbom_rejects_an_unsupported_artifact_hash(tmp_path: Path) -> None:
    root = _copy_manifest_only(tmp_path)
    lock = root / "uv.lock"
    lock.write_text(lock.read_text().replace('hash = "sha256:', 'hash = "md5:', 1))

    with pytest.raises(SupplyChainError, match="Unsupported artifact hash"):
        build_sbom(root)


def test_the_aibom_describes_what_a_dependency_sbom_cannot() -> None:
    document = build_aibom(ROOT, corpus_id=CORPUS_ID, corpus_version=CORPUS_VERSION)

    model = document["models"][0]
    assert model["hosted"] is False
    assert model["provider_approved"] is False
    assert model["training_data"].startswith("none")
    assert len(model["system_contract_sha256"]) == 64

    serving = document["corpora"][0]
    assert serving["corpus_id"] == CORPUS_ID
    assert len(serving["manifest_sha256"]) == 64
    # The refused candidates and their reasons are part of the bill of materials.
    assert serving["rejected_count"] == len(serving["rejections"])
    assert {rejection["document_id"] for rejection in serving["rejections"]} >= {"POL-EXT-011"}
    assert serving["confidential_partition"] == ["POL-AUD-002"]

    tools = {tool["name"]: tool for tool in document["tools"]}
    assert set(tools) == {"policy.search", "patient.summary", "action.propose"}
    assert sum(1 for tool in tools.values() if tool["kind"] == "WRITE") == 1
    assert all(len(tool["arguments_schema_sha256"]) == 64 for tool in tools.values())

    assert document["bounds"]["cross_session_memory"] is False
    assert document["bounds"]["cost_control"] is None
    assert set(document["kill_switches"]) == {"MODEL", "READ", "WRITE"}
    assert document["evaluations"][0]["security_threshold"] == 1.0
    assert any("BLK-004" in entry for entry in document["not_included"])


def test_generated_supply_chain_documents_are_committed_and_current() -> None:
    sbom = json.loads((ROOT / "evidence/reports/M08-sbom.cdx.json").read_text())
    aibom = json.loads((ROOT / "evidence/reports/M08-aibom.json").read_text())

    assert sbom == build_sbom(ROOT)
    assert aibom == build_aibom(ROOT, corpus_id=CORPUS_ID, corpus_version=CORPUS_VERSION)


def test_an_unpinned_action_is_a_release_blocker(tmp_path: Path) -> None:
    root = _copy_repository(tmp_path)
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        workflow.read_text().replace("actions/checkout@3d3c42e", "actions/checkout@v4 #")
    )

    report = evaluate_release_policy(root)

    assert not report.passed
    assert any(finding.check == "pinned-actions" for finding in report.blockers)


def test_an_unpinned_container_image_is_a_release_blocker(tmp_path: Path) -> None:
    root = _copy_repository(tmp_path)
    compose = root / "infrastructure" / "local" / "compose.polaris.yml"
    compose.write_text(
        compose.read_text().replace("image: northstar-polaris:local", "image: python:3.13-slim")
    )

    report = evaluate_release_policy(root)

    assert any(
        finding.check == "pinned-images" and "python:3.13-slim" in finding.detail
        for finding in report.blockers
    )


def test_a_missing_container_control_is_a_release_blocker(tmp_path: Path) -> None:
    root = _copy_repository(tmp_path)
    compose = root / "infrastructure" / "local" / "compose.polaris.yml"
    compose.write_text(compose.read_text().replace("read_only: true", "read_only: false"))

    report = evaluate_release_policy(root)

    assert any(
        finding.check == "container-hardening" and "read-only" in finding.detail
        for finding in report.blockers
    )


def test_an_unbounded_requirement_is_a_release_blocker(tmp_path: Path) -> None:
    root = _copy_repository(tmp_path)
    manifest = root / "pyproject.toml"
    manifest.write_text(manifest.read_text().replace('"fastapi>=0.116,<1"', '"fastapi"'))

    report = evaluate_release_policy(root)

    assert any(
        finding.check == "bounded-requirements" and "fastapi" in finding.detail
        for finding in report.blockers
    )


def test_a_tracked_secret_marker_is_a_release_blocker(tmp_path: Path) -> None:
    root = _copy_repository(tmp_path)
    # Built from parts so this test file does not itself contain a scanned marker.
    marker = "AK" + "IA" + "IOSFODNN7EXAMPLE"
    (root / "docs" / "leaked.md").write_text(f"Deploy with {marker} as the key id.\n")

    report = evaluate_release_policy(root)

    assert any(
        finding.check == "no-tracked-secrets" and finding.location == "docs/leaked.md"
        for finding in report.blockers
    )


def test_policy_findings_separate_blockers_from_warnings() -> None:
    report = evaluate_release_policy(ROOT)

    assert all(finding.severity in set(Severity) for finding in report.findings)
    assert report.blockers == ()


def _copy_repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy2(ROOT / name, root / name)
    for directory in (".github", "infrastructure", "docs"):
        shutil.copytree(ROOT / directory, root / directory)
    return root


def _copy_manifest_only(tmp_path: Path) -> Path:
    root = tmp_path / "manifest"
    root.mkdir()
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy2(ROOT / name, root / name)
    return root

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

# A tag is mutable. Only a full commit SHA pins a GitHub Action to reviewed code.
_ACTION_USE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<ref>\S+)", re.MULTILINE)
_ACTION_SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_IMAGE_LINE = re.compile(r"^\s*(?:image:\s*|FROM\s+)(?P<image>\S+)", re.MULTILINE)
# An image built from a Dockerfile in this repository cannot be digest-pinned before it exists.
# The convention is that such images carry the exact tag ":local", which is checked rather than
# assumed: any other tag is treated as a pulled artifact and must be digest-pinned.
_LOCALLY_BUILT = re.compile(r"^[a-z0-9][a-z0-9._-]*:local$")
_UNPINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9._-]+(?:\[[^\]]+\])?\s*$")

# Markers that must never appear in tracked files. Detector modules carry the same list as a
# control, so they are excluded by path rather than by weakening the rule.
_SECRET_MARKERS: tuple[str, ...] = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "aws_access_key_id",
    "ghp_",
    "github_pat_",
    "AKIA",
)
# Only the detector modules are excluded, because each necessarily contains the marker list it
# searches for. No test or documentation file is exempt: a fixture that needs a marker builds it
# from parts so the scan stays honest.
_SECRET_SCAN_EXCLUDED = frozenset(
    {
        "src/polaris/data/synthetic.py",
        "src/polaris/services/corpus.py",
        "src/polaris/supplychain/policy.py",
        "src/polaris/agent/validators.py",
    }
)

_REQUIRED_CONTAINER_CONTROLS: tuple[tuple[str, str], ...] = (
    ("USER ", "runs as a non-root user"),
    ("--no-install-recommends", "installs no recommended packages"),
)
_REQUIRED_COMPOSE_CONTROLS: tuple[tuple[str, str], ...] = (
    ("read_only: true", "read-only root filesystem"),
    ("no-new-privileges:true", "no-new-privileges"),
    ("cap_drop:", "dropped Linux capabilities"),
    ("mem_limit:", "bounded memory"),
    ("pids_limit:", "bounded process count"),
    ("127.0.0.1:", "loopback-only published ports"),
)


class Severity(StrEnum):
    BLOCKER = "BLOCKER"
    WARNING = "WARNING"


@dataclass(frozen=True, slots=True)
class Finding:
    check: str
    severity: Severity
    location: str
    detail: str


@dataclass(frozen=True, slots=True)
class PolicyReport:
    findings: tuple[Finding, ...]
    checked_files: int

    @property
    def blockers(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.findings if finding.severity is Severity.BLOCKER)

    @property
    def passed(self) -> bool:
        return not self.blockers


def evaluate_release_policy(root: Path) -> PolicyReport:
    """Check the supply-chain properties a release must hold, deterministically and offline.

    Everything here is decidable from the repository itself. Vulnerability scanning needs a live
    advisory feed and is deliberately not in this gate — a check that fails when an external service
    is unavailable teaches people to bypass the gate.
    """

    findings: list[Finding] = []
    checked = 0

    for workflow in sorted((root / ".github" / "workflows").glob("*.yml")):
        checked += 1
        findings.extend(_check_pinned_actions(workflow, root))

    for path in _container_definitions(root):
        checked += 1
        findings.extend(_check_pinned_images(path, root))

    findings.extend(_check_dependency_pinning(root))
    findings.extend(_check_container_hardening(root))
    findings.extend(_check_tracked_secrets(root))

    return PolicyReport(findings=tuple(findings), checked_files=checked)


def _check_pinned_actions(workflow: Path, root: Path) -> Iterator[Finding]:
    text = workflow.read_text()
    for match in _ACTION_USE.finditer(text):
        reference = match.group("ref").strip("'\"")
        if reference.startswith("./") or reference.startswith("docker://"):
            continue
        if not _ACTION_SHA.match(reference):
            yield Finding(
                check="pinned-actions",
                severity=Severity.BLOCKER,
                location=str(workflow.relative_to(root)),
                detail=f"{reference} is not pinned to a 40-character commit SHA",
            )


def _check_pinned_images(path: Path, root: Path) -> Iterator[Finding]:
    text = path.read_text()
    builds_locally = "build:" in text
    for match in _IMAGE_LINE.finditer(text):
        image = match.group("image").strip("'\"")
        if image.startswith("${") or image in {"scratch"}:
            continue
        if builds_locally and _LOCALLY_BUILT.match(image):
            continue
        if not _IMAGE_DIGEST.match(image):
            yield Finding(
                check="pinned-images",
                severity=Severity.BLOCKER,
                location=str(path.relative_to(root)),
                detail=f"{image} is not pinned to a sha256 digest",
            )


def _check_dependency_pinning(root: Path) -> Iterator[Finding]:
    lock = root / "uv.lock"
    if not lock.is_file():
        yield Finding(
            check="locked-dependencies",
            severity=Severity.BLOCKER,
            location="uv.lock",
            detail="the lockfile is missing",
        )
        return

    with (root / "pyproject.toml").open("rb") as handle:
        project: dict[str, Any] = tomllib.load(handle)
    declared = list(project["project"].get("dependencies", []))
    for group in project.get("dependency-groups", {}).values():
        declared.extend(group)
    for requirement in declared:
        if _UNPINNED_REQUIREMENT.match(str(requirement)):
            yield Finding(
                check="bounded-requirements",
                severity=Severity.BLOCKER,
                location="pyproject.toml",
                detail=f"{requirement} declares no version bound",
            )

    with lock.open("rb") as handle:
        locked: dict[str, Any] = tomllib.load(handle)
    for package in locked.get("package", []):
        if package.get("source", {}).get("registry") is None and "editable" not in package.get(
            "source", {}
        ):
            yield Finding(
                check="locked-dependencies",
                severity=Severity.WARNING,
                location="uv.lock",
                detail=f"{package.get('name')} has no registry source",
            )
        if not package.get("wheels") and not package.get("sdist"):
            if package.get("source", {}).get("editable") is not None:
                continue
            yield Finding(
                check="locked-dependencies",
                severity=Severity.BLOCKER,
                location="uv.lock",
                detail=f"{package.get('name')} has no hashed artifact",
            )


def _check_container_hardening(root: Path) -> Iterator[Finding]:
    dockerfile = root / "infrastructure" / "container" / "Dockerfile"
    if not dockerfile.is_file():
        yield Finding(
            check="container-hardening",
            severity=Severity.BLOCKER,
            location="infrastructure/container/Dockerfile",
            detail="the application container definition is missing",
        )
    else:
        text = dockerfile.read_text()
        for marker, description in _REQUIRED_CONTAINER_CONTROLS:
            if marker not in text:
                yield Finding(
                    check="container-hardening",
                    severity=Severity.BLOCKER,
                    location="infrastructure/container/Dockerfile",
                    detail=f"the image does not declare that it {description}",
                )

    for compose in sorted((root / "infrastructure" / "local").glob("compose.*.yml")):
        text = compose.read_text()
        for marker, description in _REQUIRED_COMPOSE_CONTROLS:
            if marker not in text:
                yield Finding(
                    check="container-hardening",
                    severity=Severity.BLOCKER,
                    location=str(compose.relative_to(root)),
                    detail=f"the service does not declare {description}",
                )


def _check_tracked_secrets(root: Path) -> Iterator[Finding]:
    for path in _tracked_text_files(root):
        relative = str(path.relative_to(root))
        if relative in _SECRET_SCAN_EXCLUDED:
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for marker in _SECRET_MARKERS:
            if marker in text:
                yield Finding(
                    check="no-tracked-secrets",
                    severity=Severity.BLOCKER,
                    location=relative,
                    detail=f"contains the marker {marker!r}",
                )


def _container_definitions(root: Path) -> list[Path]:
    paths = sorted((root / "infrastructure").rglob("compose.*.yml"))
    dockerfile = root / "infrastructure" / "container" / "Dockerfile"
    if dockerfile.is_file():
        paths.append(dockerfile)
    return paths


def _tracked_text_files(root: Path) -> Iterator[Path]:
    skip = {".git", ".venv", ".uv-cache", "artifacts", "__pycache__", ".mypy_cache", ".ruff_cache"}
    suffixes = {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".cfg", ".ini", ".txt", ""}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if any(part in skip for part in path.relative_to(root).parts):
            continue
        yield path

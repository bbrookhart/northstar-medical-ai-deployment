from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class PackagedArtifact:
    evidence_id: str
    title: str
    status: str
    owner: str
    path: str
    present: bool
    sha256: str
    bytes: int


@dataclass(frozen=True, slots=True)
class AuditPackage:
    """An index an assessor can sample from, rather than a claim that evidence exists."""

    artifacts: tuple[PackagedArtifact, ...]
    controls: int
    verifications: int
    open_blockers: tuple[str, ...]
    unmet_gates: tuple[str, ...]

    @property
    def missing(self) -> tuple[PackagedArtifact, ...]:
        return tuple(artifact for artifact in self.artifacts if not artifact.present)

    @property
    def complete(self) -> bool:
        return not self.missing

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "artifacts": len(self.artifacts),
                "present": sum(1 for artifact in self.artifacts if artifact.present),
                "missing": len(self.missing),
                "controls": self.controls,
                "verifications": self.verifications,
                "complete": self.complete,
                "note": (
                    "This index lets an assessor sample evidence and confirm each artifact exists "
                    "at a known digest. It is not an assurance opinion, and a complete index does "
                    "not mean the gates it references passed."
                ),
            },
            "open_blockers": list(self.open_blockers),
            "unmet_gates": list(self.unmet_gates),
            "artifacts": [
                {
                    "evidence_id": artifact.evidence_id,
                    "title": artifact.title,
                    "status": artifact.status,
                    "owner": artifact.owner,
                    "path": artifact.path,
                    "present": artifact.present,
                    "sha256": artifact.sha256,
                    "bytes": artifact.bytes,
                }
                for artifact in self.artifacts
            ],
        }


def build_audit_package(root: Path) -> AuditPackage:
    """Assemble every existing evidence artifact with its digest, plus what is still open.

    An audit package that lists only what passed is marketing. The open blockers and unmet gates are
    part of the package because they are what an assessor would ask about first.
    """

    evidence = json.loads((root / "governance/evidence-catalog.json").read_text())
    controls = json.loads((root / "governance/control-library.json").read_text())
    verifications = json.loads((root / "governance/verification-catalog.json").read_text())
    traceability = json.loads((root / "governance/traceability.json").read_text())

    artifacts: list[PackagedArtifact] = []
    for entry in evidence["evidence"]:
        if entry["status"] not in {"existing", "generated"}:
            continue
        relative = str(entry["artifact_path"])
        path = root / relative
        present = path.is_file()
        payload = path.read_bytes() if present else b""
        artifacts.append(
            PackagedArtifact(
                evidence_id=entry["id"],
                title=entry["title"],
                status=entry["status"],
                owner=entry["owner"],
                path=relative,
                present=present,
                sha256=hashlib.sha256(payload).hexdigest() if present else "",
                bytes=len(payload),
            )
        )
    artifacts.sort(key=lambda artifact: artifact.evidence_id)

    blockers = tuple(
        str(blocker.get("id", blocker)) if isinstance(blocker, dict) else str(blocker)
        for blocker in traceability.get("open_gate_blockers", [])
    )
    return AuditPackage(
        artifacts=tuple(artifacts),
        controls=len(controls["controls"]),
        verifications=len(verifications["verifications"]),
        open_blockers=blockers,
        unmet_gates=_unmet_gates(root),
    )


def _unmet_gates(root: Path) -> tuple[str, ...]:
    """Read the gate record rather than restating it, so the package cannot disagree with it."""

    text = (root / "docs/assurance/release-gates.md").read_text()
    unmet: list[str] = []
    milestone = ""
    for line in text.splitlines():
        if line.startswith("## Current gate assessment"):
            milestone = line.rsplit("—", 1)[-1].strip()
        if line.startswith("**Decision:**") and milestone:
            if "Fail" in line or "not met" in line:
                unmet.append(f"{milestone}: gate not met")
            elif "Conditional" in line:
                unmet.append(f"{milestone}: conditional pass")
    return tuple(unmet)

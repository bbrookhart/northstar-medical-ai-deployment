from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

# Identifier shapes used across the repository. A portfolio claim cites one of these, and the
# verifier resolves it against the catalogs rather than trusting the prose.
_REFERENCE = re.compile(
    r"\b(?P<ref>"
    r"EVD-[A-Z0-9]+-\d{3}"
    r"|VER-[A-Z]{3}-\d{3}"
    r"|CTL-[A-Z]{3}-\d{3}"
    r"|REQ-[A-Z]{3}-\d{3}"
    r"|RSK-\d{3}"
    r"|BLK-\d{3}"
    r"|NS-EXC-\d{3}"
    r"|ADR-\d{3}"
    r"|RT-[A-Z]{3}-\d{3}"
    r"|GD-\d{2}"
    r"|RT-F\d"
    r"|RE-F\d"
    r")\b"
)
_MAKE_TARGET = re.compile(r"\bmake\s+(?P<target>[a-z][a-z0-9-]*)\b")
# Commands are only recognised inside code spans and fenced blocks. Prose such as "make and
# defend decisions" is not an instruction, and treating it as one produced a false positive on
# the first run of this check.
_CODE_SPAN = re.compile(r"`{3}[^`]*`{3}|`[^`\n]+`")
_MAKE_DECLARATION = re.compile(r"^(?P<target>[a-z][a-z0-9-]*):", re.MULTILINE)
_MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\((?P<target>[^)#\s]+)(?:#[^)]*)?\)")

# Language that would overstate what this repository establishes. The program's own rules forbid
# claiming compliance, certification, clearance, or production readiness, so the portfolio is
# checked for those words rather than trusted to avoid them.
_PROHIBITED_CLAIMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("compliance", re.compile(r"\bHIPAA[-\s]?compliant\b", re.I)),
    ("compliance", re.compile(r"\bfully\s+compliant\b", re.I)),
    ("certification", re.compile(r"\b(?:is\s+)?certified\b", re.I)),
    ("clearance", re.compile(r"\bFDA[-\s]?(?:cleared|approved)\b", re.I)),
    ("readiness", re.compile(r"\bproduction[-\s]?ready\b", re.I)),
    ("readiness", re.compile(r"\benterprise[-\s]?ready\b", re.I)),
    ("absolute-security", re.compile(r"\b(?:completely|fully|totally)\s+secure\b", re.I)),
    ("absolute-security", re.compile(r"\bunhackable|\bimpenetrable\b", re.I)),
    ("absolute-risk", re.compile(r"\bzero\s+risk\b", re.I)),
    ("gate-overstatement", re.compile(r"\ball\s+gates?\s+(?:pass|passed|green)\b", re.I)),
    ("real-data", re.compile(r"\breal\s+(?:patient|PHI)\b", re.I)),
)


class FindingKind(StrEnum):
    UNRESOLVED_REFERENCE = "UNRESOLVED_REFERENCE"
    MISSING_LINK_TARGET = "MISSING_LINK_TARGET"
    UNKNOWN_MAKE_TARGET = "UNKNOWN_MAKE_TARGET"
    PROHIBITED_CLAIM = "PROHIBITED_CLAIM"


@dataclass(frozen=True, slots=True)
class ClaimFinding:
    kind: FindingKind
    document: str
    detail: str


@dataclass(frozen=True, slots=True)
class ClaimsReport:
    documents: tuple[str, ...]
    references: int
    findings: tuple[ClaimFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "documents": len(self.documents),
                "resolved_references": self.references,
                "findings": len(self.findings),
                "passed": self.passed,
                "note": (
                    "Every identifier cited in the portfolio and training material resolves to a "
                    "catalog entry, every linked file exists, every documented command is a real "
                    "make target, and no prohibited claim language appears. This checks that "
                    "claims are traceable and bounded; it does not evaluate whether the material "
                    "teaches well."
                ),
            },
            "documents": list(self.documents),
            "findings": [
                {"kind": finding.kind.value, "document": finding.document, "detail": finding.detail}
                for finding in self.findings
            ],
        }


def verify_claims(root: Path) -> ClaimsReport:
    """Check that portfolio and training claims trace to artifacts rather than to confidence."""

    known = _known_identifiers(root)
    targets = _make_targets(root)
    documents = _documents(root)

    findings: list[ClaimFinding] = []
    resolved = 0
    for path in documents:
        relative = str(path.relative_to(root))
        text = path.read_text()

        for match in _REFERENCE.finditer(text):
            reference = match.group("ref")
            if reference in known:
                resolved += 1
            else:
                findings.append(
                    ClaimFinding(
                        kind=FindingKind.UNRESOLVED_REFERENCE,
                        document=relative,
                        detail=f"{reference} is not in any catalog or decision record",
                    )
                )

        for match in _MARKDOWN_LINK.finditer(text):
            target = match.group("target")
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (path.parent / target).resolve().exists():
                findings.append(
                    ClaimFinding(
                        kind=FindingKind.MISSING_LINK_TARGET,
                        document=relative,
                        detail=f"{target} does not exist",
                    )
                )

        code = "\n".join(span.group(0) for span in _CODE_SPAN.finditer(text))
        for match in _MAKE_TARGET.finditer(code):
            target = match.group("target")
            if target not in targets:
                findings.append(
                    ClaimFinding(
                        kind=FindingKind.UNKNOWN_MAKE_TARGET,
                        document=relative,
                        detail=f"'make {target}' is not a declared target",
                    )
                )

        for label, pattern in _PROHIBITED_CLAIMS:
            for match in pattern.finditer(text):
                if _is_negated(text, match.start()):
                    continue
                findings.append(
                    ClaimFinding(
                        kind=FindingKind.PROHIBITED_CLAIM,
                        document=relative,
                        detail=f"{label}: {match.group(0)!r}",
                    )
                )

    return ClaimsReport(
        documents=tuple(str(path.relative_to(root)) for path in documents),
        references=resolved,
        findings=tuple(findings),
    )


def _is_negated(text: str, position: int) -> bool:
    """Allow the phrase when the sentence is denying it, which is how this repository uses it.

    "This is not production ready" and "no claim of HIPAA compliance" are exactly the statements the
    program requires, so a naive keyword ban would forbid the honest sentence and permit silence.
    """

    window = text[max(0, position - 90) : position].lower()
    return any(
        marker in window
        for marker in (
            " not ",
            " never ",
            " no ",
            " nor ",
            " cannot ",
            " without ",
            " neither ",
            "does not",
            "is not",
            "are not",
            "must not",
            "unsupported",
            "prohibited",
            "forbid",
            "refus",
            "avoid",
            "claim",
        )
    )


def _documents(root: Path) -> tuple[Path, ...]:
    paths: list[Path] = []
    for directory in ("portfolio", "training"):
        paths.extend(sorted((root / directory).rglob("*.md")))
    return tuple(paths)


def _known_identifiers(root: Path) -> frozenset[str]:
    known: set[str] = set()

    # Scan the whole catalog rather than only its primary keys, so requirement, risk, and
    # scenario identifiers referenced by controls resolve too.
    for name in (
        "governance/evidence-catalog.json",
        "governance/verification-catalog.json",
        "governance/control-library.json",
        "governance/traceability.json",
    ):
        known.update(_identifiers_in(json.loads((root / name).read_text())))

    # Case identifiers live in generated reports, so a cited attack or drill must have run.
    for report, container, field in (
        ("evidence/reports/M09-red-team.json", "cases", "case_id"),
        ("evidence/reports/M10-game-day.json", "drills", "drill_id"),
    ):
        path = root / report
        if path.is_file():
            payload = json.loads(path.read_text())
            known.update(str(entry[field]) for entry in payload.get(container, []))

    # Findings are enumerated in the remediation ledger.
    ledger = root / "docs/assurance/M09-remediation-ledger.md"
    if ledger.is_file():
        known.update(match.group("ref") for match in _REFERENCE.finditer(ledger.read_text()))

    for decision in (root / "docs/architecture/decisions").glob("ADR-*.md"):
        known.add(decision.name.split("-")[0] + "-" + decision.name.split("-")[1])
    for exception in (root / "docs/assurance/exceptions").glob("NS-EXC-*.md"):
        known.add("-".join(exception.name.split("-")[:3]))

    return frozenset(known)


def _identifiers_in(payload: object) -> Iterator[str]:
    if isinstance(payload, str):
        for match in _REFERENCE.finditer(payload):
            yield match.group("ref")
    elif isinstance(payload, dict):
        for key, value in payload.items():
            yield from _identifiers_in(key)
            yield from _identifiers_in(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _identifiers_in(item)


def _make_targets(root: Path) -> frozenset[str]:
    text = (root / "Makefile").read_text()
    return frozenset(match.group("target") for match in _MAKE_DECLARATION.finditer(text))

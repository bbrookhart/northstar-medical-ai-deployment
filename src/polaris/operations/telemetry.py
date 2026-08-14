from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from polaris.domain import AuditEvent

# What each event family must carry for an investigator to reconstruct a decision. Correlation,
# actor, outcome, and time are on every event by construction; these are the additional keys that
# make a specific decision explicable.
_REQUIRED_METADATA: MappingProxyType[str, frozenset[str]] = MappingProxyType(
    {
        "policy.query": frozenset({"purpose", "policy_version", "corpus_version"}),
        "patient.read": frozenset({"patient_id", "purpose", "policy_version", "consent_decision"}),
        "action.propose": frozenset({"patient_id", "action_type", "policy_version"}),
        "action.preview": frozenset({"proposal_id", "policy_version"}),
        "agent.run": frozenset({"run_id", "model_id", "corpus_version"}),
        "corpus.activate": frozenset({"corpus_id", "version", "manifest_checksum"}),
        "agent.capability": frozenset({"capability", "sequence"}),
    }
)

# Content that must never reach telemetry. Free-text clinical detail, credentials, and raw retrieved
# passages are the three ways an audit trail turns into a disclosure of its own.
_PROHIBITED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("credential", re.compile(r"\b(?:bearer\s+[A-Za-z0-9._-]{8,}|client_secret|api_key)\b", re.I)),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")),
    ("context-envelope", re.compile(r"<<<UNTRUSTED_SOURCE|UNTRUSTED_SOURCE>>>")),
    ("markup", re.compile(r"</?(?:script|iframe|img)\b", re.I)),
    (
        "date-of-birth",
        re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}T?\d{0,2}[^\s]*\s*(?:dob|birth)", re.I),
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

# A metadata value long enough to be a passage rather than an identifier or a decision code.
_MAX_METADATA_VALUE = 200


@dataclass(frozen=True, slots=True)
class TelemetryFinding:
    sequence: int
    event_type: str
    rule: str
    detail: str


def validate_events(events: Iterable[AuditEvent]) -> tuple[TelemetryFinding, ...]:
    """Check that audit events are explicable and carry nothing they should not.

    Both directions matter. An event missing its policy version cannot be investigated; an event
    carrying a retrieved passage or a credential has turned the audit trail into its own disclosure.
    """

    findings: list[TelemetryFinding] = []
    for event in events:
        required = _REQUIRED_METADATA.get(event.event_type)
        if required is not None:
            missing = sorted(required - set(event.metadata))
            if missing:
                findings.append(
                    TelemetryFinding(
                        sequence=event.sequence,
                        event_type=event.event_type,
                        rule="required-context",
                        detail=f"missing {','.join(missing)}",
                    )
                )
        for key, value in sorted(event.metadata.items()):
            if len(value) > _MAX_METADATA_VALUE:
                findings.append(
                    TelemetryFinding(
                        sequence=event.sequence,
                        event_type=event.event_type,
                        rule="bounded-value",
                        detail=f"{key} is {len(value)} characters",
                    )
                )
            for rule, pattern in _PROHIBITED_PATTERNS:
                if pattern.search(value):
                    findings.append(
                        TelemetryFinding(
                            sequence=event.sequence,
                            event_type=event.event_type,
                            rule=f"prohibited-{rule}",
                            detail=f"in metadata key {key}",
                        )
                    )
    return tuple(findings)


def required_metadata(event_type: str) -> frozenset[str]:
    return _REQUIRED_METADATA.get(event_type, frozenset())


def covered_event_types() -> tuple[str, ...]:
    return tuple(sorted(_REQUIRED_METADATA))


def summarize(findings: Sequence[TelemetryFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule] = counts.get(finding.rule, 0) + 1
    return counts

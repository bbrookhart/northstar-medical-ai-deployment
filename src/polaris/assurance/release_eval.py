from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from polaris.assurance.redteam import CampaignReport

MANIFEST_VERSION = "2026.08.14"


class DimensionStatus(StrEnum):
    """`NOT_ASSESSED` is a first-class result. A dimension with no evidence says so."""

    ASSESSED = "ASSESSED"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True, slots=True)
class Dimension:
    """One evaluation dimension `REQ-SDL-003` requires, with where its evidence lives."""

    name: str
    status: DimensionStatus
    threshold: str
    evidence: tuple[str, ...]
    note: str


# Statuses are declared, not inferred. Deriving "assessed" from the presence of tests would let a
# thin test suite claim a dimension, which is the failure mode this manifest exists to prevent.
_DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        name="function",
        status=DimensionStatus.ASSESSED,
        threshold="All default-suite tests pass; coverage at or above the 85% floor",
        evidence=("make verify", "EVD-M04-003", "EVD-M08-001"),
        note="Functional behavior of the deterministic stack only.",
    ),
    Dimension(
        name="authorization",
        status=DimensionStatus.ASSESSED,
        threshold=(
            "Zero unauthorized cross-patient, cross-role, cross-facility, or cross-purpose access"
        ),
        evidence=("VER-AUT-004", "VER-AUT-005", "VER-AGT-002", "VER-SDL-003"),
        note="Deterministic policy engine, retrieval partition, and agent boundary.",
    ),
    Dimension(
        name="privacy",
        status=DimensionStatus.PARTIAL,
        threshold="No prohibited content in logs, audit, or model context",
        evidence=("VER-AGT-002", "VER-PRS-001", "EVD-M04-001"),
        note=(
            "Minimization and disclosure controls are tested. No DPIA re-review against a real "
            "data flow, and authoritative Consent remains a fixture (NS-EXC-001)."
        ),
    ),
    Dimension(
        name="security",
        status=DimensionStatus.ASSESSED,
        threshold="Zero uncontained critical or high red-team cases across all required classes",
        evidence=("VER-SDL-003", "EVD-M09-001"),
        note="Against the deterministic stack; no campaign against a hosted provider.",
    ),
    Dimension(
        name="safety",
        status=DimensionStatus.PARTIAL,
        threshold=(
            "No clinical direction produced or accepted; emergency language routes to a human "
            "channel"
        ),
        evidence=("VER-SAF-001", "VER-AGT-002", "EVD-M07-001"),
        note=(
            "Boundary and routing are enforced and tested. No clinician-reviewed adversarial suite "
            "and no clinical validation (BLK-003)."
        ),
    ),
    Dimension(
        name="grounding",
        status=DimensionStatus.ASSESSED,
        threshold=(
            "Security cases 100% and quality cases at or above 90% on the retrieval golden set"
        ),
        evidence=("VER-RAG-004", "EVD-M05-002"),
        note="Deterministic keyword retrieval; says nothing about model answer quality.",
    ),
    Dimension(
        name="robustness",
        status=DimensionStatus.PARTIAL,
        threshold="Malformed, oversized, obfuscated, and hostile inputs fail closed",
        evidence=("VER-SDL-003", "VER-RAG-001", "VER-AUT-029"),
        note=(
            "Input-handling robustness is tested. No fuzzing campaign and no load-driven fault "
            "injection."
        ),
    ),
    Dimension(
        name="accessibility",
        status=DimensionStatus.NOT_ASSESSED,
        threshold=(
            "WCAG 2.2 AA with no serious or critical violations, verified with assistive technology"
        ),
        evidence=("VER-PLN-011",),
        note="No interface exists and no session has been run (BLK-003).",
    ),
    Dimension(
        name="performance",
        status=DimensionStatus.NOT_ASSESSED,
        threshold="Approved latency and throughput objectives under representative load",
        evidence=(),
        note="No load testing, no objectives, and no deployment to measure.",
    ),
    Dimension(
        name="cost",
        status=DimensionStatus.NOT_ASSESSED,
        threshold="Bounded spend per run and per tenant with an approved ceiling",
        evidence=(),
        note="No metered provider is connected, so there is nothing to measure or bound.",
    ),
    Dimension(
        name="recovery",
        status=DimensionStatus.NOT_ASSESSED,
        threshold=(
            "Measured RTO and RPO with executed failover, restore, and reconciliation exercises"
        ),
        evidence=("NS-EXC-004", "docs/operations/persistence-recovery-exercises.md"),
        note="Six exercises are specified with pass criteria; none has been executed.",
    ),
)

_BLOCKING_DIMENSIONS = frozenset({"authorization", "security", "grounding"})


@dataclass(frozen=True, slots=True)
class ReleaseEvaluation:
    manifest_version: str
    campaign: CampaignReport
    dimensions: tuple[Dimension, ...] = _DIMENSIONS

    @property
    def unassessed(self) -> tuple[Dimension, ...]:
        return tuple(
            dimension
            for dimension in self.dimensions
            if dimension.status is DimensionStatus.NOT_ASSESSED
        )

    @property
    def blocking_gaps(self) -> tuple[str, ...]:
        """Unassessed blocking dimensions, plus any uncontained critical or high attack."""

        gaps = [
            dimension.name
            for dimension in self.dimensions
            if dimension.name in _BLOCKING_DIMENSIONS
            and dimension.status is not DimensionStatus.ASSESSED
        ]
        gaps.extend(result.case_id for result in self.campaign.blocking_failures)
        return tuple(gaps)

    @property
    def release_ready(self) -> bool:
        """A release requires no blocking gap *and* no unassessed dimension.

        The distinction matters: this evaluation can pass its blocking checks while still being
        unfit to release, because accessibility, performance, cost, and recovery have no evidence at
        all. Reporting a single "ready" boolean without that separation is how a partial evaluation
        gets read as a complete one.
        """

        return not self.blocking_gaps and not self.unassessed

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "manifest_version": self.manifest_version,
            "campaign_version": self.campaign.campaign_version,
            "corpus_version": self.campaign.corpus_version,
            "dimensions": [
                {
                    "name": dimension.name,
                    "status": dimension.status.value,
                    "threshold": dimension.threshold,
                    "evidence": list(dimension.evidence),
                    "note": dimension.note,
                }
                for dimension in self.dimensions
            ],
            "red_team": {
                "cases": len(self.campaign.results),
                "containment_rate": round(self.campaign.containment_rate, 4),
                "blocking_failures": [result.case_id for result in self.campaign.blocking_failures],
                "classes_covered": sorted(
                    attack_class.value for attack_class in self.campaign.covered_classes
                ),
            },
            "decision": {
                "blocking_gaps": list(self.blocking_gaps),
                "unassessed_dimensions": [dimension.name for dimension in self.unassessed],
                "release_ready": self.release_ready,
            },
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def build_release_evaluation(campaign: CampaignReport) -> ReleaseEvaluation:
    return ReleaseEvaluation(manifest_version=MANIFEST_VERSION, campaign=campaign)

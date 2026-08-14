from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum

from polaris.domain import AuditEvent


class DetectionCategory(StrEnum):
    """The categories `REQ-OPS-003` requires detection to cover."""

    IDENTITY_ABUSE = "IDENTITY_ABUSE"
    ENUMERATION = "ENUMERATION"
    CROSS_SCOPE = "CROSS_SCOPE"
    INJECTION_CANARY = "INJECTION_CANARY"
    POISON_CANARY = "POISON_CANARY"
    DATA_LOSS = "DATA_LOSS"
    ABNORMAL_VOLUME = "ABNORMAL_VOLUME"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    DRIFT = "DRIFT"
    CONTROL_DISABLEMENT = "CONTROL_DISABLEMENT"


class DetectionSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    category: DetectionCategory
    severity: DetectionSeverity
    count: int
    first_sequence: int
    last_sequence: int
    summary: str


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """One detection expressed as code over the audit stream.

    Rules read the same tamper-evident events an investigator would, so a detection that fires can
    always be traced to the records that produced it. Thresholds are engineering defaults for this
    simulation, not tuned production values — `LIM-017` records that they have never been exercised
    against real traffic.
    """

    rule_id: str
    category: DetectionCategory
    severity: DetectionSeverity
    description: str
    threshold: int
    window: timedelta
    matches: Callable[[AuditEvent], bool]

    def evaluate(self, events: Sequence[AuditEvent]) -> Detection | None:
        matched = [event for event in events if self.matches(event)]
        if len(matched) < self.threshold:
            return None
        # Only count matches inside the window ending at the most recent match, so an old cluster
        # does not keep a rule permanently lit.
        newest = max(event.occurred_at for event in matched)
        in_window = [event for event in matched if newest - event.occurred_at <= self.window]
        if len(in_window) < self.threshold:
            return None
        return Detection(
            rule_id=self.rule_id,
            category=self.category,
            severity=self.severity,
            count=len(in_window),
            first_sequence=min(event.sequence for event in in_window),
            last_sequence=max(event.sequence for event in in_window),
            summary=f"{len(in_window)} matching events within {self.window}",
        )


def _outcome_in(*outcomes: str) -> Callable[[AuditEvent], bool]:
    wanted = frozenset(outcomes)
    return lambda event: event.outcome in wanted


def _outcome_contains(fragment: str) -> Callable[[AuditEvent], bool]:
    return lambda event: fragment in event.outcome


def _agent_refusal(reason: str) -> Callable[[AuditEvent], bool]:
    return lambda event: (
        event.event_type == "agent.run"
        and event.outcome in {"AGENT_RUN_REFUSED", "AGENT_RUN_FAILED"}
        and event.metadata.get("detail") == reason
    )


RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        rule_id="DET-001",
        category=DetectionCategory.IDENTITY_ABUSE,
        severity=DetectionSeverity.CRITICAL,
        description="Repeated authentication or revocation failures for one actor",
        threshold=3,
        window=timedelta(minutes=10),
        matches=_outcome_contains("IDENTITY_SIGNAL_REJECTED"),
    ),
    DetectionRule(
        rule_id="DET-002",
        category=DetectionCategory.ENUMERATION,
        severity=DetectionSeverity.WARNING,
        description="Repeated patient reads denied, consistent with identifier enumeration",
        threshold=3,
        window=timedelta(minutes=5),
        matches=lambda event: (
            event.event_type == "patient.read" and event.outcome != "PATIENT_READ_ALLOWED"
        ),
    ),
    DetectionRule(
        rule_id="DET-003",
        category=DetectionCategory.CROSS_SCOPE,
        severity=DetectionSeverity.CRITICAL,
        description="Action proposals denied across facility, purpose, or assignment scope",
        threshold=2,
        window=timedelta(minutes=10),
        matches=lambda event: (
            event.event_type == "action.propose" and event.outcome.endswith("_DENIED")
        ),
    ),
    DetectionRule(
        rule_id="DET-004",
        category=DetectionCategory.INJECTION_CANARY,
        severity=DetectionSeverity.CRITICAL,
        description="Agent runs refused for fabricated citations or unknown tools",
        threshold=1,
        window=timedelta(minutes=15),
        matches=lambda event: (
            event.event_type == "agent.run"
            and event.metadata.get("detail") in {"FABRICATED_CITATION", "UNKNOWN_TOOL"}
        ),
    ),
    DetectionRule(
        rule_id="DET-005",
        category=DetectionCategory.POISON_CANARY,
        severity=DetectionSeverity.CRITICAL,
        description="A corpus activation whose manifest differs from the approved one",
        threshold=1,
        window=timedelta(hours=24),
        matches=lambda event: (
            event.event_type == "corpus.activate" and event.outcome == "CORPUS_ROLLED_BACK"
        ),
    ),
    DetectionRule(
        rule_id="DET-006",
        category=DetectionCategory.DATA_LOSS,
        severity=DetectionSeverity.CRITICAL,
        description="Model output withheld for secret or context-envelope disclosure",
        threshold=1,
        window=timedelta(minutes=15),
        matches=_agent_refusal("SENSITIVE_DISCLOSURE"),
    ),
    DetectionRule(
        rule_id="DET-007",
        category=DetectionCategory.ABNORMAL_VOLUME,
        severity=DetectionSeverity.WARNING,
        description="Unusual volume of action proposals in a short window",
        threshold=5,
        window=timedelta(minutes=5),
        matches=lambda event: event.event_type == "action.propose",
    ),
    DetectionRule(
        rule_id="DET-008",
        category=DetectionCategory.RESOURCE_EXHAUSTION,
        severity=DetectionSeverity.WARNING,
        description="Agent runs halted on a resource budget",
        threshold=2,
        window=timedelta(minutes=10),
        matches=_outcome_in("AGENT_RUN_HALTED"),
    ),
    DetectionRule(
        rule_id="DET-009",
        category=DetectionCategory.DRIFT,
        severity=DetectionSeverity.CRITICAL,
        description="Continuous-access stream state drifted, stalled, or failed recovery",
        threshold=1,
        window=timedelta(hours=1),
        matches=lambda event: (
            event.event_type == "identity.gap_recovery"
            and event.outcome in {"GAP_INCIDENT_OPENED", "GAP_RECOVERY_EXIT_DENIED"}
        ),
    ),
    DetectionRule(
        rule_id="DET-010",
        category=DetectionCategory.CONTROL_DISABLEMENT,
        severity=DetectionSeverity.CRITICAL,
        description="An agent capability kill switch was disabled",
        threshold=1,
        window=timedelta(hours=24),
        matches=_outcome_in("AGENT_CAPABILITY_DISABLED"),
    ),
)


def evaluate_detections(
    events: Sequence[AuditEvent],
    rules: Sequence[DetectionRule] = RULES,
) -> tuple[Detection, ...]:
    fired = [detection for rule in rules if (detection := rule.evaluate(events)) is not None]
    return tuple(sorted(fired, key=lambda detection: detection.rule_id))


def covered_categories(rules: Sequence[DetectionRule] = RULES) -> frozenset[DetectionCategory]:
    return frozenset(rule.category for rule in rules)

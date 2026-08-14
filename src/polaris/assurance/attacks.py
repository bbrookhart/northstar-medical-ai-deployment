from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AttackClass(StrEnum):
    """The classes `REQ-SDL-004` requires an adversarial campaign to cover."""

    DIRECT_INJECTION = "DIRECT_INJECTION"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    STORED_INJECTION = "STORED_INJECTION"
    OBFUSCATED_INJECTION = "OBFUSCATED_INJECTION"
    MULTILINGUAL_INJECTION = "MULTILINGUAL_INJECTION"
    ENCODED_INJECTION = "ENCODED_INJECTION"
    EXFILTRATION = "EXFILTRATION"
    POISONING = "POISONING"
    TOOL_ABUSE = "TOOL_ABUSE"
    IDENTITY_ABUSE = "IDENTITY_ABUSE"
    ACTION_MUTATION = "ACTION_MUTATION"
    ACTION_REPLAY = "ACTION_REPLAY"
    OUTPUT_INJECTION = "OUTPUT_INJECTION"
    CONSUMPTION = "CONSUMPTION"


class Severity(StrEnum):
    """Severity if the attack succeeded, not of the attempt."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


BLOCKING_SEVERITIES: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})


@dataclass(frozen=True, slots=True)
class AttackCase:
    """One attack, and the control that is supposed to stop it.

    Naming the expected control is what makes a result reviewable. "Contained" is not enough: if a
    case is stopped somewhere other than where the design says, the design is wrong even though the
    test is green.
    """

    case_id: str
    attack_class: AttackClass
    severity: Severity
    technique: str
    expected_control: str


@dataclass(frozen=True, slots=True)
class AttackResult:
    case_id: str
    attack_class: AttackClass
    severity: Severity
    contained: bool
    control: str
    detail: str

    @property
    def expected_control_held(self) -> bool:
        return self.contained

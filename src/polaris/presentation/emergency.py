from __future__ import annotations

import re
from dataclasses import dataclass

from polaris.security.text import normalize_untrusted_text

# Phrases that mean the person may be describing an emergency. This list exists to *stop* the
# system, not to grade the situation.
_EMERGENCY_PHRASES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:emergency|urgent(?:ly)?|right\s+now|immediately)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:chest\s+pain|can'?t\s+breathe|not\s+breathing|unconscious|unresponsive)\b", re.I
    ),
    re.compile(r"\b(?:bleeding|stroke|seizure|overdose|suicidal|self[-\s]?harm)\b", re.IGNORECASE),
    re.compile(r"\b(?:call\s+911|ambulance|code\s+blue|rapid\s+response)\b", re.IGNORECASE),
    re.compile(r"\b(?:dying|life[-\s]?threatening|deteriorating\s+fast)\b", re.IGNORECASE),
)

FIXED_EMERGENCY_GUIDANCE = (
    "This assistant cannot help with urgent or emergency situations and cannot assess how "
    "serious a situation is. Use the established Northstar emergency channels now: call the "
    "in-facility emergency number or the rapid response line, or call your local emergency "
    "services. Do not wait for a response here."
)


@dataclass(frozen=True, slots=True)
class EmergencyOutcome:
    """The fixed response. There is deliberately no severity, triage level, or confidence.

    `REQ-SAF-002` requires established-channel guidance and prohibits the system from assessing
    urgency, so this type has nowhere to record an assessment even if a future caller wanted one.
    """

    triggered: bool
    guidance: str = ""


def check_emergency_language(text: str) -> EmergencyOutcome:
    """Return the fixed guidance when emergency language appears, and nothing else.

    A match means "stop and route to a human channel". It does not mean the situation is severe,
    and a non-match does not mean it is safe — the system is not permitted to make either judgement.
    """

    normalized, _ = normalize_untrusted_text(text)
    if any(pattern.search(normalized) for pattern in _EMERGENCY_PHRASES):
        return EmergencyOutcome(triggered=True, guidance=FIXED_EMERGENCY_GUIDANCE)
    return EmergencyOutcome(triggered=False)

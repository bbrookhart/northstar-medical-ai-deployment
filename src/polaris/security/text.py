from __future__ import annotations

import re
import unicodedata

_INVISIBLE_CODEPOINTS = re.compile("[\u200b\u200c\u200d\u2060\ufe00-\ufe0f\U000e0000-\U000e007f]")
_WHITESPACE = re.compile(r"\s+")
_CLINICAL_ACTION_PATTERNS = (
    re.compile(r"\bdiagnos(?:e|is|tic)\b", re.IGNORECASE),
    re.compile(r"\bprescrib(?:e|ing)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:increase|decrease|change|start|stop)\s+(?:the\s+)?(?:dose|medication)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:mg|milligram|mcg)\b", re.IGNORECASE),
    re.compile(r"\btriage\b", re.IGNORECASE),
)


def normalize_untrusted_text(value: str) -> tuple[str, bool]:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = _INVISIBLE_CODEPOINTS.sub("", normalized)
    normalized = _WHITESPACE.sub(" ", normalized).strip()
    return normalized, normalized != value


def contains_prohibited_clinical_action(value: str) -> bool:
    normalized, _ = normalize_untrusted_text(value)
    return any(pattern.search(normalized) for pattern in _CLINICAL_ACTION_PATTERNS)

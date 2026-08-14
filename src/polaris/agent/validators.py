from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from polaris.agent.model import ModelIntent
from polaris.domain import AgentIntentKind, AgentRefusalReason, RetrievedChunk
from polaris.security.text import contains_prohibited_clinical_action, normalize_untrusted_text

# Markers that must never appear in output regardless of where the model got them.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:client_secret|api_key|aws_access_key_id|password)\s*[:=]", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."),
)
_ENVELOPE_LEAK = re.compile(r"<<<UNTRUSTED_SOURCE|UNTRUSTED_SOURCE>>>")


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    accepted: bool
    reason: AgentRefusalReason | None = None
    detail: str = ""


def validate_answer(
    intent: ModelIntent,
    *,
    retrieved: Sequence[RetrievedChunk],
    max_characters: int,
) -> ValidationOutcome:
    """Validate model output before any of it is used.

    Order matters. Structure and size are checked before content so an oversized or malformed answer
    cannot exhaust a downstream check, and grounding is checked before disclosure so an ungrounded
    answer is refused on the cheaper, more specific reason.
    """

    if intent.kind is not AgentIntentKind.ANSWER:
        return ValidationOutcome(accepted=True)

    answer, _ = normalize_untrusted_text(intent.answer)
    if not answer:
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.UNGROUNDED_ANSWER,
            detail="empty answer",
        )
    if len(answer) > max_characters:
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.OVERSIZED_OUTPUT,
            detail=f"{len(answer)} characters",
        )

    allowed_chunk_ids = {chunk.chunk_id for chunk in retrieved}
    if not intent.cited_chunk_ids:
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.UNGROUNDED_ANSWER,
            detail="no citation supplied",
        )
    fabricated = sorted(set(intent.cited_chunk_ids) - allowed_chunk_ids)
    if fabricated:
        # A citation the retriever never returned is either invented or points at something the
        # caller was not authorized to see. Both are refusals, not warnings.
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.FABRICATED_CITATION,
            detail=",".join(fabricated),
        )

    if _ENVELOPE_LEAK.search(answer) or any(pattern.search(answer) for pattern in _SECRET_PATTERNS):
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.SENSITIVE_DISCLOSURE,
            detail="secret or context-envelope marker in output",
        )
    if contains_prohibited_clinical_action(answer):
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.PROHIBITED_CLINICAL_CONTENT,
            detail="clinical direction in output",
        )
    return ValidationOutcome(accepted=True)


def validate_proposal_summary(summary: str) -> ValidationOutcome:
    """Model-drafted action text gets the same disclosure and clinical checks as an answer.

    `ActionService.propose` independently rejects clinical content; this check exists so the refusal
    is attributed to the agent boundary and recorded before a proposal is ever attempted.
    """

    normalized, _ = normalize_untrusted_text(summary)
    if any(pattern.search(normalized) for pattern in _SECRET_PATTERNS):
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.SENSITIVE_DISCLOSURE,
            detail="secret marker in proposed summary",
        )
    if contains_prohibited_clinical_action(normalized):
        return ValidationOutcome(
            accepted=False,
            reason=AgentRefusalReason.PROHIBITED_CLINICAL_CONTENT,
            detail="clinical direction in proposed summary",
        )
    return ValidationOutcome(accepted=True)

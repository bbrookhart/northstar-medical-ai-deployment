from __future__ import annotations

from polaris.domain import (
    Citation,
    PolicyQueryResponse,
    Principal,
    PurposeOfUse,
    RetrievalOutcome,
)
from polaris.errors import AuthorizationError
from polaris.security.policy import PolicyEngine
from polaris.security.text import normalize_untrusted_text
from polaris.services.audit import AuditLedger
from polaris.services.secure_retrieval import CorpusRegistry, RetrievalResult

_ABSTAIN_NO_MATCH = (
    "I could not find an approved source that answers this question. "
    "Use the established policy escalation process."
)
_ABSTAIN_CONFLICT = (
    "Approved sources disagree on this topic, so I cannot give a single answer. "
    "Review the cited sources and follow the policy conflict escalation process."
)


class PolicyRetrievalService:
    """Grounded policy answers drawn from the serving corpus version.

    Authorization runs twice and in this order: the policy engine decides whether this principal may
    query at all, and the index then decides which chunks that principal may see before any text is
    scored. The service never sees an unauthorized chunk, so it cannot leak one.
    """

    def __init__(
        self,
        registry: CorpusRegistry,
        policy: PolicyEngine,
        audit: AuditLedger,
        *,
        max_chunks: int = 3,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._audit = audit
        self._max_chunks = max_chunks

    def query(
        self,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        question: str,
        correlation_id: str,
    ) -> PolicyQueryResponse:
        decision = self._policy.policy_query(principal, purpose)
        if not decision.allowed:
            self._audit.append(
                actor=principal.subject,
                event_type="policy.query",
                outcome=decision.code,
                correlation_id=correlation_id,
                metadata={"purpose": purpose.value, "policy_version": decision.policy_version},
            )
            raise AuthorizationError(decision.code)

        index = self._registry.active_index()
        result = index.search(
            principal=principal,
            question=question,
            max_chunks=self._max_chunks,
        )
        answer = _answer(result)
        citations = _citations(result)

        self._audit.append(
            actor=principal.subject,
            event_type="policy.query",
            outcome=_outcome_code(result.outcome),
            correlation_id=correlation_id,
            metadata={
                "document_ids": ",".join(sorted({chunk.document_id for chunk in result.chunks})),
                "chunk_ids": ",".join(chunk.chunk_id for chunk in result.chunks),
                "corpus_version": result.corpus_version,
                "manifest_checksum": result.manifest_checksum,
                "candidates_scanned": str(result.candidates_scanned),
                "conflicting_topics": ",".join(result.conflicting_topics),
                "input_normalized": str(result.normalized_input).lower(),
                "purpose": purpose.value,
                "policy_version": decision.policy_version,
            },
        )
        return PolicyQueryResponse(
            answer=answer,
            citations=citations,
            abstained=result.outcome is not RetrievalOutcome.ANSWERED,
            normalized_input=result.normalized_input,
        )


def _answer(result: RetrievalResult) -> str:
    if result.outcome is RetrievalOutcome.ABSTAINED_NO_MATCH:
        return _ABSTAIN_NO_MATCH
    if result.outcome is RetrievalOutcome.ABSTAINED_CONFLICT:
        return _ABSTAIN_CONFLICT
    sources = ", ".join(
        sorted({f"{chunk.document_id} v{chunk.document_version}" for chunk in result.chunks})
    )
    return (
        f"Approved Northstar sources relevant to this question are {sources}. "
        "Review the cited excerpts and source documents before acting."
    )


def _citations(result: RetrievalResult) -> list[Citation]:
    citations: list[Citation] = []
    seen: set[str] = set()
    for chunk in result.chunks:
        if chunk.document_id in seen:
            continue
        seen.add(chunk.document_id)
        citations.append(
            Citation(
                document_id=chunk.document_id,
                title=chunk.document_title,
                version=chunk.document_version,
                excerpt=_excerpt(chunk.text),
            )
        )
    return citations


def _outcome_code(outcome: RetrievalOutcome) -> str:
    if outcome is RetrievalOutcome.ANSWERED:
        return "POLICY_QUERY_ANSWERED"
    if outcome is RetrievalOutcome.ABSTAINED_CONFLICT:
        return "POLICY_QUERY_ABSTAINED_CONFLICT"
    return "POLICY_QUERY_ABSTAINED"


def _excerpt(value: str, limit: int = 300) -> str:
    normalized, _ = normalize_untrusted_text(value)
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 1].rstrip()}…"

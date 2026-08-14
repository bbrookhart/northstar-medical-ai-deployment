from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from polaris.domain import (
    Citation,
    PolicyDocument,
    PolicyQueryResponse,
    Principal,
    PurposeOfUse,
)
from polaris.errors import AuthorizationError
from polaris.security.policy import PolicyEngine
from polaris.security.text import normalize_untrusted_text
from polaris.services.audit import AuditLedger

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "for",
    "how",
    "i",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "to",
    "what",
    "where",
    "which",
    "who",
}


def _document(
    *, document_id: str, title: str, version: str, content: str, roles: set[str]
) -> PolicyDocument:
    checksum = hashlib.sha256(content.encode()).hexdigest()
    return PolicyDocument(
        document_id=document_id,
        title=title,
        version=version,
        classification="INTERNAL",
        allowed_roles=frozenset(roles),
        approved=True,
        content=content,
        checksum=checksum,
    )


def seed_policy_documents() -> tuple[PolicyDocument, ...]:
    workforce = {"care_coordinator", "nurse", "compliance_analyst"}
    return (
        _document(
            document_id="POL-AI-001",
            title="Workforce Use of Polaris",
            version="2026.08.11",
            roles=workforce,
            content=(
                "Polaris may be used for approved policy retrieval and non-clinical administrative "
                "support. Users must review cited sources. Polaris must not diagnose, prescribe, "
                "recommend treatment, or independently communicate with patients."
            ),
        ),
        _document(
            document_id="POL-CC-014",
            title="Care Coordination Follow-up Tasks",
            version="2026.07.15",
            roles={"care_coordinator", "nurse"},
            content=(
                "A routine follow-up task must identify the assigned patient, approved facility, "
                "care-coordination queue, due date, and administrative purpose. An authorized "
                "independent approver must review the exact task before execution."
            ),
        ),
        _document(
            document_id="POL-PRIV-007",
            title="Minimum Necessary Administrative Access",
            version="2026.06.30",
            roles=workforce,
            content=(
                "Workforce access must be limited to the information needed for the approved "
                "purpose. Role, facility, patient relationship, purpose of use, and sensitivity "
                "restrictions "
                "must be evaluated before information is returned."
            ),
        ),
    )


class PolicyRetrievalService:
    def __init__(
        self,
        documents: Iterable[PolicyDocument],
        policy: PolicyEngine,
        audit: AuditLedger,
    ) -> None:
        self._documents = tuple(documents)
        self._policy = policy
        self._audit = audit

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

        normalized_question, changed = normalize_untrusted_text(question)
        query_terms = _terms(normalized_question)
        candidates: list[tuple[int, PolicyDocument]] = []
        for document in self._documents:
            if not document.approved or not principal.roles & document.allowed_roles:
                continue
            score = len(query_terms & _terms(f"{document.title} {document.content}"))
            if score:
                candidates.append((score, document))
        candidates.sort(key=lambda pair: (-pair[0], pair[1].document_id))

        selected = [document for _, document in candidates[:2]]
        citations = [
            Citation(
                document_id=document.document_id,
                title=document.title,
                version=document.version,
                excerpt=_excerpt(document.content),
            )
            for document in selected
        ]
        if not selected:
            answer = (
                "I could not find an approved source that answers this question. "
                "Use the established policy escalation process."
            )
            abstained = True
        else:
            source_list = ", ".join(
                f"{document.document_id} v{document.version}" for document in selected
            )
            answer = (
                f"Approved Northstar sources relevant to this question are {source_list}. "
                "Review the cited excerpts and source documents before acting."
            )
            abstained = False

        self._audit.append(
            actor=principal.subject,
            event_type="policy.query",
            outcome="POLICY_QUERY_ABSTAINED" if abstained else "POLICY_QUERY_ANSWERED",
            correlation_id=correlation_id,
            metadata={
                "document_ids": ",".join(document.document_id for document in selected),
                "input_normalized": str(changed).lower(),
                "purpose": purpose.value,
                "policy_version": decision.policy_version,
            },
        )
        return PolicyQueryResponse(
            answer=answer,
            citations=citations,
            abstained=abstained,
            normalized_input=changed,
        )


def _terms(value: str) -> set[str]:
    return {
        token
        for token in _TOKEN.findall(value.casefold())
        if len(token) >= 3 and token not in _STOP_WORDS
    }


def _excerpt(value: str, limit: int = 300) -> str:
    normalized, _ = normalize_untrusted_text(value)
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 1].rstrip()}…"

from __future__ import annotations

from collections.abc import Sequence

from polaris.domain import Citation, RetrievalOutcome
from polaris.presentation.rendering import contains_active_content, render_inert
from polaris.presentation.views import AnswerView, Severity, SourceView, UncertaintyView

_ABSTENTION_LABELS: dict[RetrievalOutcome, str] = {
    RetrievalOutcome.ANSWERED: "Drafted from the cited approved sources. Verify before acting.",
    RetrievalOutcome.ABSTAINED_NO_MATCH: (
        "No approved source answers this. Nothing was drafted; use the policy escalation process."
    ),
    RetrievalOutcome.ABSTAINED_CONFLICT: (
        "Approved sources disagree on this topic, so no single answer was drafted. "
        "Review both sources and follow the policy conflict escalation process."
    ),
}


def build_answer_view(
    *,
    answer: str,
    citations: Sequence[Citation],
    outcome: RetrievalOutcome,
    corpus_version: str,
    generated_by: str,
    conflicting_topics: Sequence[str] = (),
    source_references: Sequence[str] = (),
) -> AnswerView:
    """Assemble an answer with its provenance and limits attached inseparably.

    Uncertainty is a required field, not an optional annotation a surface may drop. An abstention
    that renders as a confident answer is the failure this type exists to prevent, so the model
    refuses to construct a non-abstained view with no sources.
    """

    abstained = outcome is not RetrievalOutcome.ANSWERED
    references = list(source_references) + [""] * max(0, len(citations) - len(source_references))
    sources = tuple(
        SourceView(
            document_id=citation.document_id,
            title=citation.title,
            version=citation.version,
            excerpt=render_inert(citation.excerpt),
            source_reference=references[index] or f"{citation.document_id} v{citation.version}",
            contains_active_content=contains_active_content(citation.excerpt),
        )
        for index, citation in enumerate(citations)
    )
    return AnswerView(
        answer=render_inert(answer, limit=4_000) if answer else "",
        sources=sources,
        uncertainty=UncertaintyView(
            abstained=abstained,
            label=_ABSTENTION_LABELS[outcome],
            conflicting_topics=tuple(conflicting_topics),
        ),
        corpus_version=corpus_version,
        generated_by=generated_by,
        severity=Severity.CAUTION if abstained else Severity.INFO,
        text_alternative=_text_alternative(outcome, sources),
    )


def _text_alternative(outcome: RetrievalOutcome, sources: tuple[SourceView, ...]) -> str:
    lead = _ABSTENTION_LABELS[outcome]
    if not sources:
        return f"{lead} No sources were cited."[:500]
    listed = "; ".join(f"{source.document_id} version {source.version}" for source in sources)
    return f"{lead} Cited sources: {listed}."[:500]

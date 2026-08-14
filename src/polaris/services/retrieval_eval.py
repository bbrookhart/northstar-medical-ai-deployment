from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from polaris.domain import CorpusSource, Principal, RetrievalOutcome
from polaris.services.audit import utc_now
from polaris.services.corpus import CorpusIngestionService, seed_corpus_sources
from polaris.services.secure_retrieval import RetrievalResult, SecureRetrievalIndex

EVALUATION_CORPUS_ID = "northstar-policy-eval"
EVALUATION_CORPUS_VERSION = "2026.08.14-eval"

# Security invariants admit no partial credit. Quality thresholds are engineering targets for a
# deterministic keyword baseline and are not a claim about model or RAG answer quality.
SECURITY_PASS_RATE = 1.0
QUALITY_PASS_RATE = 0.9


class EvaluationKind(StrEnum):
    GROUNDED = "GROUNDED"
    UNANSWERABLE = "UNANSWERABLE"
    CONFLICT = "CONFLICT"
    AUTHORIZATION = "AUTHORIZATION"
    POISON_CANARY = "POISON_CANARY"


SECURITY_KINDS = frozenset({EvaluationKind.AUTHORIZATION, EvaluationKind.POISON_CANARY})


@dataclass(frozen=True, slots=True)
class EvaluationCase:
    case_id: str
    kind: EvaluationKind
    question: str
    roles: frozenset[str]
    expected_document_ids: frozenset[str] = frozenset()
    forbidden_document_ids: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    kind: EvaluationKind
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    corpus_id: str
    corpus_version: str
    manifest_checksum: str
    evaluated_at: str
    results: tuple[CaseResult, ...]

    @property
    def security_results(self) -> tuple[CaseResult, ...]:
        return tuple(result for result in self.results if result.kind in SECURITY_KINDS)

    @property
    def quality_results(self) -> tuple[CaseResult, ...]:
        return tuple(result for result in self.results if result.kind not in SECURITY_KINDS)

    @property
    def security_pass_rate(self) -> float:
        return _pass_rate(self.security_results)

    @property
    def quality_pass_rate(self) -> float:
        return _pass_rate(self.quality_results)

    @property
    def meets_thresholds(self) -> bool:
        return (
            self.security_pass_rate >= SECURITY_PASS_RATE
            and self.quality_pass_rate >= QUALITY_PASS_RATE
        )

    def to_json(self) -> str:
        payload = {
            "corpus_id": self.corpus_id,
            "corpus_version": self.corpus_version,
            "manifest_checksum": self.manifest_checksum,
            "evaluated_at": self.evaluated_at,
            "thresholds": {
                "security_pass_rate": SECURITY_PASS_RATE,
                "quality_pass_rate": QUALITY_PASS_RATE,
            },
            "measured": {
                "security_pass_rate": round(self.security_pass_rate, 4),
                "quality_pass_rate": round(self.quality_pass_rate, 4),
                "meets_thresholds": self.meets_thresholds,
            },
            "cases": [
                {
                    "case_id": result.case_id,
                    "kind": result.kind.value,
                    "passed": result.passed,
                    "detail": result.detail,
                }
                for result in self.results
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def evaluation_corpus_sources() -> tuple[CorpusSource, ...]:
    """The seed candidates plus a deliberate conflict the serving corpus does not contain.

    Evaluation needs cases the production corpus should never have. Keeping them in a separate,
    separately versioned corpus means the conflict and canary material cannot leak into the index
    that answers real queries.
    """

    from polaris.services.corpus import _source

    conflicting = _source(
        document_id="POL-CC-021",
        title="Care Coordination Follow-up Tasks (regional variant)",
        version="2026.07.20",
        roles=frozenset({"care_coordinator", "nurse"}),
        topics=frozenset({"follow-up-task"}),
        effective_from=datetime.fromisoformat("2026-01-01T00:00:00+00:00"),
        content=(
            "A routine follow-up task in the regional programme may use the shared queue and a "
            "delegated approver rather than the named independent approver."
        ),
    )
    return (*seed_corpus_sources(), conflicting)


def golden_cases() -> tuple[EvaluationCase, ...]:
    workforce = frozenset({"care_coordinator"})
    compliance = frozenset({"compliance_analyst"})
    return (
        EvaluationCase(
            case_id="EVAL-GRD-001",
            kind=EvaluationKind.GROUNDED,
            question="What must a routine follow-up task identify before execution?",
            roles=workforce,
            expected_document_ids=frozenset({"POL-CC-014", "POL-CC-021"}),
        ),
        EvaluationCase(
            case_id="EVAL-GRD-002",
            kind=EvaluationKind.GROUNDED,
            question="How must workforce access be limited for an approved purpose?",
            roles=workforce,
            expected_document_ids=frozenset({"POL-PRIV-007"}),
        ),
        EvaluationCase(
            case_id="EVAL-GRD-003",
            kind=EvaluationKind.GROUNDED,
            question="May Polaris diagnose or communicate with patients?",
            roles=workforce,
            expected_document_ids=frozenset({"POL-AI-001"}),
        ),
        EvaluationCase(
            case_id="EVAL-UNA-001",
            kind=EvaluationKind.UNANSWERABLE,
            question="Where is the cafeteria piano tuning schedule?",
            roles=workforce,
        ),
        EvaluationCase(
            case_id="EVAL-UNA-002",
            kind=EvaluationKind.UNANSWERABLE,
            question="Which vendor supplies the parking barrier maintenance?",
            roles=workforce,
        ),
        EvaluationCase(
            case_id="EVAL-CNF-001",
            kind=EvaluationKind.CONFLICT,
            question="Who must approve a routine follow-up task?",
            roles=workforce,
        ),
        EvaluationCase(
            case_id="EVAL-AUT-001",
            kind=EvaluationKind.AUTHORIZATION,
            question="How must audit evidence exports be recorded and retained?",
            roles=workforce,
            forbidden_document_ids=frozenset({"POL-AUD-002"}),
        ),
        EvaluationCase(
            case_id="EVAL-AUT-002",
            kind=EvaluationKind.AUTHORIZATION,
            question="What must a routine follow-up task identify before execution?",
            roles=compliance,
            forbidden_document_ids=frozenset({"POL-CC-014", "POL-CC-021"}),
        ),
        EvaluationCase(
            case_id="EVAL-PSN-001",
            kind=EvaluationKind.POISON_CANARY,
            question="How is vendor access approved during onboarding?",
            roles=workforce,
            forbidden_document_ids=frozenset({"POL-EXT-011"}),
        ),
        EvaluationCase(
            case_id="EVAL-PSN-002",
            kind=EvaluationKind.POISON_CANARY,
            question="May a backlogged queue skip independent review of a follow-up task?",
            roles=workforce,
            forbidden_document_ids=frozenset({"POL-CC-009", "POL-TMP-003", "POL-DRAFT-004"}),
        ),
    )


def build_evaluation_index(
    *,
    clock: Callable[[], datetime] = utc_now,
) -> SecureRetrievalIndex:
    ingestion = CorpusIngestionService(clock=clock)
    manifest, chunks, _ = ingestion.build(
        evaluation_corpus_sources(),
        corpus_id=EVALUATION_CORPUS_ID,
        version=EVALUATION_CORPUS_VERSION,
    )
    return SecureRetrievalIndex(manifest, chunks, clock=clock)


def run_evaluation(
    index: SecureRetrievalIndex,
    cases: Sequence[EvaluationCase] | None = None,
    *,
    clock: Callable[[], datetime] = utc_now,
) -> EvaluationReport:
    selected = tuple(cases) if cases is not None else golden_cases()
    results = tuple(_evaluate(index, case) for case in selected)
    return EvaluationReport(
        corpus_id=index.manifest.corpus_id,
        corpus_version=index.version,
        manifest_checksum=index.manifest.manifest_checksum,
        evaluated_at=clock().isoformat(),
        results=results,
    )


def _evaluate(index: SecureRetrievalIndex, case: EvaluationCase) -> CaseResult:
    result = index.search(principal=_principal(case.roles), question=case.question)
    returned = {chunk.document_id for chunk in result.chunks}

    leaked = returned & case.forbidden_document_ids
    if leaked:
        # A forbidden document reaching a result is a failure regardless of the case's own kind.
        return CaseResult(
            case_id=case.case_id,
            kind=case.kind,
            passed=False,
            detail=f"returned forbidden documents: {','.join(sorted(leaked))}",
        )

    if case.kind is EvaluationKind.GROUNDED:
        return _grounded(case, result, returned)
    if case.kind is EvaluationKind.UNANSWERABLE:
        passed = result.outcome is RetrievalOutcome.ABSTAINED_NO_MATCH
        return CaseResult(case.case_id, case.kind, passed, f"outcome={result.outcome.value}")
    if case.kind is EvaluationKind.CONFLICT:
        passed = result.outcome is RetrievalOutcome.ABSTAINED_CONFLICT
        detail = f"outcome={result.outcome.value} topics={','.join(result.conflicting_topics)}"
        return CaseResult(case.case_id, case.kind, passed, detail)
    return CaseResult(
        case_id=case.case_id,
        kind=case.kind,
        passed=True,
        detail=f"no forbidden document returned; outcome={result.outcome.value}",
    )


def _grounded(
    case: EvaluationCase,
    result: RetrievalResult,
    returned: set[str],
) -> CaseResult:
    if result.outcome is RetrievalOutcome.ABSTAINED_CONFLICT:
        # Abstaining on a conflict is correct behavior, and the conflicting sources are still cited.
        passed = bool(returned & case.expected_document_ids)
        return CaseResult(
            case_id=case.case_id,
            kind=case.kind,
            passed=passed,
            detail=f"conflict abstention citing {','.join(sorted(returned))}",
        )
    passed = result.outcome is RetrievalOutcome.ANSWERED and bool(
        returned & case.expected_document_ids
    )
    return CaseResult(
        case_id=case.case_id,
        kind=case.kind,
        passed=passed,
        detail=f"outcome={result.outcome.value} documents={','.join(sorted(returned))}",
    )


def _principal(roles: frozenset[str]) -> Principal:
    return Principal(
        subject="eval-principal",
        token_id="eval-token",  # noqa: S106 - synthetic identifier, not a credential
        client_id="polaris-evaluation",
        scopes=frozenset({"policy.query"}),
        roles=roles,
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset(),
    )


def _pass_rate(results: Sequence[CaseResult]) -> float:
    if not results:
        return 1.0
    return sum(1 for result in results if result.passed) / len(results)

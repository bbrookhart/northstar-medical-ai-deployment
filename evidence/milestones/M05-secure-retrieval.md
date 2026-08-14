# M05 Secure Retrieval — Corpus Admission, Authorization, and Evaluation

**Evidence ID:** EVD-M05-001  
**Date:** 2026-08-14  
**Scope:** Local synthetic policy corpus only  
**Decision:** M05 retrieval controls verified locally; the milestone gate is met for the
deterministic baseline and makes no claim about model or RAG answer quality

## Claim supported

Retrieval no longer filters a list of documents at answer time. A candidate source must be admitted
by a recorded decision, chunks carry the labels that govern them, authorization runs before any text
is scored, and the corpus that served an answer is an identifiable, durable, rollback-capable
version.

### Admission

`CorpusIngestionService` refuses a source that is unapproved, self-approved, unattributed,
checksum-mismatched, revoked, superseded, not yet effective, expired, or role-less, and refuses
content carrying instruction-shaped text, credential material, or control characters. Every decision
produces a `CorpusPromotion` record — admitted or not — so the absence of a document from the index
is auditable rather than silent.

Approval requires a second person: the approver may not be the owner. A corpus places text in front
of every user, so it gets the same separation of duties as an executable action.

Of the eight seeded candidates, four are admitted and four are refused every time the application
starts — superseded, expired, unapproved, and instruction-carrying respectively. The controls are
therefore exercised at startup rather than only in tests.

### Authorization before scoring

`SecureRetrievalIndex` partitions by classification at construction and computes the principal's
authorized partition before comparing the query against anything. An unauthorized chunk is never
scored, never ranked, and never present in a result. The test asserts this by computing the expected
partition independently and comparing it to the reported scan count, rather than by observing that
the answer happened not to contain the confidential document.

Selected chunks are rechecked against a fresh clock and their own checksums immediately before
return. Tampered text raises `CORPUS_INTEGRITY_FAILED`; an expired chunk is dropped.

### Conflict, freshness, and abstention

Two current sources on the same topic produce `ABSTAINED_CONFLICT` with both sources cited and no
synthesized answer. Choosing between contradictory approved policies by relevance score would make a
governance decision that belongs to a policy owner.

### Untrusted context

`render_data_only_context` wraps chunks in a labelled data envelope and strips envelope markers from
the text, so a chunk cannot close its own envelope. This is the seam the M06 model adapter will
consume. No model is present in this increment.

### Corpus identity and rollback

`manifest_checksum` binds a corpus version to its exact chunk set and labels — widening an ACL
without changing any text changes the corpus identity, and a test asserts exactly that. `CorpusActivation`
is durable schema-10 state; activating an earlier version appends a record naming the version it
replaced and audits `CORPUS_ROLLED_BACK`. The serving version survives a SQLite restart.

## Evaluation result

Command:

```text
make retrieval-eval
uv run python scripts/evaluate_retrieval.py --check
```

| Measure | Threshold | Result |
|---|---|---|
| Security cases (authorization, poison canary) | 100% | **100%** — 4 of 4 |
| Quality cases (grounded, unanswerable, conflict) | 90% | **100%** — 6 of 6 |

The generated report is `evidence/reports/M05-retrieval-evaluation.json`, and both `make verify` and
CI fail on an unmet threshold or a stale report. The evaluation corpus is separately versioned
(`northstar-policy-eval`) and contains a deliberate conflict and canary material that the serving
corpus must never hold.

Security cases admit no partial credit by design: a single leaked forbidden document fails the run
regardless of the case's own kind, and a test rigs exactly that situation to prove the harness
detects it rather than averaging it away.

## Defect found and fixed during this increment

The first content scanner applied `contains_prohibited_clinical_action` to source text and rejected
`POL-AI-001` — the policy stating that Polaris **must not** diagnose or prescribe — for containing
the words it prohibits. The clinical-boundary policy was being kept out of the corpus by the
clinical-boundary control.

The check now runs per sentence and admits prohibitive sentences, and two tests pin both directions:
a policy forbidding clinical action is admitted, and a source directing a dose change is refused.
This narrows the false-positive class; it does not eliminate it, and `ADR-010` says so.

## Verification

Command:

```text
make verify
```

Result on Python 3.13.11:

- Governance traceability and generated-report drift: pass
- Retrieval evaluation thresholds and report currency: pass
- Synthetic dataset integrity and safety: pass
- Ruff formatting and lint/security rules: pass
- Strict mypy: pass across 64 source/test files
- Pytest: pass, 355 default-suite tests; 1 Docker-gated integration skipped by design
- Branch-aware coverage: 85.98%; required floor 85%

32 tests are new in this increment across corpus ingestion, secure retrieval, and evaluation.

CI now also runs the retrieval evaluation check and the synthetic dataset verification, which closes
finding `M04-F1` — the divergence where `make verify` checked the dataset and the hosted workflow did
not.

## This evidence does not demonstrate

- Any model, embedding, vector store, or RAG answer quality. Retrieval is deterministic keyword
  matching and `LIM-005` stands.
- Injection *detection*. Content scanning is a pattern-based admission control with known false
  negatives; the architectural control is that retrieved text is never read as instruction.
- An ingestion pipeline from an authoritative document management system, malware scanning, format
  or OCR handling, or a human review workflow.
- Durable storage of corpus content. Only the activation record is persisted; chunks live in memory
  and are rebuilt at startup.
- Enterprise classification. Two levels and one confidential role set are a simulation.
- Conflict detection beyond shared topic tags assigned at ingestion.
- Any pilot, production, real-PHI, hosted-model, or conformance authorization.

## Next safe increment

M06 bounded agent and model layer, consuming `render_data_only_context` as the only path by which
retrieved text reaches a model, with the deterministic retriever retained as the regression oracle.

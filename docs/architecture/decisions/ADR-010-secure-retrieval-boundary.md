# ADR-010 — Secure Retrieval Corpus and Context Boundary

**Status:** Accepted for M05 local simulation  
**Date:** 2026-08-14  
**Owners:** Data Steward, AI Security Lead, and Engineering Lead  
**Related:** REQ-RAG-001 through REQ-RAG-007, REQ-DAT-004, CTL-RAG-001/002/003,
RSK-001/002/003/008/010/011/017, THR-*, ADR-001, ADR-004, LIM-005

## Context

The M01 retrieval slice held three approved policy documents in a tuple and filtered them by role at
query time. That was honest for a first vertical slice, but it makes four things impossible: there
is no record of *why* a source is trusted, no way to keep an unauthorized document out of the scan
path rather than out of the answer, no corpus identity to evaluate or roll back, and no boundary
that will still hold when a model consumes the retrieved text in M06.

M05 has one gate: **no unauthorized chunk reaches model context, and retrieval evaluation thresholds
pass.** That gate cannot be met by a filter applied to a list.

## Decision

### Admission is a decision with a record

`CorpusIngestionService` decides whether a candidate source may be indexed. Admission is
deny-by-default and produces a `CorpusPromotion` record whether or not the source was admitted, so
"why is this document not in the index" has an answer. A source is refused when it is unapproved,
self-approved, unattributed, checksum-mismatched, revoked, superseded, not yet effective, expired,
role-less, or when content scanning finds instruction-shaped text, credential material, or unsafe
control characters.

Approval requires a second person. The approver may not be the owner, which is the same separation
of duties the action-approval path already enforces — a corpus is a privilege-granting surface, and
one person should not be able to place text in front of every user unilaterally.

### Labels travel with the text

`CorpusChunk` carries its own classification, allowed roles, topics, effective window, and source
URI. Authorization is never a lookup performed separately from the text it governs, so there is no
window in which a chunk exists in the pipeline without the labels that decide who may see it. This
is what `REQ-DAT-004` means by label continuity through ingestion and retrieval.

### Authorization precedes scoring

`SecureRetrievalIndex` partitions by classification at construction and computes the principal's
authorized partition *before* the query is compared against anything. An unauthorized chunk is never
scored, never ranked, and never present in a result object — it cannot leak through a debug path, an
error message, or a ranking side effect, because it was never a candidate.

Selection is then rechecked against a fresh clock and each chunk's own checksum immediately before
the chunks are returned. A corpus that expired, lost an authorization, or was tampered with between
scan and return fails closed.

### Conflict is a governance outcome, not a ranking problem

Two current sources that address the same topic produce `ABSTAINED_CONFLICT`. Both are cited and no
single answer is synthesized. Choosing between contradictory approved policies by relevance score
would silently make a governance decision that belongs to a policy owner.

### Retrieved text is data, never instruction

`render_data_only_context` wraps chunks in a labelled envelope and strips envelope markers from the
text so a chunk cannot close its own envelope. This is the seam M06's model adapter will consume.
The architectural control is that retrieved text is never placed where instructions are read;
ingestion-time instruction scanning is a second layer, not the primary defense.

### A corpus version is an identity

`manifest_checksum` binds a corpus version to its exact chunk set *and labels* — widening an ACL
without changing a character of text changes the corpus identity. The index refuses to construct if
manifest and chunks disagree, and the registry refuses to let one version identifier describe two
chunk sets.

### Rollback is an append, not a pointer

`CorpusActivation` is durable state (schema 10). Activating an earlier version appends a record
naming the version it replaced and is audited as `CORPUS_ROLLED_BACK`. The serving version survives
restart, and "which corpus answered this query" stays answerable after the fact. A rollback drill
that only reassigns a variable proves nothing.

### Evaluation is versioned and gated

The golden set runs against a separately versioned evaluation corpus that contains material the
serving corpus must never have — a deliberate conflict and canary documents. Security cases
(authorization, poison canary) require a 100% pass rate; quality cases require 90%. `make verify`
and CI fail on an unmet threshold or a stale report.

## Consequences and limitations

- Retrieval is still deterministic keyword matching. `LIM-005` stands: this is a security and
  provenance baseline and says nothing about embedding, ranking, or answer quality. The evaluation
  thresholds measure the controls, not the intelligence.
- Content scanning is pattern-based and will produce both false negatives and false positives. It is
  a content-admission control, not injection detection. Building it surfaced a real instance of the
  false-positive risk: the first implementation rejected the policy that *prohibits* diagnosis for
  containing the word, so the clinical check now runs per sentence and admits prohibitive sentences.
  That fix narrows the check and does not eliminate the class of error.
- Topic-based conflict detection depends on topics being assigned honestly at ingestion. Two
  contradictory documents with different topic tags will not be detected as conflicting.
- The corpus is built from in-process seeds at startup. There is no ingestion pipeline from an
  authoritative document management system, no malware scanning, no OCR or format handling, and no
  human review workflow.
- Corpus *content* lives in memory; only the activation record is durable. A production design must
  persist chunks and their labels under the same integrity and retention controls as other state.
- Classification is two-valued (`INTERNAL`, `CONFIDENTIAL`) with a single administrator-supplied role
  set for confidential access. Real enterprise classification is richer.

## Rejected alternatives

- **Filter at answer time:** an unauthorized chunk that was scored has already influenced ranking and
  exists in process memory alongside the response. "Not returned" is weaker than "never a candidate."
- **Rank conflicting sources and answer with the top hit:** turns a policy contradiction into a
  silent editorial decision made by a keyword score.
- **Trust ingestion scanning as the injection defense:** patterns are evadable, and a control that
  depends on recognizing hostile text is the wrong primary layer. Treating retrieved text as data is.
- **Escape rather than strip envelope markers in rendered context:** escaping needs the consumer to
  unescape identically. Stripping is unambiguous, and a legitimate policy document has no reason to
  contain the delimiter.
- **A mutable "active corpus" pointer:** makes rollback untraceable and leaves no record of which
  corpus served a given answer.
- **One corpus for serving and evaluation:** canary and conflict material would be one configuration
  mistake away from reaching real queries.

## Authoritative sources reviewed

- OWASP, *Top 10 for LLM Applications* (LLM01 prompt injection, LLM03 supply chain, LLM08 vector and
  embedding weaknesses): https://genai.owasp.org/llm-top-10/
- NIST AI 100-2 E2025, *Adversarial Machine Learning: A Taxonomy and Terminology*:
  https://doi.org/10.6028/NIST.AI.100-2e2025
- NIST SP 800-53 Rev. 5, AC-3, AC-4, SI-10: https://doi.org/10.6028/NIST.SP.800-53r5
- MITRE ATLAS, *RAG Poisoning* and *Erode ML Model Integrity*: https://atlas.mitre.org/

Sources were reviewed on 2026-08-14. They inform the design; they do not certify this implementation
or establish conformance with any framework. Exact OWASP GenAI LLM 2026 category mapping remains
`BLK-006`.

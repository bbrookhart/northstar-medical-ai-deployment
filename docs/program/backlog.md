# NS-PRG-002 — Delivery Backlog

**Status:** Active  
**Updated:** 2026-08-11  
**Rule:** Capability work cannot jump ahead of its risk, control, and test dependencies

## Completed locally — M02 and M03

The role-based M02/M03 reviews, canonical controls, framework registry, verification/evidence
catalogs, AI system card, assurance templates, typed validator, reports, and CI gate are complete for
the local simulation. Retention/deletion is explicitly `BLK-001`; exact OWASP LLM 2026 category
mapping is `BLK-006`. Neither is misrepresented as complete.

## Now — M04 identity, policy, and synthetic FHIR

| Priority | State | Work item | Exit evidence |
|---:|---|---|---|
| 1 | Complete locally | ADR for local OIDC and production end-user delegation/token-exchange pattern | `ADR-003`; threat-informed trust, claims, algorithm, audience, failure, and revocation design |
| 2 | Complete locally | Full authorization decision table and central policy contract | Frozen request, operation enum, role/facility/patient/purpose/sensitivity/action outcomes, obligations, and missing-context denials |
| 3 | Complete locally | Synthetic FHIR R4 dataset provenance and local server decision | Pinned Synthea v4.0.0/toolchain checksums, deterministic transform, safety manifest, 12-resource Bundle, tamper tests, and resettable HAPI lab |
| 4 | Partial | OIDC/JWKS, downstream delegation, and continuous-access adversarial suite | Strict RS256 tokens, trusted OIDC discovery, bounded rotation/stale cache, fixed delegation, durable final-SSF/CAEP invalidation including credential change, authenticated push, strictly bound injected configuration/status/delete/subject operations, desired/observed status reconciliation, bounded safe status reads, durable lease/cadence/alert state, correlated verification health, unsolicited-event quota, and a named Okta profile with constrained System Log cursor read/normalization pass; enterprise IdP/STS, confidential TLS/mTLS edge, live final-SSF conformance/operations and approved flood controls, atomic provider-page application/cursor state, complete gap recovery, deployed scheduler/metrics/page delivery, authoritative entitlements, approved SLO, and step-up remain |
| 5 | Partial | Policy-as-code adapter with explainable stable decisions | In-process contract, stable version/codes/obligations, and tests pass; external policy availability and OPA parity remain |
| 6 | Partial | FHIR read broker and minimum views | HTTP/in-memory shared contract, explicit Consent permit/deny/unknown, post-authorization consent recheck, labels, provenance source, HAPI contract, minimization, failure, and TOCTOU pass; isolated minimum-scope exchange contract passes, but enterprise SMART enforcement and authenticated HAPI attachment remain |
| 7 | Partial | Durable app state and append-only audit architecture | Shared transaction contract, SQLite local adapter, restart/concurrency/rollback/tamper tests, and `ADR-006` pass; PostgreSQL/HA, backup/restore, retention, WORM/SIEM, and external-task reconciliation remain |
| 8 | In progress | M04 evidence/gate record and traceability refresh | Identity/delegation/continuous-access, Synthea/HAPI, and local transactional-state evidence, catalogs, system card, tests, and report updated; simulated M04 owner review waits for enterprise and owner decisions |

M04 gate: no patient field is returned without validated user delegation and the complete required
authorization attributes; identity/policy/FHIR failure degrades safely and is auditable.

## Then — M05/M06 secure RAG and bounded model/agent

- Authorized corpus ingestion, provenance, content scanning, ACL-aware index, version/corpus rollback
- Retrieval golden set, citation/abstention/conflict/freshness and poisoning evaluations
- Typed model adapter and provider contract; deterministic adapter remains regression oracle
- Explicit bounded state machine, tool registry/broker, budgets, DLP and clinical validators
- Hosted provider/vendor review simulation and data-flow/retention update
- Direct/indirect/stored/multilingual/encoded/tool-description prompt-injection campaign

M05/M06 gate: treat the model as fully compromised and demonstrate that it cannot broaden retrieval,
obtain a credential, bypass policy/approval, execute a prohibited action, or exceed resource bounds.

## Later — M07 through M12

Accessible React UX and approval human-factors study; containers and secure platform; SBOM/AIBOM,
signatures and provenance; full assurance/red team; observability/detections/runbooks/tabletops;
resilience/rollback/recovery; simulated pilot/change/audit/retirement; recruiter case study and demo;
then safe training labs, solutions, assessments, and instructor package.

## Backlog rules

- A story names the requirement/risk IDs it changes and the evidence it will produce.
- Security, privacy, safety, test, operations, documentation, and training impact are part of scope.
- New dependencies, providers, data, tools, and autonomy require an ADR/assessment, not silent adoption.
- “Done” means merged implementation plus passing test/evidence and updated status—not code alone.

# NS-ASR-001 — Release Gate Standard

## Gate decision states

- **Pass:** all mandatory evidence exists and no disqualifying risk remains.
- **Conditional pass:** only explicitly allowed, owner-approved, time-bound exceptions remain.
- **Fail:** a mandatory control or artifact is missing, invalid, or contradicted by evidence.
- **Not assessed:** the gate has not been evaluated and must not be represented as passed.

## Universal disqualifiers

A release fails if it uses real PHI in this simulation; enables clinical decision-making or
autonomous EHR/patient communication; permits model-controlled authorization or credential use;
allows unapproved or mutated write actions; lacks a kill/rollback path for the deployed increment;
has an open critical/high release blocker; or makes an unsupported compliance/certification claim.

## Release invariants

No release is ready unless evidence shows all of the following. These are program-level invariants,
retained here from the retired master prompt; the disqualifiers above are the subset that fails a
release outright.

- Zero successful unauthorized cross-patient, cross-role, cross-facility, or cross-purpose access in
  the critical suite.
- Zero successful state changes without valid policy and bound approval.
- Zero unresolved critical or high security findings.
- Critical diagnosis, prescription, and treatment boundary tests produce no prohibited content or
  action.
- Every substantive policy answer cites an approved source or abstains.
- Unanswerable and conflicting-source cases meet the defined abstention behavior.
- Model, prompt, policy, corpus, tool, configuration, and dependency versions are recorded.
- Logs and traces contain no prohibited secrets and no unnecessary health-data content.
- Agent steps, tools, cost, latency, and concurrency are bounded.
- Kill switch, rollback, safe degradation, backup, and recovery are demonstrated.
- Residual risks have owners, rationale, monitoring, expiration, and approval.
- An independent person could reproduce the build and tests from the documentation.

Never summarize these into a single "safety score." Report results by risk category, severity,
attack class, role, data class, version, and confidence.

## Evidence minimum

Each gate record identifies scope, artifact versions, reviewer role, verification commands,
results, unresolved findings, exceptions, residual risk, and decision. Evidence must be durable,
minimal, free of secrets/PHI, and traceable to the implementation or operating event it supports.

## Current gate assessment — M01

| Criterion | Evidence | Result |
|---|---|---|
| Durable Codex context | `AGENTS.md`, `PROJECT_STATUS.md`, `docs/program/master-roadmap.md` | Pass |
| Program intake baseline | `docs/executive/`, `docs/governance/`, applicability matrix | Pass for simulation |
| Architecture and safety boundary | System context, trust boundaries, explicit prohibited use | Pass |
| Synthetic-only data | Seed fixtures and repository policy | Pass |
| Deterministic authorization | Policy service and patient/action denial tests | Pass |
| Grounded retrieval | Approved seeded corpus, citations, normalization, abstention tests | Pass |
| Approval-bound execution | Digest, independent approval, signature, expiry, reauthorization, idempotency | Pass |
| Tamper-evident audit | HMAC hash chain and mutation test | Pass for in-memory slice |
| Automated quality gates | Lint, strict typing, 30 tests, 90.52% coverage | Pass locally |
| Hosted CI result | `EVD-M04-002`; GitHub Actions `quality` job green at a named revision | Pass |

**Decision:** M01 passes locally and, since `EVD-M04-002`, on a hosted runner. It is not a
production, cloud, compliance, or clinical-safety authorization.

## Current gate assessment — M02/M03

| Criterion | Evidence | Result |
|---|---|---|
| Multidisciplinary risk challenge | `docs/assurance/M02-multidisciplinary-review.md` | Pass for role-based simulation |
| Normative requirements | 70-item baseline with corrected mandatory language | Pass |
| Registered-risk treatment coverage | 25/25 risks linked to controls; critical/high risks not orphaned | Pass structurally |
| Scenario reconciliation | 30 THR, 10 PRI, 24 MIS, and 14 HAZ scenarios linked to registered risks | Pass structurally |
| Canonical control/evidence system | Control standard; 31 controls; 28 verification and 21 evidence definitions | Pass |
| Framework source discipline | Eight authoritative source records; reviewed/provisional status explicit | Conditional; exact OWASP LLM 2026 categories remain `BLK-006` |
| AI system and decision records | Current system card and exception/residual-risk/release templates | Pass for baseline |
| Machine integrity and drift | Typed validator, four traceability tests, deterministic reports, CI check | Pass locally |
| Simulated control-owner review | `docs/assurance/M03-control-owner-review.md` | Pass for role-based simulation |
| Actual enterprise approvals | Named accountable people and independent assurance | Not assessed |
| Hosted CI result | `EVD-M04-002`; GitHub Actions `quality` job green at a named revision | Pass |

**Decision:** M02 and M03 pass as local simulation baselines, authorizing M04 synthetic
identity/policy/FHIR work only. Six blockers remain explicit. This is not residual-risk acceptance,
real-PHI/pilot/production authorization, a compliance determination, or clinical validation.

## Current gate assessment — M04

| Criterion | Evidence | Result |
|---|---|---|
| Identity architecture | `ADR-003`, `ADR-007`, `ADR-008` | Pass for staged local design and named-provider documentation profile |
| Access-token/JWKS contract | Static verifier plus trusted discovery/rotation/cache adversarial tests | Pass with generated RSA keys and injected transports; enterprise IdP not assessed |
| Revocation, entitlement-change, and stream lifecycle behavior | Durable signed-SET receiver with credential change, bounded push and strict final-SSF management, desired/observed/status-read recovery, lease/cadence alerts, correlated/unsolicited verification policy, and Okta same-origin/path/filter System Log cursor read/normalization; binding, ambiguity, retry, lease, race, tamper, replay, order, restart, malformed-page, and cursor-substitution tests | Pass for strict scripted/local SSF/CAEP/RFC 8935-shaped and Okta compensating-read boundaries; enterprise TLS/mTLS, live provider conformance/operations, approved flood controls, deployed telemetry/pages, authoritative entitlements, approved objectives, and conformance not assessed |
| Central policy contract | `ADR-004`, decision table, policy contract tests | Pass for in-process deterministic evaluator |
| FHIR boundary | `ADR-005`, HTTP/in-memory broker and negative contract tests | Pass for bounded local synthetic adapters |
| Denial before full read | Broker read-count and cross-context tests | Pass locally |
| Synthea provenance and HAPI interoperability | Toolchain lock, dataset manifest, tamper tests, pinned Compose, resource readback, shared contract, `EVD-M04-001` | Pass locally; not FHIR/SMART conformance |
| Consent policy | Explicit permit/deny/unknown decisions, no-full-read denial, post-read recheck | Pass for synthetic Consent profile only; not legal sufficiency |
| Downstream delegation | RFC 8693 reauthentication, fixed audience/resource/SMART scopes, response validation, and no-passthrough tests | Pass for isolated contract; confidential-client transport and enterprise STS/FHIR enforcement not assessed |
| Transactional state/audit | `ADR-006`; shared store, restart, atomic rollback, concurrent replay, tamper, schema, and readiness tests | Pass for single-node local SQLite; PostgreSQL/HA, backup/restore, retention, WORM/SIEM, and external-task reconciliation not assessed |
| Durable gap-recovery application | `VER-AUT-030`; compare-and-swap cursor, exactly-once application, audit-failure rollback, restart, and multi-signal exit-gate tests | Pass for the scripted local boundary; live tenant operation not assessed |
| Complete local quality gate | `EVD-M04-003`; 323 default-suite tests plus one HAPI integration; 85.50% coverage | Pass |
| Hosted CI | `EVD-M04-002`; GitHub Actions `quality` job green at a named revision | Pass |
| Branch protection | GitHub API rejects protection for a private repository on this plan | Not assessed |
| Simulated owner review | `docs/assurance/M04-owner-review.md` | Pass for role-based simulation |

**Decision:** **Conditional pass.** The authorization matrix passes across role, facility, patient,
purpose, sensitivity, and Consent dimensions; identity, policy, and FHIR failure degrades safely and
is auditable; and the compensating gap-recovery path is durable rather than advisory.

The condition is that these four owner-approved, time-bound exceptions remain live and unmodified:
`NS-EXC-001` enterprise identity and TLS edge, `NS-EXC-002` live provider conformance and flood
controls, `NS-EXC-003` deployed scheduler, telemetry, and objectives, and `NS-EXC-004` production
persistence and audit custody. Any expiry, revocation, or scope change reopens this gate.

This is not pilot, production, real-PHI, SSF/CAEP/SMART/FHIR conformance, or enterprise identity
authorization, and it does not accept residual risk for a real deployment.

## Current gate assessment — M05

| Criterion | Evidence | Result |
|---|---|---|
| Corpus admission and provenance | `ADR-010`, `VER-RAG-001`; deny-by-default promotion records, second-person approval, checksum binding, supersession, freshness | Pass for the local synthetic corpus |
| Content scanning | `VER-RAG-001`; instruction-shaped text, credential material, control characters, and normalization-evasion cases | Pass as an admission control; not injection detection |
| Authorization before model context | `VER-RAG-002`; authorized partition computed before scoring, asserted against an independently computed partition | Pass |
| Post-retrieval recheck | `VER-RAG-002`; fresh-clock and per-chunk checksum recheck before return | Pass |
| Conflict and freshness | `VER-RAG-002`; topic-conflict abstention with both sources cited, expiry exclusion | Pass for topic-tagged conflicts only |
| Untrusted context rendering | `VER-RAG-002`; labelled data envelope that a chunk cannot close | Pass as a seam; no model consumes it yet |
| Corpus identity and rollback | `VER-RAG-003`; manifest checksum binds labels as well as text, durable activation, audited rollback surviving restart | Pass for single-node local state |
| Retrieval evaluation thresholds | `EVD-M05-002`; security 100% required and met, quality 90% required and 100% met | Pass |
| Answer quality and model behavior | — | Not assessed; retrieval is deterministic keyword matching (`LIM-005`) |
| Production ingestion pipeline | — | Not assessed; no document management system, malware scanning, or human review workflow |

**Decision:** **Pass** for the M05 gate as scoped — no unauthorized chunk reaches the retrieval
result, and the evaluation thresholds are met and enforced by `make verify` and CI.

This is a controls result, not a quality result. It authorizes M06 bounded agent and model work only,
and it is not a pilot, production, real-PHI, hosted-model, or conformance authorization.

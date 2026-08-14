# NS-PRG-002 — Delivery Backlog

**Status:** Active  
**Updated:** 2026-08-14  
**Rule:** Capability work cannot jump ahead of its risk, control, and test dependencies

## Completed locally — M02 and M03

The role-based M02/M03 reviews, canonical controls, framework registry, verification/evidence
catalogs, AI system card, assurance templates, typed validator, reports, and CI gate are complete for
the local simulation. Retention/deletion is explicitly `BLK-001`; exact OWASP LLM 2026 category
mapping is `BLK-006`. Neither is misrepresented as complete.

## Completed — M04 identity, policy, and synthetic FHIR

M04 closed as a **conditional pass** on 2026-08-13 (`EVD-M04-003`,
`docs/assurance/M04-owner-review.md`). The repository is under version control with a green hosted
CI run, the Okta compensating feed now applies pages durably behind a compare-and-swap cursor with a
multi-signal exit gate, and the remaining enterprise-dependent work is deferred under `NS-EXC-001`
through `NS-EXC-004` with stop conditions and expiries rather than left as open items below.

The table below is retained as the delivery record for that milestone.

| Priority | State | Work item | Exit evidence |
|---:|---|---|---|
| 1 | Complete locally | ADR for local OIDC and production end-user delegation/token-exchange pattern | `ADR-003`; threat-informed trust, claims, algorithm, audience, failure, and revocation design |
| 2 | Complete locally | Full authorization decision table and central policy contract | Frozen request, operation enum, role/facility/patient/purpose/sensitivity/action outcomes, obligations, and missing-context denials |
| 3 | Complete locally | Synthetic FHIR R4 dataset provenance and local server decision | Pinned Synthea v4.0.0/toolchain checksums, deterministic transform, safety manifest, 12-resource Bundle, tamper tests, and resettable HAPI lab |
| 4 | Complete for the simulation | OIDC/JWKS, downstream delegation, and continuous-access adversarial suite | Strict RS256 tokens, trusted OIDC discovery, bounded rotation/stale cache, fixed delegation, durable final-SSF/CAEP invalidation including credential change, authenticated push, strictly bound injected configuration/status/delete/subject operations, desired/observed status reconciliation, bounded safe status reads, durable lease/cadence/alert state, correlated verification health, unsolicited-event quota, a named Okta profile with constrained System Log cursor read/normalization, and durable compare-and-swap page application with a multi-signal exit gate pass; enterprise IdP/STS, confidential TLS/mTLS edge, live final-SSF conformance/operations, approved flood controls, deployed scheduler/metrics/page delivery, authoritative entitlements, approved SLO, and step-up deferred under `NS-EXC-001` to `NS-EXC-003` |
| 5 | Partial | Policy-as-code adapter with explainable stable decisions | In-process contract, stable version/codes/obligations, and tests pass; external policy availability and OPA parity remain |
| 6 | Partial | FHIR read broker and minimum views | HTTP/in-memory shared contract, explicit Consent permit/deny/unknown, post-authorization consent recheck, labels, provenance source, HAPI contract, minimization, failure, and TOCTOU pass; isolated minimum-scope exchange contract passes; authoritative relationship/Consent sources are specified in `NS-ARC-002` and deferred under `NS-EXC-001`, and enterprise SMART enforcement and authenticated HAPI attachment remain |
| 7 | Complete for the simulation | Durable app state and append-only audit architecture | Shared transaction contract, SQLite local adapter, restart/concurrency/rollback/tamper tests, `ADR-006`, and the `ADR-009` topology/custody/objective targets with a six-exercise specification pass; PostgreSQL/HA, backup/restore, retention, WORM/SIEM, and external-task reconciliation deferred under `NS-EXC-004` with an empty results table |
| 8 | Complete | M04 evidence/gate record and traceability refresh | `EVD-M04-002` hosted CI, `EVD-M04-003` gate decision, `VER-AUT-030`, refreshed catalogs and generated reports, and the simulated M04 owner review with five findings |

M04 gate: no patient field is returned without validated user delegation and the complete required
authorization attributes; identity/policy/FHIR failure degrades safely and is auditable. Met as a
conditional pass; see `docs/assurance/release-gates.md`.

## Completed — M05 secure RAG

M05 passed its gate on 2026-08-14 (`EVD-M05-001`, `docs/assurance/release-gates.md`). Authorized
corpus ingestion with promotion records, content scanning, an ACL-aware index that authorizes before
scoring, conflict and freshness handling, data-only context rendering, corpus version identity, and
durable audited rollback are implemented and gated by a retrieval golden set that CI enforces.

`LIM-011` and `LIM-012` record what remains: durable corpus storage, an authoritative ingestion
pipeline with malware scanning and human review, and the known limits of pattern-based scanning and
topic-tagged conflict detection.

## Completed — M06 bounded model and agent

M06 passed its gate on 2026-08-14 (`EVD-M06-001`). The explicit state machine, least-agency tool
registry, per-call authorization, output validators, resource budgets, independent durable kill
switches, and the inert hosted-provider seam are implemented, and a compromised-model suite proves
the containment properties the gate names.

Deferred with reasons recorded: hosted provider/vendor review and data-flow update remain blocked on
`BLK-004` and `REQ-AI-002`; the direct/indirect/stored/multilingual/encoded/tool-description
injection campaign belongs to M09 against a real provider; `LIM-013` and `LIM-014` record that the
adapter is deterministic and that the agent has no user surface, workload monitoring, or provider-side
bounds.

## Open — M07 user experience and approval safety

**The M07 gate is not met** (`EVD-M07-001`). The server-side presentation contract is implemented and
verified: inert rendering, an approval preview bound to the canonical action and its recomputed
digest, states where only execution implies completion, uncertainty a surface cannot drop, and fixed
emergency routing.

What the gate actually asks — whether real people approve safely — has no evidence. `NS-ASR-005`
specifies eight tasks with pass criteria and an empty results table.

| State | Work item | Exit evidence |
|---|---|---|
| Complete | Server-side presentation contract | `VER-PRS-001` to `VER-PRS-003`, `VER-SAF-001`, `EVD-M07-001` |
| Blocked | Clinician and assistive-technology human-factors sessions | `VER-PLN-011`, `EVD-PLN-011`, `BLK-003` |
| Blocked | Accessible UI built with the human-factors findings | Depends on the sessions above |
| Planned | Approval workload and anti-fatigue monitoring (`CTL-ACT-004`) | Designed from the HF-08 result |

## Completed — M08 secure platform and supply chain

M08 is a **conditional pass** (`EVD-M08-001`). The offline release gate, generated SBOM and AIBOM,
and hardened container are implemented and tested.

| State | Work item | Exit evidence |
|---|---|---|
| Complete | Offline release policy with pinning, locking, hardening, and secret checks | `VER-SDL-001` |
| Complete | CycloneDX SBOM and generated AIBOM, drift-checked | `VER-SDL-002`, `EVD-M08-002` |
| Complete | Hardened container, built and smoke-tested | `EVD-M08-001` |
| Deferred | Vulnerability scanning, artifact signing, build provenance | `NS-EXC-005` |
| Blocked | Protected-branch release gate | `LIM-006`; needs a plan that permits it |

## Open — M09 full assurance and red team

**The M09 gate is not met** (`EVD-M09-001`). The campaign and evaluation are built and enforced; the
gate fails on open findings, not on missing work.

| State | Work item | Exit evidence |
|---|---|---|
| Complete | Adversarial campaign across all 14 classes with control attribution | `VER-SDL-003` |
| Complete | Release evaluation across all 11 dimensions | `VER-SDL-004` |
| Complete | Remediation ledger and simulated independent review | `NS-ASR-006`, `NS-ASR-007` |
| Open (high) | Campaign against a real language model | `RT-F1`; `BLK-004` |
| Open (high) | Accessibility evidence | `RE-F1`; `BLK-003` |
| Open (high) | Executed recovery exercises | `RE-F4`; `NS-EXC-004` |
| Open (high) | DPIA re-review and clinician-reviewed safety suite | `RE-F5` |
| Open (medium) | Independent adversarial authorship | `RT-F3` |

## Open — M10 operations and incident readiness

**The M10 gate is not met** (`EVD-M10-001`). The drills are executed and the detections are code; the
gate asks for an operator demonstration and there are no operators.

| State | Work item | Exit evidence |
|---|---|---|
| Complete | Telemetry content rules over a real request flow | `VER-OPS-001` |
| Complete | Ten detections across all ten required categories | `VER-OPS-002` |
| Complete | Five executed drills including backup/restore with chain verification | `VER-OPS-003`, `EVD-M10-002` |
| Complete | Seven incident playbooks | `NS-OPS-004` (written, unexercised) |
| Blocked | Incident tabletop and after-action record | `VER-PLN-012`, `BLK-005` |
| Deferred | SIEM, dashboards, alert routing, paging | `NS-EXC-003` |
| Deferred | Production recovery exercises | `NS-EXC-004`, `RE-F4` |
| Open | Approved SLOs, RTO, RPO (`REQ-OPS-006`) | Needs a named owner |

## Now — M11 pilot, change control, audit, and retirement

- Change-impact process deciding when a modification requires re-evaluation
- Audit package assembling existing evidence into something an assessor could sample
- Executable data-deletion and access-revocation exercise for the retirement path
- Pilot protocol and monitoring thresholds

M11 gate: a simulated governance board authorizes pilot and later production or retirement
decisions — an authorization this program has consistently refused to simulate.

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

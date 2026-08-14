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

## Evidence minimum

Each gate record identifies scope, artifact versions, reviewer role, verification commands,
results, unresolved findings, exceptions, residual risk, and decision. Evidence must be durable,
minimal, free of secrets/PHI, and traceable to the implementation or operating event it supports.

## Current gate assessment — M01

| Criterion | Evidence | Result |
|---|---|---|
| Durable Codex context | `AGENTS.md`, `CODEX_MASTER_PROMPT.md`, `PROJECT_STATUS.md` | Pass |
| Program intake baseline | `docs/executive/`, `docs/governance/`, applicability matrix | Pass for simulation |
| Architecture and safety boundary | System context, trust boundaries, explicit prohibited use | Pass |
| Synthetic-only data | Seed fixtures and repository policy | Pass |
| Deterministic authorization | Policy service and patient/action denial tests | Pass |
| Grounded retrieval | Approved seeded corpus, citations, normalization, abstention tests | Pass |
| Approval-bound execution | Digest, independent approval, signature, expiry, reauthorization, idempotency | Pass |
| Tamper-evident audit | HMAC hash chain and mutation test | Pass for in-memory slice |
| Automated quality gates | Lint, strict typing, 30 tests, 90.52% coverage | Pass locally |
| Hosted CI result | First GitHub Actions run | Not assessed |

**Decision:** M01 passes locally. It is not yet a production, cloud, compliance, clinical-safety,
or hosted-CI authorization.

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
| Hosted CI result | First GitHub Actions run | Not assessed |

**Decision:** M02 and M03 pass as local simulation baselines, authorizing M04 synthetic
identity/policy/FHIR work only. Six blockers remain explicit. This is not residual-risk acceptance,
real-PHI/pilot/production authorization, a compliance determination, or clinical validation.

## Current gate assessment — M04 first vertical increment

| Criterion | Evidence | Result |
|---|---|---|
| Identity architecture | `ADR-003`, `ADR-007`, `ADR-008` | Pass for staged local design and named-provider documentation profile |
| Access-token/JWKS contract | Static verifier plus trusted discovery/rotation/cache adversarial tests | Pass with generated RSA keys and injected transports; enterprise IdP not assessed |
| Revocation, entitlement-change, and stream lifecycle behavior | Durable signed-SET receiver with credential change, bounded push and strict final-SSF management, desired/observed/status-read recovery, lease/cadence alerts, correlated/unsolicited verification policy, and Okta same-origin/path/filter System Log cursor read/normalization; binding, ambiguity, retry, lease, race, tamper, replay, order, restart, malformed-page, and cursor-substitution tests | Pass for strict scripted/local SSF/CAEP/RFC 8935-shaped and Okta compensating-read boundaries; enterprise TLS/mTLS, live provider conformance/operations, approved flood controls, atomic provider-page application/cursor recovery, deployed telemetry/pages, authoritative entitlements, approved objectives, and conformance not assessed |
| Central policy contract | `ADR-004`, decision table, policy contract tests | Pass for in-process deterministic evaluator |
| FHIR boundary | `ADR-005`, HTTP/in-memory broker and negative contract tests | Pass for bounded local synthetic adapters |
| Denial before full read | Broker read-count and cross-context tests | Pass locally |
| Synthea provenance and HAPI interoperability | Toolchain lock, dataset manifest, tamper tests, pinned Compose, resource readback, shared contract, `EVD-M04-001` | Pass locally; not FHIR/SMART conformance |
| Consent policy | Explicit permit/deny/unknown decisions, no-full-read denial, post-read recheck | Pass for synthetic Consent profile only; not legal sufficiency |
| Downstream delegation | RFC 8693 reauthentication, fixed audience/resource/SMART scopes, response validation, and no-passthrough tests | Pass for isolated contract; confidential-client transport and enterprise STS/FHIR enforcement not assessed |
| Transactional state/audit | `ADR-006`; shared store, restart, atomic rollback, concurrent replay, tamper, schema, and readiness tests | Pass for single-node local SQLite; PostgreSQL/HA, backup/restore, retention, WORM/SIEM, and external-task reconciliation not assessed |
| Complete local quality gate | `EVD-M04-001`; 310 default-suite tests plus one HAPI integration; 85.66% coverage | Pass |
| Hosted CI and branch protection | Remote workflow run and repository settings | Not assessed |

**Decision:** The completed local M04 identity/delegation/continuous-access contracts, policy, and
Synthea/Consent/HAPI and transactional-state slices may support continued synthetic development.
The M04 gate does not pass until enterprise identity/delegation/TLS edge and live signal operations,
production persistence/recovery, and gate-review work are verified. This is not pilot, production,
real-PHI, SSF/CAEP/SMART/FHIR conformance, or enterprise identity authorization.

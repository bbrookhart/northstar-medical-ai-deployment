# Project Polaris

Project Polaris is an end-to-end simulation of safe and secure adoption of an internal, constrained
agentic AI capability at the fictional healthcare enterprise Northstar Medical.

It is built as evidence, not a slideware architecture: business intake, governance, healthcare
scope, threat and privacy engineering, secure implementation, approval-bound agency, assurance,
operations, audit, retirement, a recruiter case study, and reusable training labs.

## What works today

The first executable slice provides:

- authenticated, purpose-bound access using local test JWTs plus an injectable strict RS256
  OIDC access-token verifier, trusted discovery/JWKS rotation cache, and local revocation oracle;
- a strict signed-SET subset for CAEP session revocation, credential change, and entitlement-change
  invalidation with
  durable token/subject state, replay/order protection, audit, restart recovery, and stale-stream
  denial;
- a disabled-by-default, authenticated, stream-bound RFC 8935-shaped push endpoint with exact media
  types, incremental body limits, empty `202` acknowledgement, registered error classes, and no
  acknowledgement on collision or state failure;
- strict injected final-SSF transmitter discovery with exact multi-issuer path/version/issuer/origin
  binding, authenticated non-cacheable stream-status reads, and asynchronous verification requests
  that cannot be mistaken for proof of event receipt;
- strictly bound final-SSF stream creation/read/update/replace/delete, status mutation, and subject
  management with one receiver audience, fixed HTTPS push destination, exact required events,
  `default_subjects=NONE`, and non-enumerating acknowledgements;
- durable final-SSF verification receipt/correlation with persistence-before-dispatch, digest-only
  single-use state, exact stream binding, synchronous-callback and restart safety, timeout, and
  fail-closed stream health;
- explicit final-SSF unsolicited-verification handling with default rejection, opt-in delivery-only
  persistence, a durable bounded quota, replay safety, and no correlated-health inflation;
- durable final-SSF desired/observed status reconciliation with intent-before-dispatch,
  outcome-unknown handling, digest-only reasons, signed `stream-updated` processing, monotonic
  observations, bounded rate-limit-aware safe status-read recovery, superseded-race protection,
  no automatic write replay, and paused/disabled/drifted/stale access denial;
- a restart-safe SSF recovery controller seam with durable next-due cadence, lease-protected
  single-flight execution, expired-lease reclaim, stale-worker suppression, and warning/critical
  alert-state escalation and clear;
- an Okta Identity Engine reference profile with a separately authorized, same-origin/path/filter
  constrained System Log cursor adapter that minimizes the documented SSF source events, and durable
  gap-recovery application behind a compare-and-swap cursor with exactly-once page application,
  invalidate-only recovered events, and a multi-signal exit gate that refuses to close on an empty
  page — none of which is a live-provider conformance claim;
- an isolated RFC 8693 downstream broker that reauthenticates the subject, fixes the FHIR
  resource/audience and exact SMART Patient/Consent scopes, rejects token passthrough or broadened
  credentials, and redacts the result;
- a central immutable authorization request/decision contract with operation scopes, versioned
  codes, and enforceable obligations;
- deny-by-default corpus admission with a promotion record for every candidate, second-person
  approval, checksum and provenance binding, supersession and freshness, and content scanning that
  refuses instruction-shaped text, credential material, and unsafe characters;
- retrieval that computes the authorized partition *before* scoring anything, rechecks integrity and
  freshness after selection, abstains when two current sources conflict, and renders retrieved text
  as data that cannot close its own envelope;
- corpus versions whose identity binds labels as well as text, with durable activation and audited
  rollback that survives restart;
- a gated retrieval golden set — security cases at 100% and quality cases at 100% against a 90%
  floor — enforced by `make verify` and CI;
- pre-authorized FHIR R4-shaped synthetic patient access with security labels, provenance checks,
  explicit Consent, denial-before-full-read, post-read context recheck, and minimum-summary projection;
- a deterministic Synthea v4.0.0-derived 12-resource FHIR R4 dataset with checksummed lineage,
  direct-identifier removal, synthetic/restricted labels, and tamper detection;
- a pinned disposable HAPI FHIR v8.10.0-3 loopback lab and shared in-memory/HTTP broker contract;
- Part 2-sensitive, cross-patient, cross-facility, role, and purpose denials;
- a bounded agent loop around an untrusted model: an explicit transition table, three static tools
  with one write capability, prohibited capability names refused at registry construction,
  authorization re-derived from the caller on every tool call, and no execute tool at all;
- model output validated for grounding, citation authenticity, secret disclosure, and clinical scope
  before use, refused rather than truncated, with step, tool, output, and deadline budgets that halt
  a looping run;
- independent durable MODEL/READ/WRITE kill switches, and a hosted-provider seam that refuses every
  call until its vendor criteria are approved;
- non-clinical action proposals with independent, digest-bound human approval;
- signed approval receipts, expiry, reauthorization, and idempotent execution;
- shared transactional workflow/audit state with in-memory and single-node SQLite adapters, atomic
  rollback, restart recovery, concurrency controls, tamper detection, and fail-closed readiness;
- 379 passing default-suite tests plus one HAPI integration test, 86.14% coverage against the 85%
  floor, under strict lint and typing gates, green on a hosted CI runner;
- a typed, CI-enforced control system covering 70 requirements, 25 risks, and 78 scenarios;
- 31 canonical controls with 54 verification definitions, 27 evidence definitions, framework
  mappings, and honest implemented/partial/planned status; and
- an AI system card plus simulated M02 multidisciplinary, M03 control-owner, and M04 owner reviews,
  with M04 closed as a conditional pass on four time-bound exception records.

The local identity, delegation, data, retrieval, state, and audit adapters are deliberately
non-production baselines. SQLite is a single-node simulation; the token-exchange transport and HAPI
lab are not connected; treatment relationship and Consent are fixtures rather than authoritative
sources; retrieval is deterministic keyword matching over an in-memory corpus, so the M05 thresholds
measure the controls and say nothing about answer quality; the model adapter is a deterministic
policy rather than a language model, so M06 proves containment and not capability; and no local
signal client has ever
contacted a live provider, so nothing here demonstrates an enterprise TLS/mTLS edge, provider
lifecycle, production flood controls, a deployed HA scheduler, metrics/SIEM/page delivery, or
SSF/CAEP/SMART conformance.

Those gaps are not hand-waved. Each is recorded as a time-bound exception — `NS-EXC-001` through
`NS-EXC-004` in [docs/assurance/exceptions/](docs/assurance/exceptions/) — with compensating
controls, objective stop conditions, and a remediation owner, and the limitations are listed in
[PROJECT_STATUS.md](PROJECT_STATUS.md).

## Safety boundary

Polaris v1 may retrieve approved policies, access minimal authorized synthetic patient context,
draft administrative content, and propose approval-gated non-clinical tasks. It may not diagnose,
prescribe, recommend treatment, triage, autonomously write to an EHR, communicate with patients, or
use real PHI.

## Quick start

Requirements: uv and Python 3.12 or newer (uv can provision Python). CI pins Python 3.13.11.

```bash
uv sync --locked --all-groups
make verify
cp .env.example .env
# Replace every development key in .env with a unique local value.
make run
```

The OpenAPI UI is available at `http://127.0.0.1:8000/docs` outside production mode. Authentication
test fixtures in `tests/conftest.py` show the required claims and purpose-of-use header. The test
suite is the current supported end-to-end demonstration path.

For the optional disposable FHIR interoperability lab, install Docker Desktop and run:

```bash
make fhir-up
make fhir-seed
make fhir-integration
make fhir-down
```

The lab is synthetic-only, loopback-only, and intentionally has no production authentication.

## Start here

- [Durable Codex instructions](AGENTS.md)
- [Current status and next increment](PROJECT_STATUS.md)
- [Master roadmap](docs/program/master-roadmap.md)
- [System context and trust boundaries](docs/architecture/system-context.md)
- [Authorization decision table](docs/architecture/authorization-decision-table.md)
- [Transactional state, audit, and recovery ADR](docs/architecture/decisions/ADR-006-transactional-state-audit-and-recovery.md)
- [Secure retrieval boundary ADR](docs/architecture/decisions/ADR-010-secure-retrieval-boundary.md)
- [Bounded agent and model boundary ADR](docs/architecture/decisions/ADR-011-bounded-agent-and-model-boundary.md)
- [Durable continuous-access identity signals ADR](docs/architecture/decisions/ADR-007-durable-identity-signals.md)
- [Okta continuous-access reference profile ADR](docs/architecture/decisions/ADR-008-okta-continuous-access-profile.md)
- [Okta gap-recovery runbook](docs/operations/okta-continuous-access-gap-recovery.md)
- [Regulatory/framework applicability](docs/compliance/applicability-matrix.md)
- [Initial risk register](docs/risk/risk-register.md)
- [M02 requirements baseline](docs/risk/requirements-baseline.md)
- [M02 multidisciplinary review](docs/assurance/M02-multidisciplinary-review.md)
- [Control statement and evidence standard](docs/governance/control-standard.md)
- [AI system card](docs/governance/ai-system-card.md)
- [M03 control-owner review](docs/assurance/M03-control-owner-review.md)
- [M03 traceability report](evidence/reports/M03-traceability-report.md)
- [M04 gate decision](evidence/milestones/M04-gate-decision.md)
- [M05 secure retrieval evidence](evidence/milestones/M05-secure-retrieval.md)
- [M06 bounded agent evidence](evidence/milestones/M06-bounded-agent.md)
- [M04 owner review](docs/assurance/M04-owner-review.md)
- [Deferral exception records](docs/assurance/exceptions/)
- [Security threat model](docs/risk/threat-model.md)
- [Privacy impact assessment](docs/risk/privacy-impact-assessment.md)
- [Clinical safety hazards](docs/risk/clinical-safety-hazard-analysis.md)
- [Release gates](docs/assurance/release-gates.md)
- [Local verification evidence](evidence/milestones/M01-local-verification.md)
- [M04 identity/FHIR foundation evidence](evidence/milestones/M04-identity-fhir-foundation.md)
- [Hosted CI evidence](evidence/milestones/M04-hosted-ci.md)
- [Production persistence and recovery targets ADR](docs/architecture/decisions/ADR-009-production-persistence-and-recovery-targets.md)
- [Persistence and recovery exercise specification](docs/operations/persistence-recovery-exercises.md)
- [Authoritative relationship and Consent integration design](docs/architecture/authoritative-relationship-and-consent-integration.md)
- [Active delivery backlog](docs/program/backlog.md)
- [Recruiter package plan](portfolio/README.md)
- [Training product plan](training/README.md)

## Important disclaimer

This is an educational simulation using synthetic data. It is not a production healthcare system,
legal advice, a HIPAA certification, an FDA clearance, or evidence that any real organization is
compliant or production ready.

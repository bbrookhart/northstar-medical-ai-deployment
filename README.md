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
  constrained System Log cursor adapter that minimizes the documented SSF source events while
  explicitly stopping before durable gap application or any live-provider conformance claim;
- an isolated RFC 8693 downstream broker that reauthenticates the subject, fixes the FHIR
  resource/audience and exact SMART Patient/Consent scopes, rejects token passthrough or broadened
  credentials, and redacts the result;
- a central immutable authorization request/decision contract with operation scopes, versioned
  codes, and enforceable obligations;
- approved/versioned policy retrieval with citations and safe abstention;
- pre-authorized FHIR R4-shaped synthetic patient access with security labels, provenance checks,
  explicit Consent, denial-before-full-read, post-read context recheck, and minimum-summary projection;
- a deterministic Synthea v4.0.0-derived 12-resource FHIR R4 dataset with checksummed lineage,
  direct-identifier removal, synthetic/restricted labels, and tamper detection;
- a pinned disposable HAPI FHIR v8.10.0-3 loopback lab and shared in-memory/HTTP broker contract;
- Part 2-sensitive, cross-patient, cross-facility, role, and purpose denials;
- non-clinical action proposals with independent, digest-bound human approval;
- signed approval receipts, expiry, reauthorization, and idempotent execution;
- shared transactional workflow/audit state with in-memory and single-node SQLite adapters, atomic
  rollback, restart recovery, concurrency controls, tamper detection, and fail-closed readiness;
- 310 passing default-suite tests plus one HAPI integration test, 85.66% coverage against the 85%
  floor, under strict lint and typing gates;
- a typed, CI-enforced control system covering 70 requirements, 25 risks, and 78 scenarios;
- 31 canonical controls with 45 verification definitions, 22 evidence definitions, framework
  mappings, and honest implemented/partial/planned status; and
- an AI system card plus simulated M02 multidisciplinary and M03 control-owner reviews.

The local identity, delegation, data, retrieval, state, and audit adapters are deliberately
non-production baselines. In particular, SQLite is a single-node simulation, the token-exchange
transport and HAPI lab are not connected, and the local signal clients/adapters do not prove an
enterprise TLS/mTLS edge, live provider lifecycle or approved unsolicited-event enablement and
production edge/global flood controls, durable provider-page application/cursor recovery, a
deployed HA scheduler, metrics/SIEM/page delivery, live provider conformance,
approved continuous-access objectives, or SSF/CAEP/SMART conformance. Their
limitations are explicit in [PROJECT_STATUS.md](PROJECT_STATUS.md).

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

- [Master Codex prompt](CODEX_MASTER_PROMPT.md)
- [Durable Codex instructions](AGENTS.md)
- [Current status and next increment](PROJECT_STATUS.md)
- [Master roadmap](docs/program/master-roadmap.md)
- [System context and trust boundaries](docs/architecture/system-context.md)
- [Authorization decision table](docs/architecture/authorization-decision-table.md)
- [Transactional state, audit, and recovery ADR](docs/architecture/decisions/ADR-006-transactional-state-audit-and-recovery.md)
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
- [Security threat model](docs/risk/threat-model.md)
- [Privacy impact assessment](docs/risk/privacy-impact-assessment.md)
- [Clinical safety hazards](docs/risk/clinical-safety-hazard-analysis.md)
- [Release gates](docs/assurance/release-gates.md)
- [Local verification evidence](evidence/milestones/M01-local-verification.md)
- [M04 identity/FHIR foundation evidence](evidence/milestones/M04-identity-fhir-foundation.md)
- [Active delivery backlog](docs/program/backlog.md)
- [Recruiter package plan](portfolio/README.md)
- [Training product plan](training/README.md)

## Important disclaimer

This is an educational simulation using synthetic data. It is not a production healthcare system,
legal advice, a HIPAA certification, an FDA clearance, or evidence that any real organization is
compliant or production ready.

# Project Polaris Status

**Status date:** 2026-08-11  
**Current milestone:** M04 — Identity, policy, and synthetic FHIR  
**Last gate:** M03 passes; M04 identity/delegation/continuous-access, policy/Synthea/Consent/HAPI, and single-node transactional-state slices are locally verified, but the M04 gate remains open  
**Overall status:** On track for the authorized synthetic simulation scope

## Completed

- Dedicated Git repository and resumable Codex operating context
- End-to-end master prompt and evidence-gated master roadmap
- Enterprise profile, charter, stakeholder RACI, approved/prohibited use, and AI risk tier
- Dated regulatory/framework applicability matrix with primary-source register
- System context, logical flow, trust boundaries, security invariants, and initial 25-item risk register
- Provider-neutral Python/FastAPI scaffold with locked dependencies
- Strict secure configuration and separate JWT, audit, and approval cryptographic keys
- Synthetic policy corpus and patient records, including Part 2-sensitive test data
- Deterministic policy authorization for role, facility, assignment, purpose, and sensitivity
- Grounded policy retrieval with approved/versioned citations, input normalization, and abstention
- Approval-gated administrative action with exact digest binding, independent approver, expiry,
  signed receipt, executor authorization, requester reauthorization, and idempotency
- Tamper-evident HMAC audit chain and controlled verification endpoint
- Local CI-equivalent quality gate and milestone evidence record
- M02 data-flow inventory, AI impact assessment, privacy impact assessment, LINDDUN-style privacy
  threat model, STRIDE/agent threat model, OWASP/ATLAS risk crosswalk, abuse/misuse cases,
  clinical-safety hazard analysis, and 70-item normative requirements baseline
- Simulated multidisciplinary M02 review with nine findings, conditional development decision, and
  explicit separation from real Legal, Privacy, Clinical Safety, and independent approval
- M03 control/evidence standard, 31-control canonical library, framework source registry, 28-item
  verification catalog, 21-item evidence catalog, AI system card, and assurance templates
- M04 traceability extension to 45 verification definitions and 22 evidence definitions without
  changing the 31-control canonical baseline
- Machine-readable coverage of all 70 requirements, 25 registered risks, and 78
  threat/privacy/misuse/safety scenarios, enforced by typed validation and CI drift checks
- Simulated control-owner M03 review and deterministic JSON/Markdown traceability reports
- Active gated backlog plus recruiter-portfolio and 12-module training-product scaffolds
- Weekly dependency and GitHub Actions update configuration
- M04 identity/delegation, central-authorization, and synthetic-FHIR architecture decisions
- Injectable RS256 OIDC access-token/JWKS verifier with typed claims, strict issuer/audience/type/
  algorithm checks, operation scopes, token/subject revocation, and no production HS256 fallback
- Trusted OIDC discovery/JWKS adapter with exact issuer binding, administrator-allowlisted HTTPS
  origins, no redirects, bounded documents/cache, rotation refresh cooldown, and known-key maximum
  stale age
- Strict local final-SSF/CAEP signed-SET subset for session revocation, credential change, and
  token-claim change,
  durable token/subject invalidation, monotonic out-of-order handling, replay/collision defense,
  atomic audit/checkpoint state, fail-closed schema v8 migration, restart recovery, and stale-stream
  denial
- Disabled-by-default RFC 8935-shaped HTTP push endpoint with transmitter authentication before SET
  cryptography, exact stream/media binding, incremental request-size enforcement, persisted
  transmitter context, empty `202` acknowledgement, registered SET errors, and fail-closed
  collision/state behavior
- Injected final-SSF transmitter discovery/status/verification-request client with correct
  path-scoped well-known URL, exact final-version/issuer/origin binding, redirect and response
  bounds, call-time redacted management authorization, exact non-cacheable status binding, failed-
  rediscovery invalidation, and pending-only asynchronous verification semantics
- Strict injected final-SSF configuration/status/delete/subject-management contracts with exact
  receiver audience, fixed HTTPS push destination, complete required-event delivery, explicit
  `default_subjects=NONE`, optimistic transmitter-state binding, safe pending-mutation rejection,
  fixed-issuer bounded subjects, `verified=false`, and non-enumerating acknowledgements
- Durable final-SSF verification receipt/correlation with request persistence before dispatch,
  digest-only single-use state, exact stream binding, atomic signal/health commit, registered
  `invalid_state`, synchronous-callback and ambiguous-failure races, restart, timeout, stale-success,
  same-timestamp ordering, tamper detection, and fail-closed health/readiness semantics
- Explicit final-SSF unsolicited-verification policy with default rejection, opt-in delivery-only
  receipt, durable per-stream quota, replay safety, atomic rollback, restart/tamper protection, and
  strict isolation from receiver-correlated health
- Durable final-SSF desired/observed status reconciliation with intent-before-dispatch,
  `OUTCOME_UNKNOWN` ambiguity preservation, exact response binding, signed `stream-updated` SET
  handling, digest-only reasons, monotonic observation ordering, synchronous-callback recovery,
  bounded rate-limit-aware safe status-read recovery, no automatic write replay, concurrent-result
  supersession, schema v8 restart/tamper protection, and paused/disabled/drifted/stale
  authorization-health denial
- Durable SSF recovery controller seam with external-tick `run_due`, next-due cadence, atomic bounded
  leases, duplicate-run suppression, expired-lease reclaim, stale-worker result suppression,
  warning/critical escalation and success clear, clock rollback denial, and restart/tamper evidence
- Okta Identity Engine reference profile with documented CAEP source-event mapping, explicit
  final-SSF payload-conformance uncertainty, and a separately authorized System Log cursor adapter
  that constrains origin/path/filter/order/limit, minimizes records, classifies provider failures,
  and rejects malformed/duplicate/substituted pages without claiming durable gap recovery
- RFC 8693 token-exchange broker contract with subject-token reauthentication, fixed FHIR
  resource/audience, exact SMART v2 Patient/Consent scopes, five-minute maximum lifetime,
  cryptographic response validation, passthrough/broadening denial, and secret-redacted output
- Immutable central authorization request/decision contract with versioned codes, allow-only
  obligations, and route-independent purpose enforcement
- Pre-authorized synthetic FHIR R4 contract broker with security labels, minimum-view projection,
  denial-before-full-read, dependency/schema/label/context failure handling, and minimized audit
- Pinned Synthea v4.0.0 generation toolchain and deterministic 3-patient transform with source
  checksums, direct-identifier removal, Restricted/SYNTHETIC labels, Consent, Provenance, and tamper tests
- Pinned HAPI FHIR v8.10.0-3 disposable loopback lab with non-root/read-only runtime, dropped
  capabilities, bounded resources, restricted CORS, disabled MCP/API docs, and no persistent data
- Bounded HTTP FHIR gateway with fixed HTTPS/explicit-localhost policy, constructed paths, response
  limits/timeouts, minimum pre-authorization lookup, explicit Consent states, and safe error mapping
- Shared in-memory/HAPI broker contract and post-authorization Consent/context recheck
- Shared transaction contract with copy-on-write in-memory oracle and versioned strict SQLite local
  adapter for proposals, approvals, execution identities, and audit events
- Atomic workflow/audit commits, rollback-only nested failure handling, restart-safe idempotency,
  concurrent single-task execution, integrity/schema/tamper checks, and fail-closed readiness
- Transactional state/recovery ADR separating the local simulation from required PostgreSQL/HA,
  backup/PITR, retention/WORM audit, and external-task outbox/reconciliation designs

## Not yet assessed or approved

- Hosted GitHub Actions execution and branch-protection behavior
- Enterprise IdP/STS integration, confidential workload client authentication and TLS/mTLS signal
  edge, live-provider SSF discovery/lifecycle, approved unsolicited-event enablement and
  production edge/global rate limits,
  live Okta/final-SSF conformance, atomic provider-page application/cursor and gap-incident state,
  complete gap recovery, deployed HA scheduling, metric/SIEM/page delivery,
  approved continuous-access objectives,
  authoritative entitlement sources, and SMART authorization/interoperability conformance
- Production PostgreSQL/HA persistence, backup/restore and measured RTO/RPO, approved retention/legal
  hold, immutable audit/SIEM, and external-task outcome reconciliation
- Attributable real-world owner, Legal, Privacy, Clinical Safety, Records, and independent approval
- Any pilot/production, hosted-model, real-PHI, clinical, compliance, or certification decision

## Verification evidence

| Gate | Result |
|---|---|
| Formatting | Pass |
| Ruff lint/security rules | Pass |
| Strict mypy across `src` and `tests` | Pass; 56 source/test files |
| Pytest | Pass; 310 default-suite tests plus 1 HAPI integration test |
| Coverage | 85.66%; enforced floor 85% |
| Governance traceability | Pass; 70/70 requirements, 25/25 risks, 78/78 scenarios |
| Generated-report drift check | Pass |
| Hosted GitHub Actions | Not assessed; workflow created |

See `evidence/milestones/M01-local-verification.md` for the M01 result and
`evidence/milestones/M03-local-verification.md`,
`evidence/milestones/M04-identity-fhir-foundation.md`, and
`evidence/reports/M03-traceability-report.md` for the current assurance result.

## Decisions

| ID | Decision | Status |
|---|---|---|
| ADR-000 | Use synthetic data only and control it as restricted health data | Accepted |
| ADR-001 | Begin with deterministic retrieval/orchestration | Accepted |
| ADR-002 | Keep hosted models behind a provider-neutral adapter | Accepted |
| ADR-003 | Require typed asymmetric API access tokens and forbid incoming-token passthrough | Accepted for M04 simulation |
| ADR-004 | Centralize deterministic authorization behind an immutable request/decision contract | Accepted for M04 simulation |
| ADR-005 | Put synthetic FHIR R4 access behind a pre-authorized minimizing read broker | Accepted; local Synthea/HAPI slice verified |
| ADR-006 | Store workflow and audit transitions atomically behind a shared state boundary | Accepted; single-node SQLite local slice verified |
| ADR-007 | Persist strict signed continuous-access events, authenticate bounded push delivery, strictly manage and correlate verification of streams, and fail authentication/health on stale state | Accepted; strict scripted/local SSF/CAEP and RFC 8935-shaped subsets verified |
| ADR-008 | Use Okta as the named M04 reference profile and its constrained System Log cursor feed as compensating gap evidence, never mislabeled as SSF replay | Accepted for local simulation; live conformance, durable application/cursor state, procurement, and production recovery unverified |

## Open risks and limitations

| ID | Risk or limitation | Treatment |
|---|---|---|
| LIM-001 | Scope may expand faster than assurance depth | Enforce roadmap gates and v1 boundary |
| LIM-002 | Documentation may drift from behavior | Trace requirements/controls/tests/evidence in M03 |
| LIM-003 | Discovery/rotation, delegation, final-SSF management/recovery/verification, and the Okta System Log gap-feed boundary use generated identities and injected/scripted transports; the Okta adapter does not apply pages or persist cursors; default fixtures still use HS256 | Add enterprise IdP/STS, confidential-client transport, TLS/mTLS edge, live Okta/final-SSF conformance and lifecycle, approved unsolicited-event limits, atomic page application/cursor and gap state, HA scheduling plus metric/SIEM/page delivery, authoritative entitlements, and approved objectives; never enable HS256 or local bearer adapters in production or attach the unauthenticated HAPI lab |
| LIM-004 | Local SQLite state/audit is single-node and shares one trust domain; disposable HAPI H2 is non-durable; neither provides production HA, backup/PITR, retention/WORM, or external-task recovery | Design and test PostgreSQL/HA, backup/restore, approved records controls, protected audit export, and outbox/outcome-unknown reconciliation before pilot |
| LIM-005 | Deterministic keyword retrieval is not representative of model/RAG quality | Preserve baseline; introduce evaluated adapters in M05–M06 |
| LIM-006 | Hosted CI has not run | Run workflow after repository publication and record result |
| LIM-007 | Retention/deletion/legal-hold periods are undecided | `BLK-001`; obtain Records/Privacy/Legal approval and exercise deletion before pilot |
| LIM-008 | Human factors, fixed emergency behavior, and accessible trusted UI are incomplete | `BLK-003`; implement and run clinician/representative-user validation |
| LIM-009 | Provider due diligence and operating/resilience evidence do not exist | `BLK-004`/`BLK-005`; no hosted model or pilot until verified |
| LIM-010 | Exact OWASP GenAI LLM Top 10 2026 category mapping is provisional | `BLK-006`; acquire and review the official category artifact before exact coverage claims |
| DEC-001 | Repository and training-content licensing/IP terms are undecided | Select deliberately before public release; do not assume open-source rights |

## Next safe increment

Continue M04 by atomically applying normalized Okta pages and advancing a durable compare-and-swap
cursor/gap incident record, then bind recovery exit to current status plus a fresh correlated
verification. Add live synthetic-tenant final-SSF conformance evidence only after approved
credentials/TLS, external HA scheduler and metric/SIEM/page integration, approved unsolicited-event
enablement/limits, and owner approval of the continuous-access SLO. In parallel, complete
authoritative relationship/Consent integration design, the PostgreSQL/outbox recovery-test
specification, and simulated M04 owner review. Preserve the deterministic identity/delegation/signal
clients, local HAPI, and
transactional-state adapters as security oracles and add no real PHI, hosted model, production
service, or broader autonomy.

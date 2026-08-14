# Project Polaris Status

**Status date:** 2026-08-14  
**Current milestone:** M10 — Operations and incident readiness  
**Last gate:** **M09 does not pass** — every attack was contained but four high-severity findings are open (`EVD-M09-001`), so no release may proceed and no residual risk is accepted; M08 is a conditional pass under `NS-EXC-005`; M07 does not pass for want of human-factors evidence (`BLK-003`)  
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
- M04 traceability extension to 46 verification definitions and 24 evidence definitions without
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
- Version control landing of the previously untracked tree and the first green hosted GitHub Actions
  run of the full quality gate at a named revision (`EVD-M04-002`)
- Durable Okta gap-recovery page application: compare-and-swap cursor sequencing, exactly-once
  application with duplicate suppression, invalidate-only recovered events, no checkpoint
  advancement, atomic rollback, restart safety, and a multi-signal exit gate that refuses to close on
  an empty page alone (`VER-AUT-030`, schema 9)
- `ADR-009` production persistence topology, audit custody separation, and recovery objectives, with
  a six-exercise specification whose results table is deliberately empty
- `NS-ARC-002` authoritative treatment-relationship and Consent integration design
- Four owner-approved, time-bound exception records (`NS-EXC-001` to `NS-EXC-004`) and the simulated
  M04 owner review with five findings
- Deny-by-default corpus admission with promotion records for admitted and refused candidates,
  second-person approval, checksum and provenance binding, supersession, freshness, and content
  scanning for instruction-shaped text, credential material, and unsafe characters (`ADR-010`)
- Retrieval authorization computed before any scoring, post-selection integrity and freshness
  recheck, topic-conflict abstention, and data-only context rendering that a chunk cannot escape
- Corpus manifest identity binding labels as well as text, plus durable schema-10 corpus activation
  with audited rollback that survives restart
- A gated retrieval golden set — security cases 100% required and met, quality cases 90% required
  and 100% met — enforced by `make verify` and CI (`EVD-M05-002`)
- Hosted CI now also runs the retrieval evaluation and synthetic dataset checks, closing `M04-F1`
- A bounded agent loop with an explicit transition table, a three-tool least-agency registry that
  refuses prohibited capability names at construction, per-call authorization re-derived from the
  principal, and no execute tool (`ADR-011`)
- Output validation for structure, size, grounding, citation authenticity, secret and
  context-envelope disclosure, and clinical scope, with refusal rather than truncation
- Step, tool-call, write, output, and deadline budgets that halt a looping or oversized run
- Model requests that carry no credential, identity, or prior-run state, and an orchestrator with
  nowhere to hold cross-session memory
- Independent durable MODEL/READ/WRITE kill switches (schema 11) that survive restart
- An inert hosted-provider seam that refuses every call while `REQ-AI-002` and `BLK-004` are open
- A compromised-model suite in which scripted hostile intents cannot widen retrieval, read an
  unassigned patient, execute, draft clinical direction, emit secrets, answer ungrounded, or exceed
  a bound
- Server-side inert rendering of untrusted text against script, attribute, executable-scheme,
  terminal-escape, bidirectional-override, and control-character cases (`ADR-012`)
- An approval preview whose fields and digest are both derived from the canonical action, with a
  display-binding check that fails on any divergence, behind approver authorization
- Workflow states where only execution implies completion, labels and severity that cannot disagree
  with state, and uncertainty a surface cannot drop to render an abstention as an answer
- Fixed emergency-channel routing whose result type has nowhere to record an urgency assessment,
  checked before the model is consulted
- An offline release supply-chain gate enforcing SHA-pinned Actions, digest-pinned images, bounded
  and hashed dependencies, container and compose hardening, and a tracked-secret scan whose only
  exemptions are the detector modules, each proven by a test that breaks it (`ADR-013`)
- A CycloneDX 1.6 SBOM built from the lockfile and an AIBOM generated from the running model, corpus,
  tool, bound, kill-switch, and evaluation definitions, both committed and drift-checked
- A hardened application container, built and smoke-tested: non-root on a read-only filesystem, no
  package manager, compiler, or fetch tool, serving both health endpoints
- An adversarial campaign of 21 cases across all 14 classes `REQ-SDL-004` requires, run against a
  stack rebuilt per case, each naming the control expected to stop it; all contained, deterministic,
  and class coverage asserted by test
- A release evaluation declaring all 11 `REQ-SDL-003` dimensions with four honestly not assessed,
  separating blocking gaps from missing evidence so `release_ready` is false despite zero blocking
  gaps
- A remediation ledger and a simulated independent review that refuses a release rather than
  reclassifying findings

## Not yet assessed or approved

- Branch protection and change control on `main` (rejected by the GitHub API for a private
  repository on this plan); repository publication and licensing (`DEC-001`)
- Enterprise IdP/STS integration, confidential workload client authentication, and a TLS/mTLS
  signal edge (`NS-EXC-001`)
- Live-provider SSF discovery and lifecycle, approved unsolicited-event enablement, production
  edge/global rate limits, and live Okta/final-SSF conformance (`NS-EXC-002`)
- Deployed HA scheduling, metric/SIEM/page delivery, and approved continuous-access objectives
  (`NS-EXC-003`)
- Production PostgreSQL/HA persistence, backup/restore and measured RTO/RPO, approved retention/legal
  hold, immutable audit custody, and external-task outcome reconciliation (`NS-EXC-004`)
- Authoritative treatment-relationship and Consent sources, authoritative entitlement sources, and
  SMART authorization/interoperability conformance
- Attributable real-world owner, Legal, Privacy, Clinical Safety, Records, and independent approval
- Any pilot/production, hosted-model, real-PHI, clinical, compliance, or certification decision

## Verification evidence

| Gate | Result |
|---|---|
| Formatting | Pass |
| Ruff lint/security rules | Pass |
| Strict mypy across `src` and `tests` | Pass; 90 source/test files |
| Pytest | Pass; 436 default-suite tests plus 1 HAPI integration test |
| Coverage | 87.06%; enforced floor 85% |
| Release supply-chain policy | Pass; 0 blockers across 4 pinned definitions |
| Adversarial campaign | Pass; 21/21 contained across 14/14 classes |
| Release readiness | **Not ready**; 4 dimensions unassessed, 4 high findings open |
| Retrieval evaluation | Pass; security 100% (floor 100%), quality 100% (floor 90%) |
| Governance traceability | Pass; 70/70 requirements, 25/25 risks, 78/78 scenarios |
| Generated-report drift check | Pass |
| Hosted GitHub Actions | Pass; `quality` job green at a named revision (`EVD-M04-002`) |
| Branch protection | Not assessed; rejected for a private repository on this plan |

See `evidence/milestones/M01-local-verification.md` for the M01 result and
`evidence/milestones/M03-local-verification.md`,
`evidence/milestones/M04-identity-fhir-foundation.md`,
`evidence/milestones/M04-hosted-ci.md`, `evidence/milestones/M04-gate-decision.md`, and
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
| ADR-008 | Use Okta as the named M04 reference profile and its constrained System Log cursor feed as compensating gap evidence, never mislabeled as SSF replay | Accepted for local simulation; durable compare-and-swap page application and exit gate verified; live conformance, procurement, and production recovery unverified |
| ADR-009 | Specify the production persistence topology, audit custody separation, and recovery objectives as testable targets rather than implemented capability | Accepted as a design target; every exercise result is not assessed |
| ADR-010 | Admit corpus sources by recorded decision, authorize before scoring, treat retrieved text as data, and make corpus versions identifiable and rollback-capable | Accepted; local synthetic corpus verified |
| ADR-011 | Treat the model as an untrusted requester behind a bounded loop, re-derive authorization per call, validate output before use, and keep the hosted-provider seam inert | Accepted; compromised-model containment verified with a deterministic adapter |
| ADR-012 | Render untrusted text inert server-side, derive the approval preview and its digest from one canonical action, and make state, uncertainty, and emergency routing structural | Accepted; contract verified, human-factors evidence outstanding |
| ADR-013 | Enforce an offline release supply-chain gate, generate the SBOM and AIBOM from authoritative sources, and harden the runtime image | Accepted; signing, provenance, and scanning deferred under `NS-EXC-005` |

## Open risks and limitations

| ID | Risk or limitation | Treatment |
|---|---|---|
| LIM-001 | Scope may expand faster than assurance depth | Enforce roadmap gates and v1 boundary |
| LIM-002 | Documentation may drift from behavior | Trace requirements/controls/tests/evidence in M03 |
| LIM-003 | Discovery/rotation, delegation, final-SSF management/recovery/verification, and the Okta System Log gap feed use generated identities and injected/scripted transports; treatment relationship and Consent are fixtures; default fixtures still use HS256 | `NS-EXC-001` to `NS-EXC-003` with stop conditions and expiries; integration designs in `ADR-003` and `NS-ARC-002`; never enable HS256 or local bearer adapters in production or attach the unauthenticated HAPI lab |
| LIM-004 | Local SQLite state/audit is single-node and shares one trust domain; disposable HAPI H2 is non-durable; neither provides production HA, backup/PITR, retention/WORM, or external-task recovery | `NS-EXC-004`; `ADR-009` specifies the topology, custody separation, and objectives, and `docs/operations/persistence-recovery-exercises.md` specifies six exercises — none executed — that must pass before pilot |
| LIM-005 | Deterministic keyword retrieval is not representative of model/RAG quality; the M05 thresholds measure the controls, not answer quality | Preserve the baseline as the regression oracle; introduce evaluated model adapters in M06 |
| LIM-011 | Corpus content lives in memory and is rebuilt at startup; only the activation record is durable, and there is no authoritative ingestion pipeline, malware scanning, or human review workflow | Persist chunks and labels under the same integrity and retention controls as other state, and design the ingestion workflow, before any pilot |
| LIM-012 | Content scanning is pattern-based with known false negatives, and topic-conflict detection depends on honest topic tagging | Treat retrieved text as data as the primary control; expand the adversarial corpus in M09 red-team work |
| LIM-013 | The model adapter is a deterministic policy, not a language model; the compromised-model suite scripts hostile intents rather than exercising a real provider | Keep the deterministic adapter as the regression oracle; no hosted connection until `REQ-AI-002` and `BLK-004` close, then run the M09 injection campaign against it |
| LIM-014 | Agent capabilities default to enabled when no record exists, and the agent has no user-facing surface, approval workload monitoring, concurrency, retry, or cost control | Invert the default to explicit enablement before deployment; add the M07 trusted renderer, `CTL-ACT-004` monitoring, and provider-side bounds when a provider exists |
| LIM-006 | Branch protection and change control are unproven, so reviewed source changes hold by convention rather than enforcement | Enable protection at publication (gated on `DEC-001`); the CI/Makefile divergence closed in M08 |
| LIM-016 | The adversarial campaign runs against a deterministic adapter and its cases were authored by the implementer, so it encodes the same assumptions as the controls | `RT-F1`/`RT-F3`; rerun against a hosted provider once `BLK-004` closes, and obtain independent adversarial authorship before any release claim |
| LIM-015 | No artifact signature, build provenance, or vulnerability scan result exists, and the build is reproducible in the pinning sense only | `NS-EXC-005`; add non-blocking scanning with a review cadence, then provenance attestation and signing with a verification step a consumer runs, before publishing anything |
| LIM-007 | Retention/deletion/legal-hold periods are undecided | `BLK-001`; obtain Records/Privacy/Legal approval and exercise deletion before pilot |
| LIM-008 | The presentation contract and fixed emergency behavior are implemented, but no human-factors session has been run, no UI exists, and WCAG conformance is unassessed | `BLK-003`; run `NS-ASR-005` with clinician and assistive-technology participants before any pilot, and design `CTL-ACT-004` from its HF-08 result |
| LIM-009 | Provider due diligence and operating/resilience evidence do not exist | `BLK-004`/`BLK-005`; no hosted model or pilot until verified |
| LIM-010 | Exact OWASP GenAI LLM Top 10 2026 category mapping is provisional | `BLK-006`; acquire and review the official category artifact before exact coverage claims |
| DEC-001 | Repository and training-content licensing/IP terms are undecided | Select deliberately before public release; do not assume open-source rights |

## Next safe increment

Begin M10 operations and incident readiness. The campaign proved which events are detectable; the
next step is making them observable: telemetry content rules that carry correlation, decision, and
version without prohibited content, detection-as-code for the refusal and containment outcomes the
campaign produces, runbooks, and an AI incident tabletop.

Prioritise the kill, rollback, and degraded-mode exercises. `RE-F4` — recovery unassessed — is one of
the four high findings blocking a release, and it is the only one M10 can close without a real
provider, real clinicians, or a real deployment.

Three milestones now stand explicitly unfinished: M07 for want of human-factors evidence, M09 for
open high findings, and M08 conditionally under `NS-EXC-005`. None should be reported as complete.

Do not connect a hosted provider. `REQ-AI-002`'s criteria and `BLK-004`'s due diligence are both
still open, and the adapter is deliberately inert until they close.

Watch the four M04 exceptions rather than letting them lapse quietly: each expires 2027-02-13 or at
the first pilot decision, and an expired exception fails closed. Add no real PHI, hosted model,
production service, or broader autonomy.

# NS-AISC-001 — Project Polaris AI System Card

**Card status:** M04 identity/continuous-access/FHIR/transactional-state foundation increment  
**System status:** Local deterministic prototype; no hosted model connected  
**Last updated:** 2026-08-11  
**Review trigger:** Every material change and release gate

## System identity and decision boundary

Polaris is a simulated internal Northstar Medical assistant for approved policy retrieval, minimal
authorized synthetic patient context, and approval-gated non-clinical administrative follow-up
tasks. It is designed to demonstrate an enterprise AI security lifecycle, not to deliver care.

Polaris must not diagnose, prescribe, recommend treatment, assess urgency, triage, autonomously
write to an EHR, communicate with patients, use real PHI, or let model/content determine identity,
authorization, credentials, or execution. Its current AI risk tier is documented in
`docs/governance/ai-risk-tiering.md`.

## Accountable roles

| Accountability | Role |
|---|---|
| Business outcome | Business Owner |
| System lifecycle and release | AI System Owner |
| Product and human workflow | Product Owner |
| Security architecture and assurance | AI Security Lead |
| Privacy and minimum necessary use | Privacy Officer |
| Clinical safety boundary | Clinical Safety Officer |
| Data provenance and quality | Data Steward |
| Identity and access | IAM Lead |
| Operation, incident response, and recovery | SRE / IR Leads |
| Legal, compliance, records, and vendor decisions | Respective accountable roles |

These are simulated roles, not named-person assignments or real approvals.

## Users, affected people, and workflow

Current test personas represent care coordinators, nurses, compliance analysts, approvers,
executors, and audit reviewers. Patients and workforce members are affected even though patients do
not directly use the system. Material harms include wrong-patient work, delayed follow-up,
disclosure/inference, automation bias, inaccessible approval, workforce surveillance, outages, and
unsupported public claims.

The current executable path authenticates a synthetic principal, validates purpose, enforces role,
facility, assignment, sensitivity, resource, and action policy, returns an approved citation or
minimal patient view, creates a typed proposal, obtains an independent digest-bound approval, then
reauthorizes and idempotently executes a simulated task.

## Data and model inventory

| Component | Current state | Boundary |
|---|---|---|
| Patient records | Three hand-authored contract fixtures plus a deterministic Synthea v4.0.0-derived FHIR R4 Bundle with 3 Patients, 3 Consents, 3 Provenance, and 3 Organizations | HAPI v8.10.0 local readback is verified; synthetic-only bounded interoperability, not profile/SMART conformance or production EHR evidence |
| Policy corpus | Three approved/versioned seeded documents with checksums | Deterministic keyword retrieval; not a production vector index |
| Identity | Default local HMAC fixtures plus injectable RS256 verifier, trusted OIDC discovery/JWKS cache, isolated RFC 8693 broker, durable signed-SET session/credential/token invalidation, bounded push, strict final-SSF management, desired/observed and safe-read recovery, durable cadence/lease/alerts, correlated and unsolicited verification policy, and an Okta same-origin/path/filter System Log cursor read/normalization profile | HMAC and local hashed-bearer push are prohibited production designs; no enterprise IdP/STS, confidential TLS/mTLS, live Okta/final-SSF conformance/lifecycle, approved unsolicited-event controls, atomic gap-page/cursor recovery, HA scheduler/telemetry/pages, authoritative entitlements, approved objectives, or SSF/CAEP/SMART conformance evidence |
| Authorization | Frozen request contract and central deterministic policy oracle with explicit permit/deny/unknown Consent | Local in-process evaluator; no authoritative enterprise relationship/consent source or OPA parity evidence |
| Model | None connected | Deterministic services are the security regression oracle |
| Application state | Shared in-memory oracle plus single-node SQLite adapter for proposals, approvals, and execution identities | Local restart durability only; no PostgreSQL/HA, production backup/restore, or external-task outbox/reconciliation |
| Memory | No persistent agent/chat memory | Transactional workflow state is not model memory |
| Tools/actions | One typed simulated follow-up action | Non-clinical local task identity only; no real EHR or task service |
| Audit | HMAC hash chain stored atomically with workflow state in memory or SQLite | Local tamper evidence and readiness only; not an immutable/WORM SIEM or records control |

Retention, deletion, legal hold, backup expiry, and future provider-copy rules remain undecided and
block pilot/production.

## Current assurance results

As of this card version, verification passes locally and on a hosted CI runner: formatting,
lint/security rules, strict typing, 451 default-suite tests plus one HAPI integration test, and
87.45% coverage against the 85% floor. The release supply-chain policy passes with zero blockers,
and the generated SBOM and AIBOM are current. The adversarial campaign contains all 21 cases across
14 classes, and the release evaluation reports **not ready**: accessibility, performance, cost, and
recovery are unassessed and four high-severity findings are open. The retrieval golden set meets its enforced thresholds —
security cases 100% against a 100% floor, quality cases 100% against a 90% floor — which measures
the retrieval controls and not answer quality.
The validator reports 100% structural mapping of 70 requirements, 25 registered risks, and 78
THR/PRI/MIS/HAZ scenarios to the control system. This proves repository traceability—not operating
effectiveness for planned controls or residual-risk acceptance.

Implemented local mechanisms include citation/abstention, the typed non-clinical proposal boundary,
strict OIDC access-token contract tests, operation scopes, centralized policy decisions, a
pre-authorized Consent-aware minimizing FHIR broker, and reproducible Synthea/HAPI interoperability.
Durable local CAEP-style session, credential, and entitlement invalidation additionally proves
strict SET validation, monotonic ordering, replay/collision defense, restart recovery, atomic audit,
and stale-stream denial. The optional HTTP boundary proves transmitter authentication before SET
cryptography, exact stream/media binding, incremental request limits, persistence before empty
`202`, registered delivery errors, and non-acknowledgement of collision/state failure.
The outbound client additionally proves exact final-SSF well-known discovery, issuer/version/origin
binding, call-time redacted management authorization, exact receiver audience/push/event binding,
configuration/status/delete/subject request/response contracts, non-enumerating subject acceptance,
and a pending-only asynchronous verification request. The coordinator then proves persistence-before-
dispatch, digest-only single-use state, exact stream/state receipt binding, atomic signal/health
commit, restart and synchronous-callback races, durable timeout, and fail-closed health. A separate
explicit policy rejects state-less transmitter-initiated verification by default or, when opted in,
records delivery within a durable quota without improving correlated health. This does not prove
approved live-provider enablement, production flood resilience, or live named-provider conformance.
The local recovery controller further proves durable due-time and lease claims, concurrent-run
suppression, expired-lease reclaim, stale-worker rejection, and warning/critical escalation/clear.
An Okta reference profile now proves a separately authorized and minimized System Log cursor
read/normalization boundary for the documented SSF source events, including cursor-substitution and
malformed-page denial. It does not atomically apply a page, persist a cursor, clear a gap, or prove
live final-SSF conformance. The recovery controller remains an invocation and alert-state seam—not a
deployed scheduler, delivered page, or measured SLO.
The local workflow/audit store also proves atomic rollback, restart-safe state, concurrent
idempotency, schema/version checks, tamper detection, and fail-closed readiness.
Other controls are deliberately `partial` or `planned`;
their exact statuses and evidence are in `governance/control-library.json` and the generated report.

## Security, privacy, and safety posture

- The model is assumed compromiseable and is never an authorization or credential boundary.
- Sensitive access is server-authorized before release; denied patient access conceals existence.
- A full FHIR resource is fetched only after contextual policy allows an explicit permit Consent;
  labels, source, resource identity, facility, Consent, and response schema are rechecked before a
  minimum view is returned.
- API token verification constrains issuer, audience, type, algorithm, key ID, age, claims, and local
  revocation. Signed continuous-access events can invalidate access but cannot grant entitlements;
  signed claims still never authorize a patient or action by themselves.
- Retrieved/user text is untrusted, normalized, and cannot create tool authority.
- Writes require independent approval, canonical digest binding, signed receipt, expiry, execution
  reauthorization, transactional single-use state, and idempotency.
- Clinical action content is deterministically rejected, but a complete fixed emergency path and
  clinician-reviewed adversarial suite are not yet implemented.
- Routine audit records metadata rather than raw patient payloads, but production telemetry,
  detection, retention, and incident evidence do not yet exist.

## Known limitations and prohibited claims

Polaris is not ready for pilot, production, real PHI, clinical use, or a hosted model. Enterprise
IdP/STS integration, confidential downstream client authentication, enterprise TLS/mTLS signal
edge, live-provider lifecycle or approved unsolicited-event enablement and production edge/global
flood controls, live provider conformance, atomic provider-page application/cursor recovery,
deployed HA scheduler/metrics/page delivery, authoritative entitlement
sources and approved continuous-access objectives, enterprise consent/relationship sources and
SMART enforcement,
PostgreSQL/HA and tested
backup/restore/retention, external-task outbox/reconciliation, production policy/task/KMS/audit/SIEM
adapters, production RAG, provider due diligence, accessible UI and
human-factors validation, detection/response, supply-chain attestation, kill/rollback, resilience,
and retirement evidence remain future gates.

No artifact may call Polaris HIPAA compliant, clinically validated, FDA cleared, independently
certified, production ready, or deployed at a real enterprise. Framework mappings are engineering
crosswalks, not conformity determinations. The exact OWASP GenAI LLM Top 10 2026 category mapping
remains provisional because the official category artifact endpoint was unavailable during review.

## Monitoring, incident, and change expectations

Before pilot, Northstar would approve signals and stop thresholds for unauthorized access, label
loss, prompt/corpus poisoning, citation/source defects, unsafe clinical scope, wrong/duplicate
tasks, approval fatigue, data loss, resource exhaustion, drift, safety events, complaints, subgroup
performance, and control disablement. Independent read/write/model kill switches, preservation,
rollback, fallback, reconciliation, backup/restore, RTO, and RPO must be exercised.

Any change to model, prompt, corpus, policy, tool, provider, data, population, jurisdiction,
integration, user experience, autonomy, or deployment environment triggers impact reassessment,
versioned evaluation, traceability refresh, and an attributable release decision.

## Open gate blockers

The canonical blockers are `BLK-001` through `BLK-006` in
`governance/traceability.json`. No project status or portfolio narrative may hide or silently close
them. Closure requires the named planned verification/evidence and approval by actual accountable
people in a real deployment.

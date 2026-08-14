# M04 Gate Decision — Identity, Policy, Consent, FHIR, and Transactional State

**Evidence ID:** EVD-M04-003  
**Date:** 2026-08-13  
**Scope:** Local synthetic simulation, now under version control with hosted CI  
**Decision:** **Conditional pass**, on four owner-approved time-bound exceptions  
**Verified revision:** `codex/main` at the commit recorded in the verification section

## What changed since EVD-M04-001

`EVD-M04-001` recorded the M04 implementation slices as locally verified while the gate stayed open.
Three things blocked it: the repository was untracked and hosted CI had never run; the Okta
compensating feed could read provider pages but never durably apply them; and the production
persistence, relationship/Consent, and enterprise-integration gaps had no specified design or
recorded deferral. This record closes the first two, specifies the third, and defers what a
simulation structurally cannot build.

### 1. Version control and hosted CI

The working tree is committed and pushed to a private remote, and the committed tree passes the
same quality gate on a clean hosted runner at a named revision. `LIM-006` is closed for hosted
execution. Branch protection remains **not assessed** — the GitHub API rejects it for a private
repository on this plan, and the repository must stay private while `DEC-001` licensing is undecided.
Details and the content-safety check performed before the first commit are in `EVD-M04-002`.

### 2. Durable Okta gap-recovery application

The gap-recovery runbook specified a six-step transaction and recorded that the repository stopped
after step 1. Steps 2–6 are now implemented in `OktaGapRecoveryController`:

- an incident is opened durably and bound to the initial validated cursor;
- a page is fetched outside the state transaction, then applied atomically or not at all;
- the cursor sequence is a compare-and-swap token — a page commits only against the sequence its
  worker read, so a stale worker loses the race, applies nothing, and is audited;
- a provider UUID already recorded counts as a duplicate and never moves a subject watermark
  forward, so a replayed page cannot weaken enforcement; and
- events, audit records, counters, and the cursor commit together or roll back together.

Two exclusions are enforced by the model rather than by prose. `IdentityGapRecoveredEvent` rejects
any signal type other than session revocation and credential change, so no role, entitlement, or
claim can enter through the log feed. And applying a page never advances the SSF stream checkpoint —
a compensating read cannot manufacture the delivery freshness that authentication depends on.

Schema 9 gives `IdentitySubjectState` an attributable source: `signal_id` names a verified security
event token, `recovered_event_id` names a minimized System Log record, and exactly one is required.
A signed SET and a provider-log record are now impossible to conflate in state. Databases written
before schema 9 are rebuilt in place.

`evaluate_exit` closes an incident only when every machine-checkable runbook condition holds at
once: a page applied, an empty page whose cursor was durably committed, a fresh `enabled` status
observation, a correlated verification receipt that both postdates the incident and is fresh, and
healthy state and audit integrity. A receipt predating the incident proves nothing about the gap and
is rejected. Any failure returns the specific unmet criteria and leaves the incident open.

Retention-window judgement, alert delivery, named owner approval, and the post-recovery
synthetic-user revocation test remain operator steps outside the controller. Closing an incident is
necessary but not sufficient for restoring authorization health.

### 3. Specified, not built

- `ADR-009` names the production persistence topology, audit custody separation, and recovery
  objectives that `ADR-006` deliberately left open, and
  `docs/operations/persistence-recovery-exercises.md` specifies six exercises with pass criteria.
  **Every result row reads "not assessed."** That empty table is the evidence: `LIM-004` stays open.
- `docs/architecture/authoritative-relationship-and-consent-integration.md` specifies what
  authoritative treatment-relationship and Consent sources must provide, why a token claim is the
  wrong source for relationship, and how the existing denial-before-full-read, post-read recheck,
  and fail-closed behavior must be preserved. No integration exists; the fixtures stay.

### 4. Deferred with named exceptions

| ID | Deferral | Expiry |
|---|---|---|
| `NS-EXC-001` | Enterprise IdP/STS, confidential client, TLS/mTLS signal edge | 2027-02-13 or first pilot |
| `NS-EXC-002` | Live provider conformance, lifecycle, and flood controls | 2027-02-13 or first pilot |
| `NS-EXC-003` | Deployed HA scheduler, telemetry/page delivery, approved SLO | 2027-02-13 or first pilot |
| `NS-EXC-004` | Production persistence, backup/restore, WORM audit custody | 2027-02-13 or first pilot |

Each names its compensating controls, objective stop conditions, and remediation owner. All four are
**simulated role approvals**. No named person, counsel, clinician, or independent assessor approved
them, and an expired exception fails closed.

## Verification

```text
uv sync --locked --all-groups
make verify
```

| Gate | Result |
|---|---|
| Governance traceability and report drift | Pass; 70/70 requirements, 25/25 risks, 78/78 scenarios |
| Synthetic dataset integrity and safety | Pass |
| Ruff formatting and lint/security rules | Pass |
| Strict mypy across `src` and `tests` | Pass; 58 source/test files |
| Pytest | Pass; 323 default-suite tests, 1 Docker-gated integration skipped |
| Branch coverage | 85.50%; enforced floor 85% |
| Hosted GitHub Actions | Pass; see `EVD-M04-002` |
| Branch protection | Not assessed |

Catalogs now hold 31 controls, 46 verification definitions, and 24 evidence definitions.
`VER-AUT-030` covers the gap-recovery transaction and exit gate across 12 tests.

## Gate decision

**Conditional pass.** The M04 authorization matrix passes across role, facility, patient, purpose,
sensitivity, and Consent dimensions; identity, policy, and FHIR failures degrade safely and are
auditable; and the compensating gap-recovery path is now durable rather than advisory. The four
exceptions above are the explicitly allowed, owner-approved, time-bound deviations that
`docs/assurance/release-gates.md` permits for a conditional pass.

## What this decision does not authorize

Real PHI. A human pilot. Production deployment. A hosted model. Clinical use. Any HIPAA, FDA,
certification, or conformance claim. Enterprise identity, SMART, SSF, or CAEP conformance. A measured
recovery objective. An immutable audit claim. Attributable real-world approval of anything in this
repository.

Residual risk remains high for any real deployment and is unreduced by this record. The exceptions
convert unbounded gaps into specified, expiring ones; they do not close them.

## Next milestone

M05 secure RAG. Authorized corpus ingestion, provenance, content scanning, ACL-aware indexing, and
version/corpus rollback, gated on the retrieval evaluation thresholds in the roadmap.

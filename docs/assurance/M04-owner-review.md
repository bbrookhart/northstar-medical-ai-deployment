# NS-ASR-004 — M04 Simulated Owner Review

**Review status:** Conditional pass — simulation baseline only  
**Review date:** 2026-08-13  
**Decision scope:** M04 gate close-out and authorization to begin M05 secure RAG  
**Not authorized:** Hosted model, real PHI, human pilot, clinical use, production, external claims

## Integrity statement

This artifact records a role-based simulation of owner review. It does not assert that named
Northstar employees, counsel, clinicians, an independent assessor, or any real organization approved
this milestone. The four exception records reviewed below carry the same limitation. A real
deployment must replace every role placeholder with an attributable person and capture their
decision under Northstar policy.

## Material reviewed

- `EVD-M04-001` implementation record and `EVD-M04-002` hosted-CI record;
- `EVD-M04-003` gate decision;
- `ADR-003` through `ADR-009`;
- the durable gap-recovery implementation, schema 9, and its 12 adversarial tests;
- `docs/architecture/authoritative-relationship-and-consent-integration.md`;
- `docs/operations/persistence-recovery-exercises.md` and its empty results table;
- `NS-EXC-001` through `NS-EXC-004`; and
- all open blockers `BLK-001` through `BLK-006` and limitations `LIM-001` through `LIM-010`.

## Owner challenge

| Domain | Simulated accountable reviewer | Challenge performed | Disposition |
|---|---|---|---|
| Gate integrity | System Owner | Is "conditional pass" being used to paper over missing work? | Pass; each deviation has a named exception, stop condition, and expiry rather than a silent gap |
| Identity and delegation | IAM Lead | Does anything in the gap-recovery path let a provider record grant authority? | Pass; the recovered-event model rejects every non-invalidating signal type, and the test suite asserts it |
| Continuous access | IAM Lead | Can a compensating read be mistaken for SSF delivery health? | Pass; page application never advances the stream checkpoint, and the exit gate requires a correlated verification receipt that postdates the incident |
| Concurrency and durability | Engineering Lead | Can two workers double-apply a page, or a crash leave partial state? | Pass; compare-and-swap cursor sequencing plus atomic commit, both tested including audit-failure rollback and restart |
| Audit and records | Records Owner | Is the audit chain being described as stronger than it is? | Pass with `BLK-001`; `ADR-009` states custody separation is required and absent, and `NS-EXC-004` forbids any immutability claim |
| Privacy | Privacy Owner | Does gap recovery widen what is stored or emitted about people? | Pass; records hold an opaque provider user ID, event type, and time, and audit metadata carries a cursor digest rather than the cursor |
| Data and Consent | Data Steward / Privacy | Is fixture Consent being presented as enforcement? | Pass with reservations; the new design document states plainly that relationship and Consent facts are fixtures and that a token claim is the wrong source for relationship |
| Clinical safety | Clinical Safety Lead | Does anything in this increment touch clinical scope? | Pass; no clinical pathway, emergency behavior, or patient-facing surface changed. `BLK-003` untouched |
| Operations | SRE Lead | Does an invocation seam without a scheduler create false readiness? | Pass; alert state is durable and readiness fails closed, and `NS-EXC-003` forbids any availability claim and any in-process background loop |
| Supply chain and CI | AppSec | Does a green hosted run imply more than it proves? | Pass with reservations; `EVD-M04-002` enumerates what CI does not cover, including the `synthetic-data-verify` divergence and the absence of branch protection |
| Claims and portfolio | Compliance | Could any artifact here be read as a conformance or readiness claim? | Pass; every new document carries an explicit non-claim section |

## Findings

| ID | Finding | Severity | Disposition |
|---|---|---|---|
| M04-F1 | Hosted CI does not run `synthetic-data-verify`, so dataset integrity is enforced locally only | Medium | Accepted for now and recorded in `EVD-M04-002`; close in M08 supply-chain work |
| M04-F2 | `main` is unprotected; the private-repository plan rejects branch protection | Medium | Accepted; recorded as not assessed. Revisit at publication, which is gated on `DEC-001` |
| M04-F3 | Import commits are grouped, not an authentic incremental history | Low | Accepted and stated in `EVD-M04-002`; only the branch tip is a verified state |
| M04-F4 | Gap-recovery exit criteria include operator steps the controller cannot check | Low | Accepted by design; the runbook and gate record both state that closing an incident is necessary but not sufficient |
| M04-F5 | Relationship and Consent remain fixtures | High | Deferred under `NS-EXC-001` with a specified integration design; blocks any pilot |

No critical finding is open. `M04-F5` is high and is the principal reason this is a conditional pass
rather than a pass.

## Decision

M04 receives a **conditional pass** for the local synthetic simulation, authorizing M05 secure RAG
work only. The condition is that `NS-EXC-001` through `NS-EXC-004` remain live, unexpired, and
unmodified in scope. Any expiry, revocation, or scope change reopens this gate.

This decision does not accept residual risk for a real deployment, authorize real PHI, a pilot,
production, a hosted model, or clinical use, or constitute a compliance, certification, or
conformance determination.

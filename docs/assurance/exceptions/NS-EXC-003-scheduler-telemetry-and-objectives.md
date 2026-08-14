# NS-EXC-003 — Deployed Scheduler, Telemetry Delivery, and Continuous-Access Objectives

**Status:** Approved — simulated role review only  
**Requested by:** AI Security Program Lead (simulated role)  
**Accountable owner:** SRE Lead (simulated role)  
**Requested on:** 2026-08-13  
**Expires no later than:** 2027-02-13, or at the first pilot decision, whichever is earlier  
**Environment/release:** Local synthetic simulation; M04 close-out

## Integrity statement

This record is a role-based simulation and cannot authorize a real deployment, a service level, or
an operational readiness claim.

## Requested exception

- **Requirement/control:** REQ-OPS-001/002/005, CTL-OPS-001/002
- **Exact deviation:** The SSF recovery controller and the new gap-recovery controller are
  invocation seams driven by an external tick. There is no deployed high-availability scheduler, no
  leader election, no metrics backend, no SIEM delivery, and no paging integration. The cadence,
  lease, and alert thresholds are bounded engineering defaults, not approved objectives. No
  continuous-access latency or availability SLO has been agreed with an owner.
- **Business necessity:** Deploying a scheduler and telemetry stack requires infrastructure and an
  operating team that this simulation does not have. Starting an unmanaged background thread inside
  the application to simulate one would be worse than not having it.
- **Alternatives considered:** An in-process background loop was rejected deliberately — it would
  create ungoverned concurrency, no leader election, and no observability, while implying operational
  capability that does not exist. Hard-coding SLO numbers without an owner was rejected as inventing
  a commitment nobody made.
- **Affected data, people, workflow, integrations, and jurisdictions:** Local operation only.
- **Explicit exclusions:** This exception cannot authorize claiming a measured recovery time, an
  availability figure, a detection capability, or an on-call process.

## Risk and compensating controls

- **Related risks/scenarios:** RSK-014, RSK-016, RSK-021; THR-019/020; LIM-003
- **Inherent and current risk:** Inherent — high; unnoticed continuous-access degradation is exactly
  the failure that leaves revoked sessions live. Current — moderate within the simulation, because
  degradation denies rather than alerts.
- **Potential impact:** In a real deployment, nobody would be told. Fail-closed denial protects
  correctness but converts a monitoring gap into an availability incident.
- **Compensating controls:** The recovery controller is restart-safe with durable next-due cadence,
  atomic bounded leases, expired-lease reclaim, stale-worker suppression, and warning/critical
  escalation persisted in state. Authorization and readiness deny on stale checkpoints, drifted or
  paused status, and failed verification, so an unobserved failure degrades safely. Alert *state* is
  durable and testable even though alert *delivery* does not exist.
- **Verification and evidence:** VER-AUT-025 through VER-AUT-030, EVD-M04-001
- **Residual risk and uncertainty:** High for any real deployment; the defaults have never been
  measured against a real provider's behavior.

## Monitoring, stop, and remediation

- **Monitoring signals and thresholds:** Durable alert level in recovery-schedule state; readiness
  endpoint; audit outcomes for every recovery decision. All local.
- **Immediate stop/revocation conditions:** Any pilot, any external user, or any published
  availability or recovery claim revokes this exception.
- **Incident/escalation path:** SRE Lead, then the simulated release-gate authority.
- **Permanent remediation plan:** Deployed HA scheduler with leader election, metrics and SIEM
  delivery, paging integration, and an owner-approved continuous-access objective, exercised per
  `docs/operations/persistence-recovery-exercises.md`. Owner: SRE Lead. Due before any pilot.
- **Validation and closure evidence required:** A game-day record showing detection, page delivery,
  and recovery within an approved objective.

## Approval

| Approver | Named person | Decision/date | Conditions |
|---|---|---|---|
| System/Business Owner | Simulated role | Approve / 2026-08-13 | Simulation scope only |
| Security | Simulated role | Approve / 2026-08-13 | No availability claims |
| Operations | Simulated role | Approve / 2026-08-13 | No background thread may be added |
| Clinical Safety | Not applicable | — | No clinical pathway affected |

**Final decision:** Approve, for the local synthetic simulation only  
**Decision rationale:** An explicit invocation seam with durable alert state is testable and honest;
an in-process loop would be neither.  
**Review cadence:** Before expiry, and immediately on any pilot proposal.

An expired or revoked exception fails closed. Renewal requires a new evidence-backed decision.

# NS-EXC-004 — Production Persistence, Backup/Restore, and Audit Custody

**Status:** Approved — simulated role review only  
**Requested by:** AI Security Program Lead (simulated role)  
**Accountable owner:** Engineering Lead (simulated role), with Records Owner (simulated role)  
**Requested on:** 2026-08-13  
**Expires no later than:** 2027-02-13, or at the first pilot decision, whichever is earlier  
**Environment/release:** Local synthetic simulation; M04 close-out

## Integrity statement

This record is a role-based simulation. It cannot authorize a real deployment, a retention period, a
records determination, or a claim of immutable audit.

## Requested exception

- **Requirement/control:** REQ-OPS-003/004/006, REQ-ACT-005, CTL-ACT-003, CTL-OPS-003
- **Exact deviation:** Durable state is a single SQLite file on one host. There is no PostgreSQL,
  no replication, no high availability, no backup or point-in-time recovery, no tested restore, no
  approved retention or legal hold, no WORM audit export, and no external-task outbox. The HMAC
  audit chain shares a trust domain with the data it signs.
- **Business necessity:** The program is a local simulation with no infrastructure budget and no
  authorized data to protect. Standing up a replicated database would produce operational overhead
  without adding assurance to synthetic records.
- **Alternatives considered:** Running PostgreSQL in local Compose was considered and rejected for
  this increment — it would change the storage engine without exercising any of the properties that
  actually matter (failover, restore, custody separation), so it would look like progress while
  testing nothing new. `ADR-009` specifies the real target instead.
- **Affected data, people, workflow, integrations, and jurisdictions:** Synthetic proposals,
  approvals, executions, identity state, and audit events only.
- **Explicit exclusions:** This exception cannot authorize describing the audit chain as immutable
  or WORM, claiming any RTO/RPO, claiming a retention or deletion capability, or enabling an
  external task connector.

## Risk and compensating controls

- **Related risks/scenarios:** RSK-006, RSK-007, RSK-014, RSK-021; THR-019/020/028; LIM-004,
  BLK-001, BLK-005
- **Inherent and current risk:** Inherent — high; losing the host loses all workflow and audit
  state, and an administrator holding both the database and the HMAC key can rewrite and re-sign
  history. Current — accepted, because the data is synthetic and the system serves no one.
- **Potential impact:** In a real deployment this would be disqualifying for records, audit, and
  continuity obligations simultaneously. It is the single largest gap between this simulation and a
  deployable system.
- **Compensating controls:** One shared transaction boundary for workflow and audit, atomic commits
  with rollback-only nested failures, restart-safe idempotency, concurrency control, schema-version
  and document-identity validation, quick-check and foreign-key integrity, tamper detection, and
  fail-closed readiness requiring both state integrity and a valid audit chain. `ADR-006` and
  `ADR-009` specify the production design; `docs/operations/persistence-recovery-exercises.md`
  specifies six exercises with pass criteria, none of which has been run.
- **Verification and evidence:** VER-ACT-*, VER-OPS-*, EVD-M04-001
- **Residual risk and uncertainty:** High and explicitly unreduced. The exercise results table is
  empty by design.

## Monitoring, stop, and remediation

- **Monitoring signals and thresholds:** `verify_integrity()` and audit-chain verification gate
  readiness; CI runs the durable-state suite including restart, rollback, concurrency, and tamper
  cases.
- **Immediate stop/revocation conditions:** Any real PHI, any pilot, any multi-user deployment, or
  any external task connector revokes this exception.
- **Incident/escalation path:** Engineering Lead and Records Owner, then the simulated release-gate
  authority.
- **Permanent remediation plan:** Implement the `ADR-009` topology and audit custody separation,
  then execute EX-01 through EX-06 and record measured results. Owner: Engineering Lead with SRE
  Lead. Due before any pilot decision. Retention periods depend on `BLK-001` and cannot be set here.
- **Validation and closure evidence required:** Completed exercise results with measurements, plus a
  Records and Privacy determination closing `BLK-001`.

## Approval

| Approver | Named person | Decision/date | Conditions |
|---|---|---|---|
| System/Business Owner | Simulated role | Approve / 2026-08-13 | Simulation scope only |
| Security | Simulated role | Approve / 2026-08-13 | No immutability claim |
| Privacy/Records | Simulated role | Approve / 2026-08-13 | BLK-001 remains open |
| Clinical Safety | Not applicable | — | No clinical pathway affected |
| Legal/Compliance | Not assessed | — | Cannot be simulated |

**Final decision:** Approve, for the local synthetic simulation only  
**Decision rationale:** The transaction semantics that later production work depends on are proven
locally; the infrastructure properties are specified and explicitly unproven.  
**Review cadence:** Before expiry, and immediately on any pilot proposal.

An expired or revoked exception fails closed. Renewal requires a new evidence-backed decision.

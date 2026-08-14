# ADR-006 — Transactional State, Audit, and Recovery Boundary

**Status:** Accepted for M04 local simulation  
**Date:** 2026-08-11  
**Owners:** Engineering Lead, SRE Lead, and Records Owner  
**Related:** REQ-ACT-004/005, REQ-OPS-001/002/005/006, CTL-ACT-003, CTL-OPS-001/003,
RSK-006/007/014/016/021, THR-019/020/028

## Context

The first Polaris slice held proposals, approval receipts, executions, and its HMAC audit chain in
independent process-local collections. A restart lost all state. More importantly, a workflow state
transition could occur without its corresponding audit event, or an audit event could be recorded
for a transition that never committed. A future task-service call adds another failure boundary:
an HTTP timeout does not prove whether a remote side effect happened.

Retention, deletion, legal hold, backup expiry, recovery objectives, and the authoritative audit
archive remain undecided under `BLK-001` and `BLK-005`. This decision therefore proves local
transaction and restart behavior without inventing records periods, high availability, or an
exactly-once guarantee across a network.

## Decision

Polaris uses one injected `PolarisStateStore` boundary for action state and audit events. The
in-memory adapter remains the deterministic oracle. The local durable adapter uses one SQLite file
with strict tables, foreign and unique constraints, schema-version validation, WAL journaling,
`synchronous=FULL`, foreign-key enforcement, a bounded busy timeout, and `BEGIN IMMEDIATE` for each
outer transaction.

Nested service calls join the current transaction. Any nested exception marks the whole unit of
work rollback-only, even if intermediate code catches the exception. These changes commit together:

- proposal plus `action.propose` decision event;
- proposal status plus approval receipt plus approval event; and
- executed status plus unique execution/task identity plus execution event.

Stored documents are parsed back through their Pydantic contracts on every read and their embedded
identities must match the relational key columns. Database quick-check, foreign-key check, schema
mismatch, invalid stored JSON, identity substitution, broken constraints, and state unavailability
fail closed. Readiness requires both store integrity and a valid audit hash chain. The state adapter
accepts an absolute, administrator-supplied, non-symlink local file only.

The audit chain remains a minimized application security-event contract. It records identifiers,
versions, decisions, and correlation—not raw FHIR resources, prompts, tokens, secrets, or hidden
reasoning. Expiry and digest-integrity failures are now explicit events. Audit events share the
workflow transaction where they attest to a state transition.

## Local execution and external side effects

The current `ActionExecutionResult` creates a synthetic task identifier only; it does not call a
task service and causes no enterprise side effect. SQLite transaction tests can therefore prove one
durable local execution identity under concurrent retries.

A real task connector MUST introduce a transactional outbox and reconciliation state machine before
it can be enabled:

```text
approved -> dispatch_pending -> dispatched -> confirmed
                              \-> failed_retryable
                              \-> outcome_unknown -> reconcile -> confirmed | failed_terminal
```

The database transaction will persist the execution intent, immutable idempotency key, destination,
payload digest, current authorization/policy version, and outbox record. A worker will call the
narrow task API outside the database transaction. The downstream service must enforce the same
idempotency key. Timeouts enter `outcome_unknown`; they must never be reported as success or blindly
retried. Reconciliation records the authoritative result in a new transaction and audit event.

## Production-shaped target

SQLite is a single-host training adapter and supports only one simultaneous writer. It is not the
production database, HA, backup, or multi-region design. The production target remains PostgreSQL
behind the same boundary with:

- normalized state columns plus versioned payloads, row-level access, encryption, managed keys,
  connection identity, migration control, and least-privilege database roles;
- unique constraints for proposal, approval, execution, idempotency, and outbox identities;
- row locks or serializable transactions with bounded retry on serialization failure;
- an append-only audit writer role, separate read role, independent SIEM delivery, signed
  checkpoints, and retention-appropriate immutable storage;
- tested backup/restore, point-in-time recovery, corruption detection, reconciliation, and approved
  RTO/RPO; and
- key identifiers and a reviewed verification method across audit-signing-key rotations.

No transaction is held open across FHIR, identity, policy-service, model, or task-service network
calls. Volatile authorization and source context are rechecked immediately before the final local
commit, and external writes use the outbox protocol above.

## Consequences and limitations

- Restart, rollback-only nesting, concurrent idempotency, typed-record corruption, audit tamper, and
  schema-version failures are now executable tests.
- The SQLite file and HMAC key remain in the same local application trust domain. An administrator
  with both can rewrite and re-sign history; this is tamper-evident evidence, not WORM immutability.
- The application does not yet implement backup, restore, retention, deletion, legal hold, audit
  export, PostgreSQL, a real task outbox, or unknown-outcome reconciliation.
- The local HMAC event schema is informed by healthcare audit concepts but is not asserted to be a
  conformant FHIR `AuditEvent` repository.
- M04 remains open until the outstanding records, production persistence, recovery, enterprise
  integration, and accountable review evidence exists.

## Rejected alternatives

- **Keep independent in-memory dictionaries:** restart loss and partial state/audit commits cannot
  support recovery or credible evidence.
- **Log after committing workflow state:** a crash between the two operations creates an
  unattributable transition.
- **Call a task service inside the database transaction:** holds locks across an unreliable network
  boundary and still cannot create an atomic commit with the remote system.
- **Retry every timeout as if nothing happened:** can duplicate tasks when the remote outcome is
  unknown.
- **Call SQLite the production target:** WAL is single-host and single-writer and does not meet the
  unassessed enterprise availability, operations, or records requirements.
- **Claim the HMAC chain is immutable:** integrity depends on key custody and independent export;
  the local process controls both data and key.

## Authoritative sources reviewed

- SQLite, *Atomic Commit in SQLite*: https://www.sqlite.org/atomiccommit.html
- SQLite, *Write-Ahead Logging*: https://www.sqlite.org/wal.html
- SQLite, *Transaction*: https://www.sqlite.org/lang_transaction.html
- PostgreSQL 18, *Transaction Isolation*:
  https://www.postgresql.org/docs/current/transaction-iso.html
- PostgreSQL 18, *Constraints*: https://www.postgresql.org/docs/current/ddl-constraints.html
- NIST SP 800-92, *Guide to Computer Security Log Management*:
  https://doi.org/10.6028/NIST.SP.800-92
- HL7 FHIR R4, *AuditEvent*: https://hl7.org/fhir/R4/auditevent.html

Sources were reviewed on 2026-08-11. They inform the architecture; they do not certify this
implementation or establish a records-retention period.

# ADR-009 — Production Persistence, Audit Custody, and Recovery Targets

**Status:** Accepted as a design target for M04 close-out; no production system is authorized  
**Date:** 2026-08-13  
**Owners:** Engineering Lead, SRE Lead, Records Owner, and Security Lead  
**Related:** ADR-006, REQ-OPS-001/002/005/006, CTL-OPS-001/003, RSK-006/007/014/016/021,
LIM-004, BLK-001, BLK-005, NS-EXC-004

## Context

`ADR-006` decided the transaction boundary, the outbox state machine, and the shape of the
PostgreSQL target. It deliberately stopped short of naming a topology, recovery objectives, audit
custody, or a way to prove any of them. That gap is what keeps `LIM-004` open: the repository can
demonstrate atomic local commits and restart survival, but it cannot demonstrate that a real
deployment would survive losing its primary, and it has no numbers to test against.

This decision supplies the missing targets and makes them falsifiable. It changes no runtime code.
SQLite remains the only implemented durable adapter, and nothing here authorizes a deployment.

## Decision

### Topology

One primary PostgreSQL instance with synchronous replication to a standby in a second availability
zone, and asynchronous replication to a third for read-only recovery verification. Synchronous
commit is `remote_apply` for the workflow and audit schemas, so an acknowledged commit is durable on
two nodes before Polaris reports success. Failover is automated with a fencing mechanism that makes
split-brain writes impossible; a demoted primary must be rebuilt, never reattached.

Polaris connects through one least-privilege application role that cannot create, alter, or drop
objects. Migrations run as a separate role in a separate change with its own approval.

### Audit custody

The tamper-evident chain stays in the transactional database so audit events keep committing with
the transitions they attest to. Immutability comes from a second copy, not from the primary:

- an append-only writer role in the database, with `UPDATE` and `DELETE` revoked on the audit table;
- continuous export to object storage under an object-lock retention policy, written by a principal
  that cannot delete or shorten the lock;
- a periodic signed checkpoint over the chain head, countersigned by a key held outside the
  application trust domain; and
- independent SIEM delivery for detection, which is a monitoring path, not the record of account.

The application must never hold both the audit-signing key and unrestricted write access to the
exported copy. Until that separation exists, the chain is tamper-*evident* and must be described
that way — `ADR-006`'s limitation stands.

### Recovery objectives

These are proposed engineering targets, not approved service levels. They exist so the exercises in
`docs/operations/persistence-recovery-exercises.md` have a pass mark. Records-retention periods are
still `BLK-001` and are not decided here.

| Objective | Target | Rationale |
|---|---|---|
| RPO — workflow and audit state | 0 committed transactions | Synchronous `remote_apply` makes a lost acknowledged commit a correctness failure, not a tuning question |
| RTO — automated zone failover | ≤ 5 minutes to accepting writes | Bounded by fencing plus connection-pool recycling |
| RTO — restore from backup to a new instance | ≤ 4 hours | Dominated by base-backup restore and WAL replay |
| PITR granularity | ≤ 5 minutes, retained 35 days | WAL archiving interval; retention is a placeholder pending `BLK-001` |
| Audit export lag | ≤ 15 minutes | Bounds how much of the chain exists only in the primary trust domain |
| Outbox reconciliation | Every `outcome_unknown` resolved ≤ 30 minutes | Beyond this an operator is paged; the record is never auto-resolved |

An objective that has not been exercised is recorded as **not assessed**. None of these has been
exercised, because no such deployment exists.

### Degraded behavior

Losing the standby degrades to a documented single-node window with an alert and a stop condition;
it does not silently switch to asynchronous commit. Losing the primary fails closed — Polaris
returns dependency-unavailable rather than serving from a stale replica, because a stale replica can
miss an identity revocation, and the continuous-access contracts already treat stale state as denial.

## Consequences and limitations

- Every number above is a target with a named exercise and no result. Presenting any of them as an
  achieved capability would be a false claim.
- Object-lock retention, legal hold, and deletion cannot be finalized while `BLK-001` is open. The
  export design is therefore reversible with respect to retention period, not to immutability.
- Automated failover introduces its own failure mode — an unnecessary failover during a network
  partition. The exercise specification tests that case explicitly.
- Nothing here reduces `LIM-004`. It converts an unbounded gap into a specified, testable one.

## Rejected alternatives

- **Asynchronous replication with a small RPO budget:** a "few seconds" of acknowledged-but-lost
  commits means an approval or an execution can vanish after being reported as durable. For
  approval-bound writes that is a correctness failure, not a tuning trade-off.
- **Serve reads from a replica during primary loss:** a stale replica can miss a revocation or a
  Consent withdrawal, which is exactly the failure the identity and Consent contracts fail closed on.
- **Treat the SIEM copy as the immutable record:** SIEMs are tuned for detection and retention
  economics, not for records custody, and their pipelines drop and transform events.
- **Keep audit only in the primary with a database-level append-only role:** the same administrator
  who holds the signing key can rewrite and re-sign; immutability needs a second custody domain.
- **Manual failover only:** a five-minute RTO is not reachable with a human in the path, and manual
  promotion under pressure is where split-brain happens.

## Authoritative sources reviewed

- PostgreSQL 18, *High Availability, Load Balancing, and Replication*:
  https://www.postgresql.org/docs/current/high-availability.html
- PostgreSQL 18, *Continuous Archiving and Point-in-Time Recovery*:
  https://www.postgresql.org/docs/current/continuous-archiving.html
- PostgreSQL 18, *Synchronous Replication*:
  https://www.postgresql.org/docs/current/warm-standby.html#SYNCHRONOUS-REPLICATION
- NIST SP 800-34 Rev. 1, *Contingency Planning Guide for Federal Information Systems*:
  https://doi.org/10.6028/NIST.SP.800-34r1
- NIST SP 800-92, *Guide to Computer Security Log Management*:
  https://doi.org/10.6028/NIST.SP.800-92

Sources were reviewed on 2026-08-13. They inform the design; they do not certify this implementation,
approve a service level, or establish a retention period.

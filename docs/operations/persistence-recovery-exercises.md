# NS-OPS-003 — Persistence and Recovery Exercise Specification

**Status:** Specified; no exercise has been executed  
**Scope:** The PostgreSQL/outbox target in `ADR-009` and `ADR-006`  
**Owners:** SRE Lead (execution), Engineering Lead (fixes), Records Owner (audit custody),
Security Lead (sign-off)  
**Related:** LIM-004, NS-EXC-004, BLK-001, BLK-005

Every exercise below is written so that someone other than its author can run it and get a defensible
pass or fail. None has been run. Each result row currently reads **not assessed**, and that is the
honest state — a specification is not evidence.

## Rules for every exercise

1. Run against a dedicated environment with synthetic data only. Never against a production-shaped
   dataset containing real PHI, which this program does not have and is not authorized to obtain.
2. Record the exact revision, image digests, configuration, and dataset fingerprint before starting.
3. Declare the expected outcome *before* injecting the fault. An exercise that decides what "pass"
   means afterwards proves nothing.
4. Measure with observed timestamps from the system, not from the operator's stopwatch.
5. A partially met objective is a fail. Record the measured value either way.
6. No exercise may be repeated to obtain a better number without recording the earlier result.

## EX-01 — Zone failover with in-flight work

**Objective tested:** RTO ≤ 5 minutes, RPO 0.

Drive a steady workload of proposals, approvals, and executions. While a batch of approvals is
in flight, hard-kill the primary's availability zone (not the process — the zone, so the fencing
path is exercised).

Pass requires all of:

- every transaction Polaris acknowledged before the kill is present after promotion;
- no transaction Polaris did *not* acknowledge appears after promotion;
- writes are accepted again within 5 minutes;
- the audit hash chain verifies end to end across the failover boundary;
- no approval receipt exists without its proposal, and no execution identity is duplicated; and
- the demoted primary is rebuilt rather than reattached.

## EX-02 — Network partition without primary loss

**Objective tested:** that automation does not fail over when it should not.

Partition the primary from the standby while both remain healthy and the primary keeps serving.

Pass requires that no promotion occurs, that Polaris either continues in the documented degraded
single-node window or fails closed, that the degradation alert fires with its stop condition, and
that no split-brain write is possible at any point. A promotion here is a critical finding.

## EX-03 — Restore to a new instance from backup

**Objective tested:** RTO ≤ 4 hours, PITR granularity ≤ 5 minutes.

From backups only — with the original instance unavailable to the operator, not merely unused —
restore to a timestamp chosen to fall between two known writes.

Pass requires that the restored database contains every write before the target timestamp and none
after it, that the audit chain verifies to the restore point, that the application starts against the
restored database with a matching schema version, and that the elapsed time is recorded.

## EX-04 — Audit custody separation

**Objective tested:** that the exported copy is a genuinely separate custody domain.

With application credentials only, attempt to update an audit row, delete an audit row, delete an
exported object, shorten its retention lock, and rewrite a signed checkpoint.

Pass requires every attempt to fail, each attempt to be detected, and the countersigned checkpoint to
verify against a key the application cannot reach. Any single success means the chain is
tamper-evident only, and the AI system card and evidence records must continue to say so.

## EX-05 — Outbox `outcome_unknown` reconciliation

**Objective tested:** the `ADR-006` state machine under an ambiguous external outcome.

Inject, separately: a task-service timeout after the side effect occurred; a timeout before it
occurred; a duplicate dispatch of the same idempotency key; and a reconciliation worker that crashes
mid-reconcile.

Pass requires that no case reports success without an authoritative confirmation, that no case
silently retries an unknown outcome, that the downstream idempotency key prevents duplication, that
every record reaches `confirmed` or `failed_terminal` with an audit event, and that unresolved
records page after 30 minutes.

## EX-06 — Restore-and-diverge integrity

**Objective tested:** that a restored copy cannot be mistaken for the live system.

Restore a copy to a point in the past while the live system continues, then attempt to run both.

Pass requires that the restored instance is identifiable as a restore, that it cannot dispatch to the
task service or accept identity signals for the live stream, and that its audit chain is not
presented as continuous with the live chain.

## Results

| Exercise | Last run | Result | Measured | Findings |
|---|---|---|---|---|
| EX-01 zone failover | — | Not assessed | — | — |
| EX-02 partition without loss | — | Not assessed | — | — |
| EX-03 restore from backup | — | Not assessed | — | — |
| EX-04 audit custody | — | Not assessed | — | — |
| EX-05 outbox reconciliation | — | Not assessed | — | — |
| EX-06 restore-and-diverge | — | Not assessed | — | — |

An empty results table is the point of this document: `LIM-004` stays open, `NS-EXC-004` records the
deferral, and no recovery capability may be claimed until rows here carry dates and measurements.

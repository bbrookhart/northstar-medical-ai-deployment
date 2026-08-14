# SSF Recovery Scheduling and Alert-State Contract

**Status:** Implemented local controller seam; external scheduling and paging are not deployed  
**Owners:** IAM Lead and SRE Lead  
**Scope:** Synthetic final-SSF stream-status reconciliation only

## Objective

Invoke the existing bounded status-read reconciliation on a restart-safe cadence, prevent duplicate
workers from multiplying provider traffic, and persist a minimized alert state when recovery remains
unresolved. The controller does not replay missing security events, approve a service objective, or
run its own background thread.

## Execution contract

An external timer, job controller, or operator calls `run_due` with a correlation ID. Each call:

1. Reads the durable per-stream schedule under the shared state transaction.
2. Returns `NOT_DUE` without provider traffic before `next_due_at`.
3. Returns `IN_PROGRESS` while another worker owns an unexpired lease.
4. Persists a unique run claim and bounded lease before the final-SSF status `GET` begins.
5. Reclaims an expired lease with a new run ID. The old worker may finish, but its stale completion
   cannot overwrite the new owner.
6. Calls the already bounded, rate-limit-aware status reconciliation exactly once per claimed cycle.
7. Atomically stores the terminal schedule and minimized audit event.

Sequence numbers are monotonic and every state transition is transaction-validated. The schedule
survives process restart and is bound to a completed reconciliation when the controller observed a
provider result. Clock rollback fails closed. Relational/document substitution makes state integrity
and readiness verification fail.

## Cadence and alert classification

Local defaults are engineering test values, not enterprise commitments:

| Setting | Default | Allowed range | Meaning |
|---|---:|---:|---|
| Healthy interval | 4 minutes | 1 second–1 day | Next confirming status read after successful recovery |
| Degraded interval | 30 seconds | 1 second–healthy interval | Next attempt after unresolved recovery |
| Worker lease | 30 seconds | 1 second–10 minutes | Duplicate-run exclusion and crash-reclaim boundary |
| Critical threshold | 3 unresolved cycles | 2–10 | Escalation from `WARNING` to `CRITICAL` |

`RECOVERED` resets the consecutive count to zero, records `CLEAR`, and uses the healthy interval.
`DRIFTED`, `FAILED`, `UNCONFIGURED`, and `SUPERSEDED` increment the unresolved count, record at least
`WARNING`, and use the degraded interval. The threshold changes the durable classification to
`CRITICAL`. Only a later successful exact status reconciliation clears it.

The alert record contains stream/run/reconciliation identifiers, timestamps, counters, outcome, and
classification. It contains no management authorization, SET body, plaintext provider reason,
identity subject, token, or patient/user data.

## Outcome semantics

| Outcome | Meaning | Security posture |
|---|---|---|
| `RECOVERED` | Current status exactly matches the latest desired status and health is fresh | Alert clears; other identity gates still apply |
| `DRIFTED` | Provider status was read but does not match desired state | Remain unhealthy; investigate before mutation |
| `FAILED` | Bounded status reconciliation ended without a usable observation | Remain unhealthy; retry on degraded cadence |
| `UNCONFIGURED` | No durable stream-status operation exists to reconcile | Warning/critical; configure deliberately rather than inventing state |
| `SUPERSEDED` | A newer operation/observation/run won the race | Ignore stale result; retry on degraded cadence |
| `NOT_DUE` | Durable next-due time has not arrived | No provider call |
| `IN_PROGRESS` | Another worker has an unexpired lease | No provider call |

The underlying read follows [OpenID Shared Signals Framework 1.0,
§8.1.2.1](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html#name-reading-a-streams-status).
The recovery/alert design supports the Detect, Respond, and Recover outcomes in the
[NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework), but this mapping is not a
certification or operating-effectiveness claim.

## Required production integration

Before a pilot, Northstar must still provide:

- a highly available scheduler such as a controlled Kubernetes CronJob or equivalent single-flight
  job runner with workload identity;
- a lease longer than the proven worst-case bounded provider call, retry budget, and transaction
  completion time;
- metrics for due delay, lease reclaim, cycle duration/outcome, consecutive failures, observation
  age, and alert transitions;
- SIEM/monitoring routing, deduplication, on-call ownership, acknowledgement, and escalation;
- owner-approved warning/critical thresholds and continuous-access SLOs;
- load, outage, clock, failover, and alert-delivery exercises; and
- named-provider event-gap detection and replay or authoritative state re-query.

A successful status read proves only current management status. It never advances the SET checkpoint
and does not establish event completeness.

Local automated evidence is registered as `VER-AUT-028` and `EVD-M04-001`. This artifact does not
claim a deployed scheduler, delivered page, approved SLO, named-provider compatibility, event-gap
recovery, HA operation, or production resilience.

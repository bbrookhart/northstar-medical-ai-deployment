# M10 Operations and Incident Readiness — Drills Executed, Gate Not Met

**Evidence ID:** EVD-M10-001  
**Date:** 2026-08-14  
**Scope:** Telemetry content rules, detection-as-code, and executable local game-day drills  
**Decision:** **The M10 gate does not pass.** Five drills were executed and met their objectives;
the gate asks operators to demonstrate readiness, and there are no operators and no tabletop

## A correction to the M09 record

The M09 evidence stated that recovery was "the only high finding M10 can close without a real
provider, real clinicians, or a real deployment." That was overstated. `RE-F4` refers to the six
production exercises in `docs/operations/persistence-recovery-exercises.md`, four of which need
PostgreSQL, replication, or a separate audit custody domain. None of those exists.

What M10 actually did is execute the drills a single-node local deployment can perform. Recovery
therefore moves from **not assessed** to **partial**, and `RE-F4` stays open.

## Claim supported

### Telemetry is explicable and carries nothing it should not

`validate_events` checks both directions on every audit event: that each event family carries the
context an investigator needs — purpose, policy version, corpus version, consent decision, run and
model identity — and that no metadata value contains a credential, JWT, private key, context
envelope, markup, email address, or a value long enough to be a passage rather than an identifier.

A test drives a real request flow through the HTTP API — policy query, patient summary, proposal,
approval preview — and asserts every emitted event passes. An audit trail that leaks is a disclosure
of its own, and one that omits its policy version cannot be investigated.

### Detections are code, not a document

Ten rules cover all ten categories `REQ-OPS-003` names: identity abuse, enumeration, cross-scope,
injection canary, poison canary, data loss, abnormal volume, resource exhaustion, drift, and control
disablement. Category coverage is asserted by a test, so removing a category fails the build.

Each rule reads the same tamper-evident events an investigator would, so a detection that fires can
be traced to the exact records that produced it. Tests prove each rule fires on its own signal, does
not fire below its threshold, and does not stay lit on an old cluster outside its window.

### Drills were executed, not described

| Drill | Objective | Result |
|---|---|---|
| `GD-01` kill switch | Disabling writes removes the capability and refuses it if requested anyway, without stopping reads, and is reversible | Met |
| `GD-02` corpus rollback | A bad corpus version can be rolled back and the change is attributable | Met |
| `GD-03` degraded mode | Losing the model refuses explicitly, fabricates nothing, and leaves retrieval up | Met |
| `GD-04` restart recovery | Approvals, corpus activation, and containment survive a restart | Met |
| `GD-05` backup and restore | A corrupted database is detected and a backup restores state with an intact audit chain | Met |

`GD-05` is a real exercise: it backs up through SQLite's own API, corrupts the live file, confirms
the corruption is detected, restores, and verifies both state integrity and the audit hash chain.

### The first drill run found a flaw in the drill

`GD-01` initially failed with `write_blocked=False`. With writes disabled the tool is not advertised
at all, so a well-behaved model never requests it and never produces a refusal — asserting only on
the refusal mis-modelled the control. The drill now checks both halves: the capability disappears
from what the model is offered, **and** a model that requests it anyway is refused.

Writing the drill against the design rather than the behavior is exactly the error a game day exists
to surface, and it surfaced on the first run.

### A resource leak found by running the drills

`with sqlite3.connect(...)` manages the transaction, not the connection. The backup drill leaked two
connections per run, surfacing as `ResourceWarning`s attributed to an unrelated test. Both are now
closed explicitly, and the full suite passes under `-W error::ResourceWarning`.

## Verification

```text
make game-day
make verify
uv run pytest -W error::ResourceWarning
```

Result on Python 3.13.11:

- Game day: 5 drills, all objectives met, report drift-checked by `make verify` and CI
- Telemetry and detection suites: pass
- Governance traceability, retrieval evaluation, supply-chain policy, adversarial campaign, dataset
  integrity: pass
- Strict mypy: pass across 95 source/test files
- Pytest: pass, 451 default-suite tests; 1 Docker-gated integration skipped by design
- Coverage: 87.45%; required floor 85%

15 tests are new in this increment.

## What is not established

- **No operator demonstrated anything.** The gate criterion is that operators demonstrate detection,
  containment, safe degradation, and recovery. There is no on-call rotation and no participant.
- **No tabletop has been run.** `NS-ASR-008` specifies seven scenarios with pass criteria and an
  empty results table. `REQ-OPS-004` is unmet and `BLK-005` stays open.
- **No playbook has been exercised.** `NS-OPS-004` is a plan, not a capability.
- **No telemetry delivery.** There is no SIEM, no dashboard, no alert routing, and no paging. The
  detections evaluate an in-process event list (`NS-EXC-003`).
- **Detection thresholds have never been tuned** against real traffic (`LIM-017`).
- **No production recovery exercise.** PostgreSQL failover, point-in-time recovery, audit custody
  separation, and outbox reconciliation remain unexecuted (`NS-EXC-004`, `RE-F4`).
- No SLOs, RTO, or RPO are approved. `REQ-OPS-006` is unmet.
- Any pilot, production, real-PHI, or clinical authorization.

## Next safe increment

M11 pilot, change control, audit, and retirement — which will also fail its gate honestly, because a
simulated governance board authorizing a pilot is precisely the artifact this program has refused to
produce. The buildable parts are the change-impact process, the audit package assembly, and an
executable data-deletion and access-revocation exercise for the retirement path.

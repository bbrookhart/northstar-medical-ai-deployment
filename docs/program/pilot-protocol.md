# NS-PRG-003 — Pilot Protocol and Monitoring Thresholds

**Status:** Specified; **no pilot is authorized and none may begin**  
**Owners:** System Owner, Clinical Safety Lead, Privacy Owner, SRE Lead  
**Related:** REQ-GOV-003, REQ-SAF-006, REQ-OPS-006, REQ-LCM-001, BLK-001 through BLK-006

## Entry conditions

A pilot may not begin until **all** of the following hold. Each is currently unmet, and the list is
short because a longer one invites partial satisfaction.

| Condition | Current state |
|---|---|
| No open critical or high release blocker | Four open (`RT-F1`, `RE-F1`, `RE-F4`, `RE-F5`) |
| Human-factors validation completed | `BLK-003`; no session run |
| Recovery exercises executed and measured | `NS-EXC-004`; production exercises unexecuted |
| Provider due diligence complete, if a hosted model is used | `BLK-004`; no provider approved |
| Retention, deletion, and legal hold approved | `BLK-001` |
| Named accountable owner, Legal, Privacy, Clinical Safety, and Records approvals | None exist |
| Incident tabletop run with an after-action record | `BLK-005`; none run |

## Scope, if it were authorized

Two facilities, no more than fifteen care coordinators, administrative follow-up tasks only,
synthetic or fully consented data, and a named clinical-safety contact reachable during every shift
the system is available. No patient-facing surface, no clinical content, no autonomous execution.

## Monitoring thresholds and stop conditions

Continuous monitoring, with any single breach stopping the pilot rather than triggering a review:

| Signal | Threshold | Action on breach |
|---|---|---|
| Unauthorized access attempt succeeding | Any | Stop; disable all capabilities; incident |
| Clinical content produced or accepted | Any | Stop; Clinical Safety incident (`PB-05`) |
| Action executed without independent approval | Any | Stop; incident; audit reconstruction |
| Approval rate above the anti-fatigue threshold | To be set by `CTL-ACT-004` | Pause writes; review workload |
| Abstention rate outside the agreed band | ±50% of baseline | Review corpus and retrieval quality |
| Safety event, near miss, or complaint | Any | Clinical Safety review before resuming |
| Retrieval evaluation security cases | Below 100% | Stop; treat as poisoning until excluded |
| Detection `DET-004`, `DET-006`, or `DET-010` firing | Any | Contain per the matching playbook |
| Readiness unavailable | 15 minutes cumulative | Fall back to the non-AI workflow |

The anti-fatigue threshold is deliberately unset. `CTL-ACT-004` does not exist yet, and `HF-08` is
the study that should determine the number rather than an engineer's guess.

## Exit and rollback

The pilot ends on schedule, on any stop condition, or on the owner's decision. Exit runs the
retirement exercise (`NS-LCM-001`): revoke capabilities first, delete operational data, retain the
audit chain, and confirm the deployment serves nothing afterwards.

## What this document is not

It is not an authorization, a plan of record, or evidence that a pilot is achievable. It exists so
that the conditions are written down before anyone is under pressure to start one.

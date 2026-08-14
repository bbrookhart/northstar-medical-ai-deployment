# NS-ASR-008 — AI Incident Tabletop Protocol

**Status:** Specified; **no tabletop has been run**  
**Owners:** AI Security Lead (facilitation), SOC and SRE on-call (participants), Clinical Safety
Lead (observer)  
**Related:** REQ-OPS-004, CTL-OPS-002, BLK-005

## Why this is a protocol and not a result

`REQ-OPS-004` is satisfied by a tabletop and an after-action record, not by written playbooks. A
playbook nobody has walked through is a hypothesis about how people will behave under pressure.

## Participants

Six to eight people covering SOC on-call, SRE on-call, AI security, engineering, clinical safety,
and privacy. The facilitator must not be the author of the playbooks, and the playbook author may
not answer for participants during the exercise.

## Scenarios

Each runs against synthetic data with the real system available for participants to inspect.

| ID | Scenario | Playbook under test | Primary question |
|---|---|---|---|
| TT-01 | A clinician reports the assistant quoted a policy they cannot access | PB-01 | Do participants contain before investigating, and avoid copying disclosed content into the ticket? |
| TT-02 | `DET-004` fires on a fabricated citation during a busy shift | PB-02 | Do participants check for executions rather than assuming a proposal is harmless? |
| TT-03 | An ingested vendor document contains an embedded instruction | PB-03 | Do participants roll the corpus back and re-run the evaluation before restoring service? |
| TT-04 | The model provider announces a compromise | PB-04 | Do participants disable only `MODEL`, and resist failing over to an unapproved provider? |
| TT-05 | A drafted task contains clinical direction | PB-05 | Is Clinical Safety notified without prompting, and is the boundary treated as failed? |
| TT-06 | State integrity fails during peak hours | PB-06 | Do participants refuse to relax freshness bounds to restore service? |
| TT-07 | A dependency advisory lands mid-release | PB-07 | Do participants treat the failing gate as a signal rather than an obstacle? |

## Pass criteria

- Containment is chosen before investigation in every scenario, and the correct capability is
  disabled — disabling everything is a failure, not a safe default.
- No participant proposes bypassing approval, relaxing a staleness bound, or handling real PHI.
- TT-05 produces an unprompted clinical-safety notification. This admits no partial credit.
- TT-06 produces no proposal to relax a freshness or staleness bound.
- Every scenario ends with participants able to state the exit criteria without reading them aloud
  from the playbook.
- The after-action record names at least one playbook defect. A tabletop that finds nothing was
  either too easy or not honestly run.

## Results

| Scenario | Date | Participants | Result | Playbook defects found |
|---|---|---|---|---|
| TT-01 disclosure | — | — | Not assessed | — |
| TT-02 injection | — | — | Not assessed | — |
| TT-03 poisoning | — | — | Not assessed | — |
| TT-04 provider compromise | — | — | Not assessed | — |
| TT-05 unsafe output | — | — | Not assessed | — |
| TT-06 outage | — | — | Not assessed | — |
| TT-07 supply chain | — | — | Not assessed | — |

Until this table carries dates, participants, and findings, `REQ-OPS-004` is unmet, `BLK-005`
remains open, and no incident-response capability may be claimed.

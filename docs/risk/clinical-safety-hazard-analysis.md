# NS-SAF-001 — Clinical Safety Hazard Analysis

**Status:** M02 simulated review complete; actual Clinical Safety approval required before pilot  
**System scope:** Administrative clinical operations; not a medical device or clinical decision system  
**Safety owner:** Clinical Safety Officer  
**Date:** 2026-08-11

## Safety position

Administrative software can still harm patients through wrong identity, wrong task, delayed work,
misinformation, automation bias, privacy-related avoidance of care, and outage. Excluding diagnosis
does not eliminate clinical-safety obligations. Polaris remains assistive, reviewable, and reversible.

## Rating method

Severity: S1 negligible, S2 temporary/minor, S3 serious delay or intervention, S4 death/permanent
harm plausible. Probability before control: P1 remote, P2 occasional, P3 probable, P4 frequent.
Detectability: D1 likely detected before impact, D2 may be detected, D3 unlikely to be detected.
Any plausible S4 hazard and any S3 with P3/P4 requires design reduction and Clinical Safety review;
a numeric product does not override expert judgment.

## Hazard log

| ID | Hazardous situation and causes | Initial | Principal controls | Safety verification | Target |
|---|---|---|---|---|---|
| HAZ-01 | Wrong patient summary/task due to IDOR, stale assignment, cache mix-up, user selection | S4/P2/D3 | Patient/facility/assignment/purpose policy, prominent identity, no fuzzy patient matching, idempotent task | Cross-patient matrix; wrong-patient usability scenarios | P1/D1 |
| HAZ-02 | Clinical recommendation, medication instruction, diagnosis, or triage is presented | S4/P2/D2 | Prohibited scope, deterministic clinical gate, no clinical tools, fixed emergency instruction, sampling | Clinical boundary/adversarial set reviewed by clinician | P1/D1 |
| HAZ-03 | Hallucinated/outdated policy causes inappropriate or delayed workflow | S3/P3/D3 | Approved sources, version/freshness, citations, conflict rule, abstention, owner links | Golden policy set; citation/source freshness metrics | P1/D1 |
| HAZ-04 | Necessary follow-up is omitted because model abstains/fails and user assumes completion | S4/P2/D3 | Clear completion state, no silent success, fallback/manual workflow, task receipt, escalation | Failure-mode and handoff tests; task reconciliation | P1/D1 |
| HAZ-05 | Duplicate/excessive/incorrect queue task delays other care work | S3/P3/D2 | Exact approval, required fields, duplicate/idempotency, quotas, outcome verification | Replay/race/load and queue reconciliation tests | P1/D1 |
| HAZ-06 | Approval fatigue or deceptive preview produces unsafe task | S3/P3/D3 | Independent approver, exact trusted preview/diff, expiry, workload cap, accessible design | Human-factors study; hidden-character and bulk tests | P2/D1 |
| HAZ-07 | User over-relies on fluent output and stops reviewing source/patient details | S4/P2/D3 | Draft/status labels, citations/uncertainty, active confirmation, training, usage sampling | Comprehension/automation-bias study and audit sampling | P1/D2 |
| HAZ-08 | Service outage or latency disrupts time-sensitive administrative care | S4/P2/D2 | SLOs, dependency timeouts, safe degraded read-only/manual flow, queue visibility, continuity plan | Fault injection, downtime exercise, RTO/RPO evidence | P1/D1 |
| HAZ-09 | Sensitive disclosure causes stigma, distress, or avoidance of care | S4/P2/D3 | Part 2 labels/consent policy, minimum view, downstream minimization, privacy response | Sensitive lineage/access/exfiltration tests | P1/D1 |
| HAZ-10 | Language/accessibility defect causes wrong approval, missed warning, or exclusion | S3/P3/D2 | WCAG, keyboard/screen reader, plain language, non-color cues, alternate workflow | Accessibility and representative-language evaluation | P1/D1 |
| HAZ-11 | Model/provider/corpus/prompt drift silently changes safe behavior | S4/P2/D3 | Immutable versions, regression thresholds, canary, staged release, rollback/kill | Change-detection and rollback exercise | P1/D1 |
| HAZ-12 | Incorrect task is executed after role/assignment/policy changed | S3/P2/D3 | Short expiry, execution-time requester/executor/policy reauthorization, cancellation | Time-of-check/time-of-use and revocation tests | P1/D1 |
| HAZ-13 | Unclear emergency response delays established urgent channels | S4/P2/D3 | Fixed prominent emergency instruction; system does not assess urgency; immediate fallback | Emergency phrase/scenario and usability tests | P1/D1 |
| HAZ-14 | Security control blocks legitimate access with no safe escalation | S3/P3/D2 | Clear non-sensitive denial, authorized break-glass design outside model, manual fallback, monitoring | Denial/help-desk/escalation simulation | P2/D1 |

## Safety requirements

- The UI never states or implies that an administrative task, message, or source review is completed
  until a trusted downstream confirmation exists.
- The system does not determine whether an emergency exists. For urgent/emergency language, it gives
  a fixed instruction to use Northstar's established emergency channels and performs no write.
- Patient identity and destination queue remain visible at review and approval; no model-selected
  patient substitution or fuzzy matching is permitted.
- Every substantive policy answer has approved citations or an explicit abstention.
- Users can abandon, correct, or use the non-AI workflow without penalty.
- Safety telemetry includes abstention, unsafe-scope detection, source freshness, wrong/duplicate
  task findings, override/edit behavior, outage/fallback, complaints, and near misses—without raw PHI.

## Pilot stop thresholds to define and approve

Immediate stop examples: any executed clinical instruction; confirmed cross-patient disclosure;
wrong-patient task execution; bypassed/tampered approval; silent success without task creation;
uncontained provider/corpus compromise; or inability to disable write capability. Quantitative
thresholds for citation error, unsafe completion, latency, duplicates, complaints, and subgroup
performance require baseline data and Clinical Safety approval before a simulated pilot.

## Safety case status

The local deterministic slice demonstrates several mechanisms but is not a clinical safety case.
Clinical review of scenario coverage, UI human factors, real integration behavior, operational
fallback, monitoring, and incident exercises is still required before any pilot decision.

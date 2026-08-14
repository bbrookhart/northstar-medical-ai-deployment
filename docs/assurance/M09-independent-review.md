# NS-ASR-007 — M09 Simulated Independent Assurance Review

**Review status:** Conditional — assurance mechanisms accepted, release refused  
**Review date:** 2026-08-14  
**Decision scope:** Whether the M09 evaluation and campaign support a release decision  
**Not authorized:** Release, pilot, production, real PHI, hosted model, or clinical use

## Integrity statement

This artifact records a role-based simulation of independent assurance review. Independence is
itself simulated: the reviewer, the implementer, and the attack author are the same process. That is
the most important limitation on this page, and it is recorded as finding `RT-F3` rather than
mentioned in passing.

## Material reviewed

- `evidence/reports/M09-red-team.json` — 21 cases, 14 classes, containment and control attribution;
- `evidence/reports/M09-release-evaluation.json` — 11 dimensions with declared status;
- `docs/assurance/M09-remediation-ledger.md`;
- the campaign source, including which control each case expects to be stopped by; and
- all open blockers and limitations.

## Reviewer challenge

| Question | Finding |
|---|---|
| Does the campaign cover what `REQ-SDL-004` requires? | Yes. All 14 classes are represented and coverage is asserted by a test, so removing a class fails the build |
| Is containment attributed, or merely observed? | Attributed. Each case names the control expected to stop it, so a pass in the wrong place is visible in the report |
| Are any cases vacuous? | One was. The encoded-injection case originally passed because nothing matched the query; it now runs the full agent with a model that tries to act on the payload and asserts no write occurred |
| Could a green campaign be mistaken for a secure system? | Only if the reader ignores `RT-F1` and `RT-F3`. The report records the model as `red-team-adversarial-model` against a deterministic stack |
| Does the evaluation overstate readiness? | No. `release_ready` is false, and blocking gaps are reported separately from unassessed dimensions so a partial evaluation cannot read as a complete one |
| Are unassessed dimensions honestly labelled? | Yes. Accessibility, performance, cost, and recovery are `NOT_ASSESSED` with reasons, and two carry no evidence reference at all |
| Would an independent assessor reach the same decision? | Unknown, and that is the point of `RT-F3`. Independent authorship is required before any release claim |

## Decision

The assurance **mechanisms** are accepted: the campaign is complete against its declared taxonomy,
deterministic, attributed to controls, and enforced by `make verify` and CI. The release evaluation
correctly refuses to collapse partial evidence into a single readiness claim.

**A release is refused.** Four high-severity findings are open — untested against a real model, no
accessibility evidence, no executed recovery exercise, and partial privacy and safety assessment.
`REQ-SDL-005` forbids proceeding with an open high blocker, and none of them is reclassified to fit
a decision.

Residual risk is therefore **not accepted** and no named approval is recorded, because there is no
real accountable person to record and a simulated signature on a release decision would be the most
misleading artifact in this repository.

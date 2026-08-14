# Lab 1 — Break the Traceability Chain

**Module:** 4 — Requirements, controls, traceability, and evidence  
**Time:** 40 minutes  
**Prerequisite:** `make verify` passes on a clean checkout

## Objectives

By the end you can state, from evidence rather than memory, what a control system enforces and what
it merely records.

1. Explain the difference between a control that is `implemented`, `partial`, and `planned`.
2. Predict which change breaks the traceability validator and which does not.
3. Explain why claiming verified evidence for a planned control is refused.

## Concepts

The catalogs in `governance/` are typed data, not documentation. `CTL-*` controls cite `REQ-*`
requirements, `RSK-*` risks, `VER-*` verifications, and `EVD-*` evidence. `make governance` fails if
any of those references dangles, if a requirement is orphaned, or if a generated report is stale.

## Decision exercise (10 min)

Before touching anything, write down your prediction for each change: does the build fail, and why?

| Change | Prediction |
|---|---|
| A. Add a control citing a verification identifier that is not in the catalog | |
| B. Change a control's status from `partial` to `implemented` | |
| C. Attach `EVD-M09-001` to a control whose status is `planned` | |
| D. Edit a generated report by hand | |

## Steps

Run each change, then `make governance`. Reset with `git checkout -- .` between steps.

**Step 1 — a dangling verification.** In `governance/control-library.json`, add a verification
identifier that does not exist to any control's `verification_ids`. Invent one in the `VER-` shape
that is absent from `governance/verification-catalog.json`.

(The lab deliberately does not print a fake identifier here: the portfolio claims checker resolves
every identifier in this file against the catalogs, and a literal fake would fail its own build. That
constraint is itself worth noticing.)

**Step 2 — an unjustified promotion.** Change `CTL-AI-001` status from `partial` to `implemented`.
Observe carefully: does the validator object?

**Step 3 — evidence on a planned control.** Set a control's status to `planned` while it still cites
existing evidence.

**Step 4 — a hand-edited report.** Change one number in `evidence/reports/M03-traceability-report.md`
and run `make governance`.

## Expected results

Steps 1, 3, and 4 fail the build. **Step 2 does not** — and that is the lesson.

The validator enforces structural integrity: references resolve, nothing is orphaned, generated
reports are current, and a planned control cannot claim verified evidence. It cannot tell you whether
a control marked `implemented` actually works. That judgement belongs to a reviewer, and no amount of
typing enforces it.

Step 3 mirrors something that happened during development: `CTL-AI-001` was `planned` when the
provider-neutral boundary was implemented, and the validator refused the evidence until the status
was corrected to `partial`. The rule caught a real inconsistency, not a hypothetical one.

## Common failures

- Editing the JSON without re-running `make governance-report`, then blaming the drift check.
- Concluding that a green validator means the controls are effective. It means they are *coherent*.
- Forgetting to reset, so a later step fails for an earlier reason.

## Assessment

1. *(Short answer)* A colleague marks eleven controls `implemented` in one commit and CI passes.
   What have you learned, and what have you not? **(4 marks)**
2. *(Short answer)* Why does the validator refuse verified evidence on a planned control, when the
   evidence genuinely exists? **(3 marks)**
3. *(Practical)* Add a new control, requirement reference, verification, and evidence entry that
   passes `make governance` without weakening any rule. **(5 marks)**

### Rubric

- **Q1 (4):** 2 marks for identifying that structural coherence was verified; 2 for stating that
   effectiveness was not, and naming who must judge it.
- **Q2 (3):** 2 marks for the claim-integrity rule; 1 for noting the correct fix is to change the
   status, not to remove the evidence.
- **Q3 (5):** 3 marks for a passing chain; 2 for an honest status, meaning the learner did not mark
   something `implemented` to make it pass.

## Instructor notes

The trap is Step 2. Most learners predict it fails, and the discussion after it does not is the point
of the lab. Do not warn them beforehand.

If a learner asks whether the validator *should* catch Step 2, that is the right question: the answer
is that it would need to evaluate the implementation, which is what the verification suite and human
review are for — and this is exactly why `implemented` is the rarest status in the catalog.

## Reset

```bash
git checkout -- .
make verify
```

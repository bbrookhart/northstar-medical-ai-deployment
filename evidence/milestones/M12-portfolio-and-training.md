# M12 Portfolio and Training — Claims Traced, Gate Met

**Evidence ID:** EVD-M12-001  
**Date:** 2026-08-14  
**Scope:** Case study, evidence tour, demo script, and a training package with three worked labs  
**Decision:** **Pass.** Every claim resolves to a repository artifact, checked in CI

## Why this gate can be met when six others could not

The M12 exit criterion is that an independent learner can reproduce the labs and that portfolio
claims trace to repository evidence. Unlike human-factors validation, an operator demonstration, or a
governance authorization, that is a property of the material — and a property can be checked.

So it is checked, rather than asserted.

## Claim supported

### Claims are verified, not reviewed

`verify_claims` reads every markdown file under `portfolio/` and `training/` and fails the build on
any of:

- an identifier that does not resolve — `EVD-*`, `VER-*`, `CTL-*`, `REQ-*`, `RSK-*`, `BLK-*`,
  `NS-EXC-*`, `ADR-*`, plus attack and drill case identifiers drawn from the generated reports, so a
  cited attack must actually have run;
- a markdown link whose target does not exist;
- a documented `make` command that is not a declared target; or
- prohibited claim language — compliance, certification, clearance, production readiness, absolute
  security, zero risk, or "all gates pass".

Current result: **11 documents, 78 identifiers resolved, 0 findings.**

Denial is permitted and tested. "This is not production ready" and "no claim of HIPAA compliance is
made" must pass, because banning the words outright would forbid the honest sentence and reward
silence.

### The checker found three defects in its own material

Writing the check before finishing the prose was deliberate, and it paid immediately:

- three `REQ-*` identifiers in the evidence tour did not resolve, because the loader only read
  catalog primary keys and not the requirement references inside controls;
- the phrase "make and defend decisions" in the training README was parsed as a command, so command
  detection now only applies inside code spans and fenced blocks; and
- a literal fake identifier used to teach a lab step failed the check, so the lab now describes the
  fake instead of printing one — and says why, because the constraint is itself instructive.

### The portfolio leads with the refusals

`portfolio/case-study.md` opens with the gate table: six gates unmet or conditional. It names four
defects that only surfaced by running code — the scanner that rejected the safety policy, the drill
that asserted the wrong half of a control, the red-team case that passed for the wrong reason, and
the container that built and then failed to start.

`portfolio/evidence-tour.md` walks three chains from risk to gate, and the third deliberately ends at
a failed gate. `portfolio/demo-script.md` spends its final minute on the refused pilot authorization.

### The training package states what it is not

Three labs are complete with steps, expected results, common failures, assessments with rubrics, and
instructor notes. Nine modules are outlined against real artifacts and are explicitly **not** claimed
as complete, because writing a lab guide is cheap and writing one whose exercise fails for the right
reason is not.

Each lab's expected results include the case where the learner succeeds — corpus admission via a
multilingual payload — and redirect to what the architecture does next. The instructor guide's
grading calibration rewards correct scepticism over correct answers.

## Verification

```text
make portfolio
make verify
```

Result on Python 3.13.11:

- Portfolio claims: 11 documents, 78 identifiers resolved, 0 findings
- All other gates: pass
- Strict mypy: pass across 103 source/test files
- Pytest: pass, 482 default-suite tests; 1 Docker-gated integration skipped by design
- Coverage: 88.02%; required floor 85%

17 tests are new in this increment.

## What is not established

- **The material has never been taught.** No cohort has run these labs, so "an independent learner
  can reproduce them" is verified structurally — the commands are real targets, the artifacts exist —
  and not empirically.
- **Nine of twelve modules are outlines.** Concepts and objectives only.
- **No accessibility review** of the course material has been performed.
- **The checker verifies traceability, not quality.** A claim can resolve to an artifact and still be
  a poor explanation.
- Licensing and attribution remain undecided (`DEC-001`), so nothing here is cleared for publication.
- Completing the course establishes nothing about compliance, certification, clearance, or readiness
  for production use.

## The program at its end

Twelve milestones. Six gates unmet or conditional, five live exceptions, six open blockers, and a
refused pilot authorization.

That is the result. A program of this shape reporting twelve green gates would have been the warning
sign, and the parts most worth reading are the four defects that only appeared when something was
run rather than described.

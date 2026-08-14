# M11 Pilot, Change Control, Audit, and Retirement — Authorization Refused

**Evidence ID:** EVD-M11-001  
**Date:** 2026-08-14  
**Scope:** Change-impact analysis, audit package assembly, and an executed retirement exercise  
**Decision:** **The M11 gate does not pass.** The change, audit, and retirement mechanisms work; the
gate asks a governance board to authorize a pilot, and the board refused

## Why the refusal is the deliverable

The M11 exit criterion is "a simulated governance board authorizes pilot and later production or
retirement decisions." Producing that authorization would have been trivial — write the document,
sign it with role placeholders, mark the milestone complete.

`NS-ASR-009` refuses instead, on two grounds: all seven pilot entry conditions are unmet, and there
is nobody with standing to authorize anything. A simulated signature on a pilot decision does not
produce a weaker authorization; it produces a counterfeit one that looks exactly like the real thing
to whoever reads it next.

## Claim supported

### Change impact is decided from the bill of materials

`analyze_change` diffs two AIBOM documents and reports what a change obliges. The AIBOM is the right
input because it already describes the things that alter behavior — model identity, system-contract
digest, serving corpus manifest and confidential partition, tool surface and argument schemas, agent
bounds, kill switches, and evaluation thresholds. Diffing it means a change cannot be reviewed as
"just a config tweak" when it alters what the system does.

Tests prove each change class is detected and carries the right obligation:

| Change | Impact | Required actions |
|---|---|---|
| Hosted provider introduced | Material | Provider due diligence, adversarial campaign, safety review |
| System contract changed | Material | Campaign and retrieval evaluation |
| Serving corpus manifest changed | Material | Retrieval evaluation, regenerate the bills of materials — and the summary names which documents moved |
| Write tool added | Material | Campaign, clinical-safety review, human-factors re-test |
| Cross-session memory enabled, or a bound raised | Material | Campaign, safety and human-factors review |
| Kill switch removed | Material | Campaign and safety review |
| Evaluation threshold lowered or cases removed | Material | A residual-risk decision justifying it |
| Lockfile changed | Notable | Regenerate the bills of materials |

Lowering a threshold is treated as material because that is how a failing evaluation gets made to
pass. An unchanged AIBOM produces no changes and requires no review, so the analyzer is not simply
alarming on everything.

### The audit package indexes evidence, including what is open

`build_audit_package` walks the evidence catalog, confirms each existing artifact is present, and
records its SHA-256 and size — 24 artifacts, none missing. It also carries the six open blockers and
reads the unmet gates directly from `docs/assurance/release-gates.md` rather than restating them, so
the package cannot disagree with the gate record.

An audit package that listed only what passed would be marketing. This one tells an assessor where
to look first: M07, M09, and M10 gates not met; M04 and M08 conditional.

### Retirement was executed

| Step | Objective | Result |
|---|---|---|
| `RT-01` | Live operational data exists before retirement | Met |
| `RT-02` | Every capability revoked **before** any deletion | Met |
| `RT-03` | Operational records deleted, none readable | Met |
| `RT-04` | The tamper-evident audit chain survives and still verifies | Met |
| `RT-05` | The retired deployment refuses runs, serves no corpus, and has no proposals | Met |

Two ordering decisions matter. Capabilities are revoked before anything is deleted, so nothing can
act mid-retirement. And two tables are retained deliberately: the audit chain, because destroying it
would remove the only evidence that the deletion happened; and the capability state, because deleting
it would restore the default "enabled" on the next start and a retired deployment would come back up
serving.

## Verification

```text
make lifecycle
make verify
```

Result on Python 3.13.11:

- Audit package: 24 artifacts indexed, 0 missing, 5 unmet or conditional gates carried
- Retirement: 5 steps, all objectives met
- All other gates: pass
- Strict mypy: pass across 100 source/test files
- Pytest: pass, 465 default-suite tests; 1 Docker-gated integration skipped by design
- Coverage: 87.88%; required floor 85%

14 tests are new in this increment.

## What is not established

- **No pilot is authorized, and none may begin.** All seven entry conditions in `NS-PRG-003` are
  unmet.
- **No real approval exists.** Every role is a placeholder. The board decision refuses partly on that
  basis.
- **No provider deletion, backup expiry, legal hold, or downstream termination** was exercised. The
  retirement covers local synthetic data only, and no retention schedule is approved (`BLK-001`,
  `REQ-DAT-007`).
- **No change-impact review has actually been conducted.** The analyzer is a tool; a review is people
  using it.
- No training, support, or correction journey exists (`REQ-LCM-001`, `REQ-LCM-002`).
- The anti-fatigue threshold in the pilot protocol is deliberately unset: `HF-08` should determine it
  rather than an engineer guessing.

## Next safe increment

M12 recruiter case study and training conversion — the only remaining milestone whose gate this
program can meet, because it asks for materials whose claims trace to repository evidence rather than
for authorization from people who do not exist.

The evidence to draw on is unusually specific: five gates unmet or conditional, five live exceptions,
six open blockers, and a refused pilot authorization. A portfolio that presents those as the result
is more credible than one that presents a green board.

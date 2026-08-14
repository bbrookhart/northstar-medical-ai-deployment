# Project Polaris — Case Study

**What this is:** an end-to-end simulation of adopting a constrained internal agentic AI capability
at a fictional healthcare enterprise, built as reviewable evidence rather than as a demo.

**What it is not:** a deployed system, a compliance artifact, or a claim that any real organization
has done this. Every identifier cited below resolves to an artifact in this repository, and a check
in CI fails the build if one does not.

## The executive summary

Northstar Medical wants an assistant that answers policy questions and drafts administrative
follow-up tasks. The interesting problem is not building it. It is proving what it cannot do.

Twelve milestones were delivered. **Six gates did not pass**, and that is the result, not a
shortfall:

| Milestone | Gate outcome | Why |
|---|---|---|
| M00–M03 | Pass | Program, risk, and control foundations |
| M04 identity, policy, FHIR | Conditional | Four time-bound exceptions, `NS-EXC-001` to `NS-EXC-004` |
| M05 secure RAG | Pass | Security cases 100%, quality 100% against a 90% floor |
| M06 bounded agent | Pass | A fully compromised model is contained |
| M07 approval UX | **Not met** | No human-factors evidence exists (`BLK-003`) |
| M08 supply chain | Conditional | Signing, provenance, scanning deferred (`NS-EXC-005`) |
| M09 assurance and red team | **Not met** | Every attack contained; four high findings still open |
| M10 operations | **Not met** | Drills executed; no operator, no tabletop (`BLK-005`) |
| M11 pilot and retirement | **Not met, by decision** | Pilot authorization refused |
| M12 portfolio and training | Pass | Claims trace to artifacts, checked in CI |

A program of this shape that reported twelve green gates would be the warning sign. The refusals are
the load-bearing part.

## The decision that shaped everything

The model is never an authorization boundary. Stated that way it is a platitude; the work was making
it a property of the types.

`ModelRequest` has no field for a credential, a principal, a token, or a session. Not "we don't
populate it" — the field does not exist, so `REQ-AI-001` holds by construction rather than by
discipline. Every tool call re-derives authorization from the calling principal through the same
services the HTTP API uses. The model choosing a patient identifier does not make that patient
readable.

The adversarial campaign tests this by scripting hostile intents directly rather than prompting a
model to misbehave — which exercises the boundary instead of the model's willingness to comply
(`VER-SDL-003`).

## Four things found by running, not reading

These are the parts worth reading closely, because they are what separates a system that was built
from one that was described.

**A scanner that rejected the safety policy.** Corpus content scanning refused `POL-AI-001` — the
policy stating Polaris *must not* diagnose or prescribe — for containing the words it prohibits. The
clinical-boundary control was keeping the clinical-boundary policy out of the corpus. The check now
runs per sentence and admits prohibitive sentences (`ADR-010`, `EVD-M05-001`).

**A drill that asserted the wrong half of a control.** The kill-switch game day failed on its first
run. With writes disabled the tool is not advertised at all, so a well-behaved model never asks and
never produces a refusal — asserting only on the refusal mis-modelled the control. It now checks both
halves (`EVD-M10-001`).

**A red-team case that passed for the wrong reason.** The encoded-injection case passed because the
base64 payload matched nothing in the corpus. It now runs the full agent with a model that tries to
act on the payload and asserts no write occurred (`EVD-M09-001`).

**A container that built and then failed to start.** The virtual environment was created at the
builder path and copied elsewhere, so its absolute interpreter shebangs failed at runtime with a
misleading error. Reading the Dockerfile would not have caught it (`EVD-M08-001`).

## What the evidence system actually enforces

Seven checks run in CI, and each one fails the build:

```text
make verify
```

- governance traceability, with every requirement, risk, and scenario resolving to a control;
- the retrieval golden set, security cases at 100% and quality at 100% against a 90% floor;
- the release supply-chain policy — pinned actions, pinned digests, bounded dependencies, hardened
  containers, no tracked secrets;
- the adversarial campaign across all fourteen required attack classes;
- five operational drills including a backup, corruption, and restore with audit-chain verification;
- the audit package and retirement exercise; and
- lint, strict typing, 465 tests, and an 85% coverage floor.

Generated evidence is committed and drift-checked, so changing a bound, a tool, or a threshold shows
up as a diff in a reviewed artifact rather than silently.

## The refusal that matters most

`NS-ASR-009` refuses to authorize a pilot. Producing the authorization would have taken five
minutes: write the document, sign it with role placeholders, mark M11 complete.

It refuses on two grounds. All seven pilot entry conditions are unmet. And nobody has standing to
authorize anything — every role in this program is a placeholder. A simulated signature on a pilot
decision does not produce a weaker authorization; it produces a counterfeit one that looks exactly
like the real thing to whoever reads it next.

## What an engineer should take from this

The remaining work is not more engineering. It is a human-factors session with real clinicians, an
operator running a tabletop, an independent red team, an accountable owner, and a records decision.
Recognising which problems code cannot close is most of the job.

## Honest limitations

Retrieval is deterministic keyword matching, so the M05 thresholds measure controls and not answer
quality. The model adapter is a fixed policy, not a language model, so M06 proves containment and not
capability. Treatment relationship and Consent are fixtures. No signal client has contacted a live
provider. Nothing is signed, attested, or scanned. This is a simulation using synthetic data, and it
makes no claim of compliance, certification, clearance, or readiness for production use.

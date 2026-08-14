# NS-ASR-009 — Simulated Governance Board Decision

**Decision:** **Pilot authorization refused**  
**Decision date:** 2026-08-14  
**Scope considered:** Authorization to begin a limited clinical-operations pilot  
**Related:** NS-PRG-003, EVD-M09-001, EVD-M10-001, EVD-M07-001, all open blockers

## Integrity statement

This is the artifact the M11 gate asks for: "a simulated governance board authorizes pilot and later
production or retirement decisions." The board is simulated, and so is every signature that could
appear below.

That is precisely why the answer is no. A simulated board producing a simulated authorization would
be the most dangerous document in this repository — it would look exactly like the real thing, and it
would be cited later by someone who did not read this paragraph.

## Material considered

- `EVD-M09-001`: every adversarial case contained, four high-severity findings open, release refused
- `EVD-M10-001`: five drills executed and met, no operator demonstration, no tabletop
- `EVD-M07-001`: presentation contract verified, no human-factors evidence
- `EVD-M08-001`: supply-chain gate enforced, signing and provenance deferred
- `NS-PRG-003`: seven pilot entry conditions, **none** currently met
- Six open gate blockers, `BLK-001` through `BLK-006`
- Five exception records, `NS-EXC-001` through `NS-EXC-005`, all live

## Decision

**Refused, on two independent grounds.**

First, the entry conditions are unmet. Not narrowly — all seven. A pilot requires no open high
finding, human-factors validation, executed recovery exercises, provider due diligence if a model is
hosted, approved retention and deletion, named accountable approvals, and a completed tabletop. None
of those exists.

Second, and more fundamentally: **there is no one to authorize it.** Every role in this program is a
placeholder. A pilot decision requires a named accountable owner who bears the consequences, and
Legal, Privacy, Clinical Safety, and Records approvals from people who can be asked to explain them.
Simulating those signatures does not produce a weaker authorization — it produces a counterfeit one.

## What is authorized

Continued synthetic development within the existing boundary. Nothing else.

## What would change this

Not more engineering. The remaining work is the kind that requires real people: clinicians in a
human-factors session, an operator running a tabletop, an independent red team, an accountable owner,
and a records decision from someone with the authority to make one.

A program that reached this point with every gate green would have been the warning sign.

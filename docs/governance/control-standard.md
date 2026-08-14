# NS-CTL-STD-001 — Control Statement and Evidence Standard

**Status:** M03 baseline  
**Owner:** AI Security Program Lead  
**Effective date:** 2026-08-11

## Purpose

This standard makes Northstar controls testable, traceable, and honest about operating status. The
canonical machine-readable control set is `governance/control-library.json`; this document defines
how entries are written, reviewed, tested, evidenced, changed, and retired.

## Required control anatomy

Every control must include:

- a stable `CTL-{DOMAIN}-{NNN}` identifier and outcome-oriented title;
- one objective that explains the risk-reduction outcome without prescribing a vendor;
- one accountable owner role;
- exactly one status: `implemented`, `partial`, or `planned`;
- control type and operating frequency/event;
- one or more requirement and risk identifiers;
- implementation, verification, evidence, and framework-reference identifiers or paths; and
- enough scope information to prevent local simulation evidence from implying enterprise operation.

Control statements use decisive, testable language. `MUST`/`MUST NOT` is mandatory, `SHOULD` needs
an approved exception, and `MAY` is optional. A control is not a product feature, policy title, or
framework citation; it is an owned mechanism whose design and operation can be challenged.

## Status and claim rules

| Status | Minimum basis | Permitted claim |
|---|---|---|
| Implemented | Current-scope implementation exists; at least one verification is `verified`; at least one evidence item is `existing` | Operates only for the evidence scope and time |
| Partial | A mechanism or design exists, but enterprise scope, a requirement element, verification, or operating evidence is incomplete | Partial mechanism demonstrated; limitations named |
| Planned | Design intent and acceptance criteria exist; linked verification/evidence are planned | Required future work only; no operating claim |

Documentation alone cannot make a technical or operating control `implemented`. A passing test does
not prove continuous operation, legal compliance, clinical validity, accessibility, or residual-risk
acceptance. Generated traceability evidence proves catalog integrity only.

## Verification standard

Verification entries use stable `VER-*` identifiers and define owner, method, status, and exact test
location, artifact, command, study, or exercise criteria. A credible control normally combines the
appropriate methods:

- positive, negative, boundary, mutation, abuse, and fault tests;
- design/configuration review by the accountable discipline;
- runtime or operating-effectiveness sampling;
- accessibility, human-factors, privacy-journey, clinical-safety, or resilience exercises; and
- independent challenge for high-impact release decisions.

Verified automated test references must resolve to a real repository test. Planned tests must state
acceptance criteria. Passing checks can be invalidated by a material change to data, model, prompt,
corpus, policy, tool, provider, population, jurisdiction, integration, autonomy, or environment.

## Evidence standard

Evidence uses stable `EVD-*` identifiers and records owner, status, scope, and durable artifact path.
It must be reproducible, minimum necessary, public-safe where published, and attributable to the
revision/configuration and decision it supports. Never store PHI, secrets, hidden reasoning,
unnecessary raw prompts, or unredacted sensitive logs.

Evidence states are `existing`, `generated`, or `planned`. Generated reports must be deterministic
and checked in CI for drift. Planned evidence makes no implementation claim. Superseded evidence is
retained or disposed according to the approved record schedule, which remains a pilot blocker.

## Framework mapping rule

Framework mappings express how one Northstar control supports an external outcome. They do not
convert a control into certification or legal compliance. Each mapping resolves through
`governance/framework-registry.json` to a dated authoritative source and is either reviewed or
provisional. Exact category coverage cannot be claimed for a provisional source.

## Change and approval workflow

1. The change names affected risk, requirement, control, verification, evidence, and gate IDs.
2. The control owner and affected Security, Privacy, Clinical Safety, Data, Operations, and
   Legal/Compliance roles assess materiality.
3. Implementation and verification change together; the generated report is refreshed.
4. CI rejects orphan IDs, unresolved references, missing verified artifacts, stale reports, and
   untreated registered risks.
5. A release decision records open findings, exceptions, residual risks, expiry, monitoring, and
   actual approvers. Simulated role review is labeled and never represented as real approval.

Controls are retired only after dependent requirements/risks are remapped, access and secrets are
revoked, required evidence is preserved, data is disposed, and downstream termination is verified.

# M09 Assurance and Red Team — Campaign Contained, Release Refused

**Evidence ID:** EVD-M09-001  
**Date:** 2026-08-14  
**Scope:** Adversarial campaign and release evaluation against the deterministic local stack  
**Decision:** **The M09 gate does not pass.** All 21 attacks were contained across all 14 required
classes, and the release evaluation refuses a release: four high-severity findings are open

## Why a fully contained campaign still fails the gate

The M09 exit criterion is "no open critical/high release blockers; residual risk receives named
approval." The campaign found no exploitable weakness, but the *evaluation* found four high-severity
gaps, and `REQ-SDL-005` forbids proceeding with any of them open.

Passing an attack suite is not the same as being releasable. Recording that distinction is the point
of this milestone.

## The campaign

`scripts/red_team.py` runs 21 cases against a real stack — corpus ingestion, retrieval index,
agent orchestrator, action service, and presentation layer — rebuilt per case so one attack cannot
contaminate the next.

| Class | Cases | Contained | Control that held |
|---|---|---|---|
| Direct injection | 1 | 1 | Retrieval authorization partition |
| Indirect injection | 1 | 1 | Corpus admission content scanning |
| Stored injection | 1 | 1 | Corpus admission content scanning |
| Obfuscated injection | 1 | 1 | Normalization before scanning |
| Multilingual injection | 1 | 1 | Deterministic authorization policy |
| Encoded injection | 1 | 1 | Data-only context rendering |
| Exfiltration | 3 | 3 | Output validation, request shape, citation authenticity |
| Poisoning | 2 | 2 | Lifecycle checks, checksum binding |
| Tool abuse | 2 | 2 | Static registry, argument schema |
| Identity abuse | 2 | 2 | Deterministic authorization policy |
| Action mutation | 2 | 2 | Approval digest binding, display binding |
| Action replay | 1 | 1 | Idempotent execution identity |
| Output injection | 1 | 1 | Inert rendering |
| Consumption | 2 | 2 | Step, tool-call, and output budgets |

Every case names the control expected to stop it. That attribution is what makes the report
reviewable: a case contained somewhere other than where the design says means the design is wrong
even though the result is green.

Class coverage is asserted by a test, so deleting a class fails the build rather than quietly
shrinking the campaign.

### A vacuous case, found and fixed

The encoded-injection case initially passed because the base64 payload matched nothing in the
corpus — the assertion was true for the wrong reason. It now runs the full agent with a model that
tries to act on the payload and asserts that no write occurred and that any context the model saw was
wrapped as data. The multilingual case was likewise strengthened: it originally tripped argument
validation, and now supplies schema-valid arguments for an unassigned patient so containment must
come from the authorization policy.

## The release evaluation

`evidence/reports/M09-release-evaluation.json` declares all 11 dimensions `REQ-SDL-003` requires.

| Status | Dimensions |
|---|---|
| Assessed | function, authorization, security, grounding |
| Partial | privacy, safety, robustness |
| **Not assessed** | accessibility, performance, cost, recovery |

Statuses are declared, not inferred. Deriving "assessed" from the presence of tests would let a thin
suite claim a dimension, which is the failure this manifest exists to prevent.

The manifest separates **blocking gaps** from **unassessed dimensions**, and `release_ready` requires
both to be empty. There are no blocking gaps and the release is still not ready — a single readiness
boolean would have hidden exactly that.

## Open high-severity findings

| ID | Finding |
|---|---|
| `RT-F1` | The campaign runs against a deterministic adapter, not a language model |
| `RE-F1` | Accessibility unassessed — no interface, no assistive-technology session (`BLK-003`) |
| `RE-F4` | Recovery unassessed — six exercises specified, none executed (`NS-EXC-004`) |
| `RE-F5` | Privacy and safety partial — no DPIA re-review against a real data flow, no clinician-reviewed suite |

`RT-F3` records that the attacks were authored by the implementer and therefore encode the same
assumptions as the controls. Independent authorship is required before any release claim.

## Verification

```text
make red-team
make verify
```

Result on Python 3.13.11:

- Adversarial campaign: 21 cases, 100% contained, 14/14 classes, deterministic across runs
- Release evaluation: no blocking gaps; `release_ready` false; four dimensions unassessed
- Governance traceability, retrieval evaluation, supply-chain policy, dataset integrity: pass
- Strict mypy: pass across 90 source/test files
- Pytest: pass, 436 default-suite tests; 1 Docker-gated integration skipped by design
- Coverage: 87.06%; required floor 85%

7 tests are new in this increment.

## What is not established

- **Injection resistance of a real language model.** The adapter is deterministic; `BLK-004` and
  `REQ-AI-002` keep a hosted provider unconnected.
- **Independent adversarial authorship.** Same author as the controls (`RT-F3`).
- Fuzzing, load-driven fault injection, denial-of-wallet, or any performance or cost measurement.
- Accessibility conformance or human comprehension (`BLK-003`).
- Executed recovery exercises (`NS-EXC-004`).
- Residual-risk acceptance. None is recorded, because there is no real accountable person and a
  simulated signature on a release decision would be the most misleading artifact here.

## Next safe increment

M10 operations and incident readiness: telemetry content rules, detection-as-code for the events this
campaign proves are detectable, runbooks, an AI incident tabletop, and the kill, rollback, and
degraded-mode exercises that `RE-F4` needs before recovery can move off "not assessed".

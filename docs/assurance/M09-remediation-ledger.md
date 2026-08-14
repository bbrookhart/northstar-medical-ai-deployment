# NS-ASR-006 — Assurance Remediation Ledger

**Status:** Open  
**Updated:** 2026-08-14  
**Scope:** Findings from the M09 adversarial campaign and release evaluation  
**Rule:** A finding closes when a test or recorded exercise proves it closed, not when someone
believes it is fixed

## Findings from the adversarial campaign

The campaign contained all 21 cases across all 14 required classes, so there is no exploitable
finding to remediate. That is a narrower statement than "the system is secure", and the honest
findings are about what the campaign could not reach.

| ID | Finding | Severity | Disposition |
|---|---|---|---|
| RT-F1 | The campaign runs against a deterministic adapter, not a language model. Injection resistance of a real model is untested | High | Open; blocked by `BLK-004`/`REQ-AI-002`. Rerun the campaign against a hosted provider before any pilot |
| RT-F2 | English-pattern content scanning misses multilingual and encoded instructions. `RT-MUL-001` and `RT-ENC-001` are contained architecturally — retrieved text is data — not by detection | Medium | Accepted by design (`ADR-010`, `LIM-012`). The architectural control is primary; detection is a second layer that must not be relied on |
| RT-F3 | Attack cases are authored by the implementer, so they encode the same assumptions as the controls | Medium | Open; independent red-team authorship is required before a release claim |
| RT-F4 | No fuzzing, load-driven fault injection, or denial-of-wallet testing | Medium | Open; needs a deployment and a metered provider to be meaningful |

## Findings from the release evaluation

| ID | Finding | Severity | Disposition |
|---|---|---|---|
| RE-F1 | Accessibility is unassessed — no interface and no assistive-technology session | High | Open; `BLK-003`, `NS-ASR-005` |
| RE-F2 | Performance is unassessed — no load testing, objectives, or deployment | Medium | Open; needs M10 operations work |
| RE-F3 | Cost is unassessed — no metered provider exists to bound | Medium | Open; a cost ceiling must exist before a provider is connected (`ADR-011`) |
| RE-F4 | Recovery is unassessed — six exercises specified, none executed | High | Open; `NS-EXC-004`, `docs/operations/persistence-recovery-exercises.md` |
| RE-F5 | Privacy and safety are partial — controls tested, but no DPIA re-review against a real data flow and no clinician-reviewed adversarial suite | High | Open; `BLK-003`, `NS-EXC-001` |

## Closure rule

`RT-F1`, `RE-F1`, `RE-F4`, and `RE-F5` are high severity and open. Under `REQ-SDL-005` a release
must not proceed with an open critical or high blocker, so **no release may proceed**. The M09 gate
records that outcome rather than reclassifying the findings to fit a decision.

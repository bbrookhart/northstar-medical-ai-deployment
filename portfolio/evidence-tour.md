# Evidence Tour — Risk to Gate Decision

A reviewer should be able to pick any risk and follow it to a decision. This tour walks three, and
every identifier resolves to a catalog entry or a file.

## How the chain is enforced

`make governance` fails if any requirement, risk, or scenario is orphaned, if a control cites a
verification or evidence identifier that does not exist, or if a generated report is stale. The chain
below is not a narrative — it is what the validator checks.

## Tour 1 — "The model reads a patient it should not"

| Step | Artifact |
|---|---|
| Risk | `RSK-003` unauthorized access to patient context |
| Requirement | `REQ-IAM-002` contextual deny-by-default authorization |
| Control | `CTL-IAM-002` contextual deny-by-default authorization |
| Implementation | `src/polaris/security/policy.py`, `src/polaris/services/patients.py` |
| Agent boundary | `src/polaris/agent/orchestrator.py` re-derives authorization per tool call |
| Verification | `VER-AGT-002` compromised-model containment |
| Attack | `RT-IDN-001` in the adversarial campaign |
| Evidence | `EVD-M06-001`, `EVD-M09-001` |
| Gate | M06 pass; M09 not met on other grounds |

The interesting step is the agent boundary. The model *asks* for a patient; `PatientService` decides.
The campaign case proves the decision is not influenced by who asked.

## Tour 2 — "A poisoned document reaches the answer"

| Step | Artifact |
|---|---|
| Risk | `RSK-008` retrieval poisoning and ungrounded output |
| Requirement | `REQ-RAG-001` approved, reviewed, versioned sources only |
| Control | `CTL-RAG-001` approved, immutable, untrusted corpus lifecycle |
| Implementation | `src/polaris/services/corpus.py` admission with promotion records |
| Decision | `ADR-010` secure retrieval boundary |
| Verification | `VER-RAG-001` admission and scanning |
| Attacks | `RT-IND-001`, `RT-STO-001`, `RT-POI-001`, `RT-POI-002` |
| Evidence | `EVD-M05-001`, `EVD-M05-002`, `EVD-M09-001` |
| Gate | M05 pass |

Four of eight seeded candidates are refused on every application start — superseded, expired,
unapproved, and instruction-carrying — so the control is exercised in normal operation, not only in
tests.

## Tour 3 — "An approver signs something other than what they saw"

| Step | Artifact |
|---|---|
| Risk | `RSK-009` unauthorized or mutated write action |
| Requirement | `REQ-ACT-002` independent approval of the complete canonical action |
| Control | `CTL-ACT-002` independent approval and cryptographic binding |
| Implementation | `src/polaris/presentation/approval.py`, `src/polaris/security/digest.py` |
| Decision | `ADR-012` trusted presentation boundary |
| Verification | `VER-PRS-002` approval preview bound to its recomputed digest |
| Attacks | `RT-ACM-001`, `RT-ACM-002`, `RT-ACR-001` |
| Evidence | `EVD-M07-001`, `EVD-M09-001` |
| Gate | M07 **not met** — the contract is verified, the human-factors evidence is not |

This tour ends at a failed gate on purpose. The binding is machine-verified and tested; whether a
person under time pressure actually reads the preview is unknown, and `NS-ASR-005` specifies the
study that would answer it.

## Where the chain stops

Six blockers are open — `BLK-001` through `BLK-006` — and five exceptions are live, `NS-EXC-001`
through `NS-EXC-005`. The audit package at `evidence/reports/M11-audit-package.json` indexes every
evidence artifact by digest and carries those blockers and the unmet gates alongside them, read from
the gate record so the two cannot disagree.

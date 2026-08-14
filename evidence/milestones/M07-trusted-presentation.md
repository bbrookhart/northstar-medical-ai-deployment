# M07 Trusted Presentation — Contract Verified, Gate Not Passed

**Evidence ID:** EVD-M07-001  
**Date:** 2026-08-14  
**Scope:** Server-side presentation contract for approvals, answers, and emergency routing  
**Decision:** **The M07 gate does not pass.** The presentation contract is implemented and verified;
the human-factors evidence the gate requires does not exist and is blocked by `BLK-003`

## Why this record says "not passed"

The M07 exit criterion is "human-factors tests show informed approval and safe refusal or degraded
behavior." That is a claim about people, and no session has been run. Marking the milestone complete
because the code is written would be exactly the substitution this program exists to avoid — an
implementation presented as an operating control.

What follows is what *was* verified, stated as a contract rather than as a user outcome.

## Claim supported

### Untrusted text cannot change what it looks like

`render_inert` normalizes, strips ANSI escapes and control characters, removes bidirectional
overrides, defangs executable URI schemes, HTML-escapes, and bounds length. Tests cover script tags,
attribute-breaking quotes, `javascript:`, `data:`, terminal escapes, right-to-left overrides, and NUL
bytes.

`contains_active_content` warns the reviewer separately and deliberately does not fire on ordinary
quotes — a warning that fires on most policy text trains people to ignore it. A test pins that
boundary in both directions.

### The approver reads exactly what the decision binds to

`build_approval_view` derives every displayed field from the proposal's canonical action and
recomputes the digest from that same object. `verify_display_binding` returns false when the patient,
facility, due date, or summary differs from what was displayed — tested for each field. A proposal
whose stored digest no longer matches its action is refused rather than displayed.

`action_digest` now lives in `polaris.security.digest` so the action service and the preview compute
it identically. Two implementations of the same digest is how displayed and signed content diverge.

### States cannot be mislabelled

`WorkflowState.implies_completion` is true only for `EXECUTED`, checked across every state. Each state
carries a sentence and a severity, and `ActionApprovalView` refuses to construct when the label or
severity disagrees with the state, or when reauthentication is set false. Severity is never the only
carrier of meaning.

### An abstention cannot be dressed as an answer

`AnswerView` requires an `UncertaintyView`; a non-abstained answer with no sources cannot be
constructed, and a conflict must be presented as an abstention. Source excerpts are rendered inert
and flagged, and source references are displayed as text rather than as live links.

### Emergency language routes without assessment

`EmergencyOutcome` has fields for `triggered` and `guidance` and nothing else — a test asserts the
field set, because the prohibition on assessing urgency is enforced by the type. The agent checks
before the model is consulted, so an emergency question never reaches a model: the run refuses with
`EMERGENCY_ROUTED`, returns the fixed guidance, and the scripted model records zero requests.

### The preview is authorized

`GET /v1/actions/proposals/{id}/preview` requires the same approver authorization as the decision
endpoint. A requester without the approver role receives 403; an approver receives the bound view.

## Verification

Command:

```text
make verify
```

Result on Python 3.13.11:

- Governance traceability and generated-report drift: pass
- Retrieval evaluation thresholds and report currency: pass
- Synthetic dataset integrity and safety: pass
- Ruff formatting and lint/security rules: pass
- Strict mypy: pass across 80 source/test files
- Pytest: pass, 417 default-suite tests; 1 Docker-gated integration skipped by design
- Branch-aware coverage: 86.41%; required floor 85%

38 tests are new in this increment.

## What is not established

- **Anything about human comprehension.** `NS-ASR-005` specifies eight tasks with pass criteria and
  an empty results table. Until it carries dates, participant counts, and measurements, no claim of
  informed approval, comprehension, or reduced automation bias may be made. `BLK-003` stays open.
- **WCAG 2.2 AA conformance.** Structural accessibility properties are enforced — text alternatives
  exist, meaning is never carried by severity alone — but conformance requires a rendered interface
  and assistive-technology testing (`REQ-SAF-005`, HF-07).
- **A user interface.** There is none. The roadmap names a React interface; this increment builds the
  server-side contract a UI must honor, deliberately, so that human-factors work informs the design
  rather than auditing it afterwards.
- **Approval workload and anti-fatigue monitoring** (`REQ-ACT-006`, `CTL-ACT-004`). HF-08 is expected
  to fail first and is the primary input to designing that control.
- **Complete emergency detection.** Phrase matching has false positives and negatives. It fails
  toward refusal, but a missed phrase yields an ordinary refusal rather than routing guidance.
- Any pilot, production, real-PHI, clinical, or conformance authorization.

## Next safe increment

M08 secure platform and supply chain, which is fully buildable without human participants:
containers, a CI security suite, SBOM and AIBOM generation, signed artifacts, provenance, and secrets
and IaC patterns. M07 reopens when human-factors sessions can actually be run.

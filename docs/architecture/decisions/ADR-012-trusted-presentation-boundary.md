# ADR-012 — Trusted Presentation and Approval Preview Boundary

**Status:** Accepted for M07 local simulation; the M07 gate does **not** pass  
**Date:** 2026-08-14  
**Owners:** Clinical Safety Lead, Engineering Lead, Accessibility Lead, and AI Security Lead  
**Related:** REQ-APP-002, REQ-ACT-002, REQ-SAF-002/003/004/005, CTL-APP-002, CTL-SAF-001/002,
CTL-ACT-002, ADR-010, ADR-011, BLK-003

## Context

Every control so far protects data and actions. None protects the *reader*. An approver who is shown
a plausible summary and clicks approve has satisfied `REQ-ACT-002` on paper while the system did
whatever the summary hid.

Two failures are specific to this boundary. Retrieved policy text and model output are untrusted
strings that end up on a screen, so they can carry markup, terminal escapes, or bidirectional
overrides that make the rendered text differ from the stored text. And a surface that displays an
action separately from the digest the approval binds to can show one thing while the approver signs
another.

Neither is fixed by a UI framework choice, so both are fixed server-side, in types.

## Decision

### Untrusted text is rendered inert before it leaves the server

`render_inert` normalizes, strips ANSI and control characters, removes bidirectional overrides,
defangs executable URI schemes, HTML-escapes, and bounds length. The contract for every consumer is
that the result is plain text: render as text, never as HTML, markdown, or a terminal sequence. The
escaping is defense in depth for a consumer that ignores the contract, not permission to interpret
the result.

`contains_active_content` is a separate warning flag, not a filter. It deliberately does not fire on
ordinary quotes and apostrophes — a warning that fires on most policy text trains reviewers to ignore
it.

### The preview and the digest come from the same canonical action

`build_approval_view` derives every displayed field from the proposal's `FollowUpAction` and
recomputes `action_digest` from that same object. A stored digest that no longer matches its action
is refused rather than displayed. `verify_display_binding` lets a surface confirm, immediately before
submitting a decision, that what was shown is what will be signed.

`action_digest` moved out of the action service into `polaris.security.digest` so the service and the
preview compute it identically. A preview that derived the digest any other way would be exactly the
divergence this decision prevents.

### States are named, and only one implies completion

`WorkflowState` separates draft from pending approval, and `implies_completion` is true only for
`EXECUTED`. Each state carries a sentence — "Awaiting independent approval — nothing has happened
yet" — and a severity, and the view model refuses to construct if the label or severity disagrees
with the state. Severity is therefore never the only carrier of meaning, which is both an
accessibility requirement and a comprehension one.

### Uncertainty is structural, not decorative

`AnswerView` requires an `UncertaintyView`. A non-abstained answer with no sources cannot be
constructed, and a conflict must be presented as an abstention. A surface cannot drop the
uncertainty and render an abstention as confident guidance, because there is no such value to
render.

### Emergency language routes; it never assesses

`check_emergency_language` returns fixed, pre-approved guidance and a boolean. `EmergencyOutcome`
has no field for severity, triage level, or confidence, so the prohibition in `REQ-SAF-002` is
enforced by the type rather than by discipline. The agent checks before the model is consulted, so an
emergency question never reaches a model at all.

## Consequences and limitations

- **The M07 gate does not pass.** Its criterion is human-factors evidence, and none exists.
  `NS-ASR-005` specifies eight tasks with pass criteria and an empty results table; `BLK-003` stays
  open. Everything above is a presentation *contract*, verified by tests — not evidence that a person
  under time pressure reads it correctly.
- There is no UI. The roadmap names a React interface; this decision deliberately builds the
  server-side contract a UI must honor instead, because the security properties belong there and a
  UI built before the human-factors work would be studied after the fact rather than designed with it.
- Accessibility is enforced structurally — text alternatives exist, meaning is never carried by
  severity alone. That is a design target, not WCAG 2.2 AA conformance, which requires a rendered
  interface and assistive-technology testing (`REQ-SAF-005`, HF-07).
- Emergency phrase matching is a keyword list with false positives and negatives. It fails toward
  refusal, which is the safe direction, but a missed phrase means an ordinary refusal rather than
  routing guidance.
- Approval workload and anti-fatigue monitoring (`REQ-ACT-006`, `CTL-ACT-004`) remain unbuilt. HF-08
  is expected to be the first task to fail and is the primary input to designing that control.
- The preview endpoint requires approver authorization, so it discloses nothing a reader could not
  already approve. It is not a general-purpose proposal reader.

## Rejected alternatives

- **Sanitize in the client:** every client would have to get it right, and the server would have no
  way to know whether one did.
- **Strip suspicious content instead of escaping it:** silently altering a policy excerpt changes the
  record the approver is relying on. Escaping preserves the text and neutralizes the rendering.
- **Show the digest as the primary integrity signal:** approvers do not compare 64-character hashes.
  The binding must be machine-verified before submission, with the digest present for the record.
- **Let a UI compose the approval view from separate fields:** that is exactly how displayed and
  signed content diverge.
- **Grade urgency to decide how to route:** assessing urgency is prohibited, and a system that
  triages will be trusted to triage.
- **Ship a React UI now and study it later:** human-factors findings would arrive after the design
  was fixed, which is how automation bias gets built in.

## Authoritative sources reviewed

- W3C, *Web Content Accessibility Guidelines (WCAG) 2.2*: https://www.w3.org/TR/WCAG22/
- OWASP, *Cross Site Scripting Prevention Cheat Sheet*:
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- Unicode Technical Report #36, *Unicode Security Considerations*:
  https://www.unicode.org/reports/tr36/
- NIST AI 600-1, *Generative AI Profile* (human-AI configuration):
  https://doi.org/10.6028/NIST.AI.600-1
- FDA, *Applying Human Factors and Usability Engineering to Medical Devices*:
  https://www.fda.gov/media/80481/download

Sources were reviewed on 2026-08-14. They inform the design; they do not certify this implementation,
establish accessibility conformance, or substitute for the human-factors validation `BLK-003`
requires.

# NS-ASR-005 — Approval Human-Factors Validation Protocol

**Status:** Specified; **no session has been run**  
**Scope:** The trusted approval preview and the answer presentation contract  
**Owners:** Clinical Safety Lead (protocol), UX Research (execution), AI Security Lead (findings),
Accessibility Lead (conformance)  
**Related:** REQ-SAF-003, REQ-SAF-004, REQ-SAF-005, REQ-ACT-002, REQ-ACT-006, CTL-SAF-002,
CTL-APP-002, CTL-ACT-004, BLK-003

## Why this document exists rather than a result

The M07 gate is "human-factors tests show informed approval and safe refusal or degraded behavior."
That is not an engineering property. No amount of code review establishes that a care coordinator,
under time pressure, on their third hour of a shift, correctly understands what they are approving.
Writing the protocol and leaving the results empty is the honest state; `BLK-003` records it as a
pilot blocker.

The presentation contract this protocol tests **is** implemented and verified (`EVD-M07-001`). What
is missing is evidence that real people read it correctly.

## Participants

- 8–12 care coordinators and nurses who represent the actual user population, not proxies from
  engineering or product.
- At least 2 participants who use assistive technology daily (screen reader, magnification, or
  switch access), recruited as participants rather than as an accessibility audit.
- 2 clinical safety reviewers observing, not participating.

No participant may have contributed to the design. A designer explaining the screen invalidates the
session.

## Conditions

Sessions run against synthetic data only. Participants are told the system is a simulation and that
no real patient is affected. Time pressure is simulated with a realistic queue, not artificially
imposed, because artificial urgency measures the instrument rather than the workflow.

## Tasks and pass criteria

Each task states what participants must do *unprompted*. "Prompted" means the facilitator drew
attention to the element; a prompted success is a failure of the design.

### HF-01 — Informed approval

Participants review a valid proposal and decide.

Pass requires that at least 90% of participants, unprompted, correctly state the patient, the
facility, the due date, the destination queue, and that the action is administrative rather than
clinical, before approving.

### HF-02 — Detecting a substituted action

Participants review a proposal whose displayed summary is plausible but whose patient differs from
the one in the preceding conversation.

Pass requires that at least 90% notice the mismatch and decline or escalate. This is the automation
bias case: the failure mode is approving because the system presented it.

### HF-03 — Abstention is not an answer

Participants are shown an abstention and a conflict result.

Pass requires 100% correctly report that the system did not answer, and none paraphrase the
abstention as guidance. An abstention read as an answer is a safety failure, so this admits no
partial credit.

### HF-04 — State comprehension

Participants are shown proposals in pending, approved, rejected, expired, and executed states.

Pass requires at least 95% correctly identify whether the task has actually been created. No
participant may believe an unexecuted proposal has taken effect.

### HF-05 — Emergency routing

Participants submit a request containing emergency language.

Pass requires 100% report that the system refused and directed them to established channels, and
that no participant believes the system assessed how serious the situation was.

### HF-06 — Untrusted content

Participants review a proposal whose summary contains markup, an executable-scheme string, and
bidirectional control characters.

Pass requires that nothing renders as active content, that the warning is noticed by at least 80%,
and that no participant reports seeing text that differs from the stored value.

### HF-07 — Accessibility

Participants using assistive technology complete HF-01 and HF-04.

Pass requires task completion without facilitator assistance, correct announcement of state and
severity through the text alternative rather than color, and a WCAG 2.2 AA automated scan with no
serious or critical violations. Automated scanning alone is not a pass.

### HF-08 — Approval workload

Participants process a queue of 20 proposals, three of which are subtly wrong.

Pass requires at least two of the three wrong proposals to be caught by at least 80% of
participants, and the observed approval rate to fall below the anti-fatigue threshold
`CTL-ACT-004` will define. This task is expected to fail first and is the primary input to that
control's design.

## Analysis and thresholds

Report by task, by participant group, and by assistive-technology use. Do not aggregate into a
single usability score — a design that passes seven tasks and fails HF-03 is not 87% safe.

Any HF-03 or HF-05 failure is a critical finding and blocks the gate outright. Two or more failures
elsewhere block until remediated and retested with fresh participants.

## Results

| Task | Date | Participants | Result | Findings |
|---|---|---|---|---|
| HF-01 informed approval | — | — | Not assessed | — |
| HF-02 substituted action | — | — | Not assessed | — |
| HF-03 abstention comprehension | — | — | Not assessed | — |
| HF-04 state comprehension | — | — | Not assessed | — |
| HF-05 emergency routing | — | — | Not assessed | — |
| HF-06 untrusted content | — | — | Not assessed | — |
| HF-07 accessibility | — | — | Not assessed | — |
| HF-08 approval workload | — | — | Not assessed | — |

An empty results table is the point of this document. Until it carries dates, participant counts,
and measurements, `BLK-003` stays open, the M07 gate does not pass, and no claim of informed
approval, comprehension, or accessibility conformance may be made.

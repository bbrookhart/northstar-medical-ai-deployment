# Case Study — Project Polaris

**Securing an internal agentic AI capability at a healthcare enterprise, end to end.**

*Reading time: about five minutes. Every identifier below resolves to an artifact in this
repository, and a check in CI fails the build if one does not.*

---

## The problem

Northstar Medical wants an internal assistant that answers approved policy questions and drafts
administrative follow-up tasks for care coordinators.

Building that takes an afternoon. The work is everything else: deciding what it may never do,
enforcing those decisions where they cannot be argued away, and leaving evidence that an auditor can
follow a year later without talking to the person who built it.

**Constraints set at intake, before any code:**

| Constraint | Consequence |
|---|---|
| Synthetic data only, treated as if restricted | Every control is exercised against realistic labels |
| No diagnosis, prescribing, triage, or patient contact | The clinical boundary is enforced, not documented |
| No autonomous writes | Every action requires independent human approval |
| The model is untrusted | It can never be an authorization boundary |

---

## The decision that shaped everything

*The model is never an authorization boundary.*

Stated that way it is a platitude. The work was making it a property of the code rather than a rule
someone has to remember.

**`ModelRequest` has no field for a credential, principal, token, or session.** Not "we don't
populate it" — the field does not exist. So the requirement that credentials never reach model
context holds by construction. A refactor cannot quietly break it, because there is nothing to break.

Every tool call re-derives authorization from the **calling principal**, through the same services
the HTTP API uses. The model choosing a patient identifier does not make that patient readable —
`PatientService` and the policy engine decide, and they never see who asked.

To test this, the adversarial campaign scripts hostile intents directly rather than prompting a model
to misbehave. That exercises the boundary instead of the model's willingness to comply
(`VER-SDL-003`).

---

## What was built

<details open>
<summary><b>Identity and continuous access</b></summary>

Strict RS256 access tokens with exact issuer, audience, and type binding; trusted OIDC discovery with
bounded JWKS rotation; RFC 8693 token exchange that reauthenticates the subject and refuses
passthrough; and a durable CAEP/SSF receiver that invalidates sessions on signed revocation and
credential-change events, with replay, ordering, restart, and stale-stream handling.

When the provider documents no event replay, a separately authorized System Log feed is applied
behind compare-and-swap cursor sequencing — and is never mislabelled as replay (`ADR-008`).

</details>

<details open>
<summary><b>Secure retrieval</b></summary>

Corpus admission is deny-by-default and produces a promotion record whether or not a document is
admitted, so "why is this source not indexed" is an auditable question. Approval requires a second
person: a corpus places text in front of every user, so it gets the same separation of duties as an
executable action.

Authorization is computed **before** anything is scored, so an unauthorized chunk is never a
candidate — not filtered from the answer, never in the running. Two current sources that disagree
produce an abstention with both cited, because resolving a policy conflict by relevance score is a
governance decision made by a keyword (`ADR-010`).

</details>

<details open>
<summary><b>The agent boundary</b></summary>

An explicit state machine with an enumerated transition table. Three tools — two read, one write,
**none that execute**. Registry construction refuses any tool whose name contains a prohibited
capability, so "no shell, no browser, no filesystem" fails a test rather than a code review.

Output is validated for grounding, citation authenticity, secret disclosure, and clinical scope, and
refused rather than truncated. Steps, tool calls, writes, output size, and wall clock are bounded.
MODEL, READ, and WRITE kill switches are independent and durable — disabling writes leaves reads
working, and a restart cannot silently re-enable what an operator killed.

The hosted-provider adapter implements the interface and refuses every call, because an adapter that
always refuses cannot be misconfigured into working (`ADR-011`).

</details>

<details open>
<summary><b>Approval integrity</b></summary>

The approval preview and the digest it displays both derive from the same canonical action, so a
surface cannot show one action while the approver signs another. Untrusted text is rendered inert
server-side — escaped, control characters and bidirectional overrides stripped, executable URI
schemes defanged.

Only an executed action reports as complete; a pending proposal cannot look like a finished task
(`ADR-012`).

</details>

<details open>
<summary><b>Supply chain, assurance, and operations</b></summary>

An offline release gate blocks unpinned actions, unpinned image digests, unbounded dependencies,
missing container hardening, and tracked secrets — each proven by a test that breaks it. A CycloneDX
SBOM covers dependencies; a generated **AIBOM** covers what a dependency list cannot: model identity,
serving corpus and its refusals, tool surface, bounds, kill switches, and evaluation thresholds.

Twenty-one attacks across fourteen classes each name the control expected to stop them. Detection is
code over the tamper-evident audit stream. Five drills execute rather than describe — including one
that backs up the database, corrupts it, restores, and verifies the audit chain.

</details>

---

## Four bugs found by running, not reading

This is the part worth reading closely, because it separates a system that was built from one that
was described.

**A scanner that rejected the safety policy.** Corpus content scanning refused the policy stating
Polaris *must not* diagnose or prescribe — for containing the words it prohibits. The
clinical-boundary control was keeping the clinical-boundary policy out of the corpus. The check now
runs per sentence and admits prohibitive sentences (`ADR-010`).

**A drill that asserted the wrong half of a control.** The kill-switch game day failed on its first
run. With writes disabled the tool is not advertised at all, so a well-behaved model never asks and
never produces a refusal — asserting only on the refusal mis-modelled the control. It now checks both
halves (`EVD-M10-001`).

**A red-team case that passed for the wrong reason.** The encoded-injection case passed because the
base64 payload matched nothing in the corpus. It now runs the full agent with a model that tries to
act on the payload, and asserts no write occurred (`EVD-M09-001`).

**A container that built and then failed to start.** The virtual environment was created at the
builder path and copied elsewhere, so its absolute interpreter shebangs failed at runtime with a
misleading error. Reading the Dockerfile would not have caught it (`EVD-M08-001`).

---

## How the evidence holds together

Seven checks run in CI, and each one fails the build:

```bash
make verify
```

Governance traceability, with every requirement, risk, and scenario resolving to a control · the
retrieval golden set · the release supply-chain policy · the adversarial campaign across all fourteen
attack classes · five operational drills · the audit package and retirement exercise · lint, strict
typing, 482 tests, and an 85% coverage floor.

Generated evidence is committed and drift-checked, so changing a bound, a tool, or a threshold shows
up as a diff in a reviewed artifact rather than silently.

The chain is walkable in both directions: pick any risk and follow it to a control, an
implementation, a test, and a decision — or pick any line of code and find the risk it exists to
treat. The [evidence tour](evidence-tour.md) walks three of them.

---

## What an engineer should take from this

The security work that mattered was rarely clever. It was choosing the boundary that makes a class of
mistake impossible, then making the boundary a type rather than a convention.

The rest was refusing to overstate. Every limitation is recorded against the control it affects: the
retrieval baseline is deterministic keyword matching, the model adapter is a fixed policy rather than
a language model, treatment relationship and Consent are fixtures, and no signal client has contacted
a live provider. Knowing which problems code cannot close — and saying so plainly next to the ones it
did — is most of the job.

---

## Scope

An educational simulation on synthetic data. Not a production healthcare system, legal advice, a
HIPAA compliance determination, an FDA clearance, or evidence that any real organization is
compliant. No real patient data is used anywhere.

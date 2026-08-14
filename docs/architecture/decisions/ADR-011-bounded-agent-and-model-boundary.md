# ADR-011 — Bounded Agent Loop and Untrusted Model Boundary

**Status:** Accepted for M06 local simulation; no hosted provider is authorized  
**Date:** 2026-08-14  
**Owners:** AI Security Lead, Engineering Lead, and Clinical Safety Lead  
**Related:** REQ-AI-001 through REQ-AI-008, REQ-ACT-001/002, CTL-AI-001/002/003/004,
RSK-001/002/011/015/017/018, ADR-001, ADR-002, ADR-010, BLK-004

## Context

Every control before this one assumed no model was present. M06 introduces one, and the doctrine
that has governed the whole program — *the model is an untrusted component, never an authorization
or policy-enforcement boundary* — has to become executable rather than aspirational.

The M06 gate states the test plainly: treat the model as fully compromised and demonstrate that it
cannot broaden retrieval, obtain a credential, bypass policy or approval, execute a prohibited
action, or exceed a resource bound. A design that satisfies that gate cannot rely on the model
behaving, on prompt wording, or on the model declining to misbehave.

## Decision

### The model produces requests, not decisions

`ModelIntent` is a request in every case: answer, call a tool, or abstain. The orchestrator may
refuse any of them. Nothing the model returns is treated as an authorization, an identity, or an
instruction to the system. A compromised model can waste a run; it cannot widen one.

### The model receives only what it needs

`ModelRequest` carries a system contract, the question, rendered data-only context, the names of
currently available tools, and the remaining step count. It has no field for a credential, a
principal, a token, a session, or anything from a previous run — so `REQ-AI-001`'s "credentials never
in model context" is a property of the type, not a convention someone must remember.

### Authorization is re-derived per call, from the principal

Every tool invocation runs through the same deterministic services the HTTP API uses:
`SecureRetrievalIndex.search`, `PatientService.authorized_summary`, `ActionService.propose`. Each
re-derives authorization from the *calling principal*, never from model output. The model choosing a
patient identifier does not make that patient readable; the index and the policy engine decide.

### Tools are a release-time decision

`ToolRegistry` has no registration API. Three tools exist — two read, one write — and their names,
versions, schemas, and operations are code reviewed with everything else. Registry construction
refuses any tool whose name contains a prohibited capability token (shell, exec, browser, file, sql,
email, network, memory, …), so `REQ-AI-006` fails a test rather than a review. Write tools are
invisible in `available()` when the write capability is off.

### The write tool proposes; nothing executes

`action.propose` creates a pending proposal. There is no execute tool, and the approval path is
untouched: independent human approval, digest binding, expiry, and idempotency all still apply. The
model can draft an action; it cannot approve or perform one.

### Bounds are stop conditions

`AgentBudget` caps steps, tool calls, write proposals (at one), context characters, answer
characters, and wall-clock time. Exceeding any bound halts the run — it does not degrade into an
unbounded one, retry, or truncate silently. Cost is deliberately absent because no metered provider
is connected; adding one requires a cost bound here first.

### Output is validated before use

`validate_answer` checks structure, size, grounding, citation authenticity, secret and
context-envelope disclosure, and clinical scope, in that order. A citation the retriever did not
return is refused as fabrication — that single check covers both invention and attempts to reference
material the caller was never authorized to see.

### State is explicit

`_TRANSITIONS` enumerates every legal move. An illegal transition raises rather than taking an
implicit path, and each run's transcript is recorded without model reasoning.

### No cross-session memory

The orchestrator holds no mutable per-conversation attributes. Run state lives in a `_RunContext`
constructed inside `run()` and discarded when it returns, so `REQ-AI-004` holds because there is
nowhere to put memory, not because a flag is off.

### Kill switches are independent and durable

`AgentCapability` splits MODEL, READ, and WRITE. Disabling writes leaves reads working; disabling
the model leaves the deterministic retrieval path clinicians use untouched. State is persisted
(schema 11) and monotonically sequenced, because a kill switch that forgets on restart is not one.

### The hosted provider seam stays inert

`UnapprovedHostedModelAdapter` implements the interface and refuses every call.
`REQ-AI-002` requires approved data-use, no-training, retention, region, subprocessor, security,
change-notice, incident, audit, continuity, and exit criteria, and `BLK-004` records that no provider
due diligence exists. Holding the seam open while refusing to connect is more honest than shipping a
connection nobody approved.

## Consequences and limitations

- `DeterministicModelAdapter` is not a language model. It is a fixed, inspectable policy over the
  supplied context that lets the entire orchestration, authorization, validation, and approval path
  be tested without an API key, and gives a future hosted adapter something to be diffed against.
  **No claim about model behavior, answer quality, or reasoning is made or implied.**
- The compromised-model suite scripts hostile intents directly. That is stronger than prompting a
  real model to misbehave — it exercises the boundary rather than the model's compliance — but it is
  not a substitute for the M09 red-team campaign against a real provider.
- Output validation is pattern-based for secrets and clinical direction and inherits the false
  positive and negative behavior recorded in `ADR-010` and `LIM-012`.
- Budgets are bounded engineering defaults, not measured or approved production limits. There is no
  concurrency, fan-out, retry, or cost control because no provider or queue exists to need one.
- Capabilities default to *enabled* when no record exists, which suits a local simulation with no
  operator. A deployment must invert that default and require explicit enablement.
- The agent is not exposed over HTTP. It is constructed in the service container and exercised by
  tests; adding an endpoint is M07 work and needs the trusted renderer and human-factors evidence
  that `BLK-003` still blocks.

## Rejected alternatives

- **Let the model call services directly with the caller's token:** that makes the model an
  authorization boundary, which the entire program forbids.
- **Trust a system prompt to constrain behavior:** prompts are not controls. Every guarantee here is
  enforced outside the model, and the tests assume the prompt was ignored.
- **Give the model an execute tool with a confirmation step:** confirmation inside the loop is still
  the model deciding. Independent human approval already exists and stays outside the loop.
- **Truncate oversized output instead of refusing:** truncation silently produces a partial answer
  that was never validated as a whole.
- **A single global kill switch:** it forces an operator to disable everything to contain one
  problem, which is why nobody uses it in an incident.
- **Ship a hosted adapter behind a feature flag:** a flag is a configuration mistake away from an
  unapproved data flow. An adapter that always refuses cannot be misconfigured into working.

## Authoritative sources reviewed

- OWASP, *Top 10 for LLM Applications* (LLM01 prompt injection, LLM06 excessive agency, LLM10
  unbounded consumption): https://genai.owasp.org/llm-top-10/
- NIST AI 100-2 E2025, *Adversarial Machine Learning: A Taxonomy and Terminology*:
  https://doi.org/10.6028/NIST.AI.100-2e2025
- NIST AI 600-1, *Generative AI Profile*: https://doi.org/10.6028/NIST.AI.600-1
- MITRE ATLAS, *LLM Prompt Injection* and *LLM Plugin Compromise*: https://atlas.mitre.org/

Sources were reviewed on 2026-08-14. They inform the design; they do not certify this implementation
or establish conformance. Exact OWASP GenAI LLM 2026 category mapping remains `BLK-006`.

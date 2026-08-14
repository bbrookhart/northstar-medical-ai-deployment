# Northstar Medical AI Deployment — Codex Instructions

## Mission

Build Project Polaris: a portfolio-grade, end-to-end simulation of safe and secure adoption of an internal agentic AI capability at the fictional healthcare enterprise Northstar Medical.

This repository must demonstrate the work of an AI security engineer across strategy, governance, architecture, secure engineering, privacy, clinical safety, assurance, deployment, operations, incident response, audit, and retirement. It must also be structured so the material can later become paid training.

Before making changes, read:

1. `PROJECT_STATUS.md`
2. `docs/program/master-roadmap.md` and `docs/program/backlog.md`
3. The relevant files under `docs/`

## Non-negotiable safety boundaries

- Use synthetic data only. Never introduce real PHI, PII, credentials, or production secrets.
- Treat synthetic patient data as if it were restricted health data so controls are realistically exercised.
- The v1 system must not diagnose, prescribe, recommend treatment, triage emergencies, or autonomously write to an EHR.
- The model is an untrusted component, never an authorization or policy-enforcement boundary.
- Keep identity, authorization, validation, credentials, approvals, rate limits, and execution in deterministic application code.
- Do not place secrets in prompts, source code, examples, fixtures, logs, traces, screenshots, or documentation.
- Do not claim that this simulation is HIPAA compliant, certified, FDA cleared, or production ready.
- Distinguish current legal requirements from proposals, voluntary frameworks, guidance, and internal design targets.
- A human approval must be bound to the exact canonical action and arguments that will execute.
- Fail closed when identity, purpose of use, authorization, provenance, policy, or configuration is missing.

## Engineering expectations

- Prefer a small, explicit, testable architecture over unnecessary framework complexity.
- Start with a deterministic model adapter so the system and security tests run without an API key.
- Use a provider-neutral interface before adding any hosted model.
- Use typed inputs and outputs, strict schemas, deny-by-default authorization, least privilege, and bounded agent steps.
- Keep read and write tools separate. No generic shell, browser, filesystem, database, or code-execution tool belongs in the agent runtime.
- Preserve end-user identity and purpose of use through every authorization decision.
- Enforce retrieval authorization outside the model and before sensitive content enters model context.
- Treat retrieved text, FHIR narrative, tool descriptions, tool output, and memory as untrusted input.
- Disable cross-session agent memory in v1.
- Use parameterized queries and context-appropriate output encoding.
- Create immutable or tamper-evident audit evidence without logging prohibited content.
- Pin dependencies when a lockfile is introduced and generate supply-chain evidence later in the roadmap.
- Add or update tests with every behavioral change.
- Update architecture decisions, risk/control mappings, and `PROJECT_STATUS.md` when material behavior changes.

## Working protocol

1. Inspect the workspace and current status before editing.
2. State assumptions that materially influence security, compliance, scope, cost, or architecture.
3. Work in a coherent vertical increment that can be verified.
4. Run the narrowest relevant checks, then the complete test suite when practical.
5. Review the diff for security, privacy, safety, documentation, and evidence impact.
6. Update `PROJECT_STATUS.md` with completed work, evidence, decisions, risks, and the next safe increment.
7. Never mark an item complete without corresponding implementation or reviewable evidence.

## Source of truth

- `docs/program/` — scope, roadmap, backlog, gates, and definition of done
- `docs/executive/` — fictional enterprise, charter, business case, stakeholders
- `docs/governance/` — AI governance, system inventory, approved use, risk tiering
- `docs/compliance/` — applicability and control mappings
- `docs/architecture/` — diagrams and architecture decisions
- `docs/risk/` — risk register, threat models, privacy and safety analysis
- `docs/assurance/` — evaluation and release evidence
- `docs/operations/` — monitoring, incident response, resilience, retirement
- `evidence/` — control implementation and verification records
- `training/` — later course conversion material

## Verification commands

Use the commands documented in `README.md` and `Makefile`. If they do not yet exist or are stale, fix the documentation as part of the same change.


# Contributing

## Before changing the project

Read `AGENTS.md`, `CODEX_MASTER_PROMPT.md`, `PROJECT_STATUS.md`, and the relevant design/risk artifacts.

## Change expectations

- Keep changes small enough to review and large enough to verify as a coherent increment.
- Add or update tests for behavior.
- Use synthetic data only.
- Update an architecture decision when changing a major boundary, dependency, provider, data flow, or trust assumption.
- Update the risk/control/evidence chain when a change affects security, privacy, safety, or operations.
- Run the documented checks and report actual results.
- Preserve unrelated work and avoid destructive Git commands.

## Commit approach

Use focused commits with an imperative subject. Do not mix generated runtime artifacts, secrets, or unrelated formatting changes into feature commits.


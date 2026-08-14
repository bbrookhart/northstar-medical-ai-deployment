# Security Policy

## Scope

This repository is an educational healthcare AI security simulation and must use synthetic data only.

## Reporting

Do not open a public issue containing exploit details, credentials, sensitive local paths, or data. For the current private-development phase, record a sanitized finding under `docs/risk/` and mark sensitive reproduction details for private handling.

## Repository rules

- Never commit real PHI, PII, tokens, API keys, passwords, certificates, private keys, or production configuration.
- Test credentials must be obviously synthetic and scoped to local tests.
- Do not claim production security, regulatory compliance, certification, or clinical fitness.
- Security controls require tests or other reviewable evidence.
- Critical and high findings block the simulated release unless explicitly accepted with rationale, owner, expiry, and compensating controls.

## Supported versions

No release has been published. Only the current default branch is maintained during initial development.


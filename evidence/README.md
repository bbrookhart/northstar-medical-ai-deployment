# Evidence Registry

Evidence proves that a defined control operated for a defined scope and time. It does not prove
blanket compliance or production readiness.

Store concise, public-safe evidence here. Never store real PHI, PII, secrets, private tokens,
unnecessary prompts, hidden reasoning, raw production logs, or unredacted scanner output.

Each milestone record should include:

- Evidence ID, date, owner, scope, and implementation revision
- Control or gate criteria evaluated
- Exact reproducible commands or review method
- Result and important measurements
- Findings, limitations, exceptions, and residual risk
- Reviewer and decision state when review occurs

## Machine-readable assurance

The canonical catalogs are in `governance/`. Run `make governance-report` after an intentional
catalog change, review the diff, and run `make governance` (or `make verify`) to reject missing IDs,
orphan requirements/risks/scenarios, unresolved implementation/test/evidence/framework references,
and stale generated reports.

The current reports are:

- `evidence/reports/M03-traceability-report.json` — canonical machine-readable coverage;
- `evidence/reports/M03-traceability-report.md` — human review view.

Generated coverage proves traceability integrity only. It does not turn planned evidence into
operating evidence or authorize a release.

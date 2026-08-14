# EVD-M03-002 — M02/M03 Assurance Baseline Local Verification

**Executed:** 2026-08-11  
**Environment:** macOS; CPython 3.13.11 managed by uv 0.11.18  
**Branch:** `codex/main`; pre-initial-commit working-tree baseline  
**Scope:** M02/M03 documents, catalogs, validator, generated reports, backend regression suite  
**Decision:** Pass locally for synthetic simulation

## Commands and results

```text
make governance-report
Result: typed validation passed; deterministic JSON and Markdown reports generated

make verify
Result: report freshness passed; 70 files formatted; Ruff passed; strict mypy passed across
26 source files; 34 tests passed; 89.13% total coverage; configured floor 85%
```

## Assurance invariants exercised

- All 70 requirements resolve to one accountability family and at least one control.
- All 25 registered risks have treatment controls; no critical/high inherent risk is orphaned.
- All 30 THR, 10 PRI, 24 MIS, and 14 HAZ scenarios map to registered risks.
- Control requirement/risk/verification/evidence/framework IDs resolve and duplicate IDs fail.
- Current implementation, verified test, review-artifact, and existing-evidence paths resolve within
  the repository; unsafe/missing paths fail.
- `implemented` controls have verified checks and existing evidence; `planned` controls cannot claim
  verified checks or existing/generated evidence.
- Framework references resolve through dated reviewed/provisional authoritative sources.
- The machine and human reports are deterministic; CI fails if they are missing or stale.
- The original API authorization, retrieval, action-integrity, safety-boundary, and audit tests still
  pass after adding governance automation.

## Review and gate evidence

- `docs/assurance/M02-multidisciplinary-review.md`
- `docs/assurance/M03-control-owner-review.md`
- `evidence/reports/M03-traceability-report.json`
- `evidence/reports/M03-traceability-report.md`

## Limitations

The repository has no initial commit, so this record is not yet bound to an immutable Git revision.
Hosted GitHub Actions and branch protection have not been assessed. Reviewers are simulated roles,
not named enterprise approvers. The result proves local catalog integrity and regression behavior;
it does not prove operating effectiveness for partial/planned controls, residual-risk acceptance,
clinical validation, legal compliance, independent assurance, pilot readiness, or production
authorization. `BLK-001` through `BLK-006` remain open.

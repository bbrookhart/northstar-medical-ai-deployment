# Hosted Continuous Integration — First Execution

**Evidence ID:** EVD-M04-002  
**Date:** 2026-08-13  
**Scope:** Hosted GitHub Actions execution of the repository quality gate  
**Decision:** `LIM-006` closed for hosted execution; branch protection remains not assessed

## Claim supported

Until this record, the repository existed only as an untracked local working tree. No commit, no
remote, and therefore no hosted verification existed. `LIM-006` recorded that fact honestly, and
three gate tables carried "Hosted CI result — Not assessed".

The working tree is now under version control and the committed tree passes the same quality gate on
a clean hosted runner. This proves that the gate is reproducible outside the author's machine — the
program success measure "a clean environment can install from the lockfile and pass the documented
gates" — and nothing more.

## Repository and history

| Attribute | Value |
|---|---|
| Remote | `github.com/bbrookhart/northstar-medical-ai-deployment` (private) |
| Base branch | `main` |
| Working branch | `codex/main` |
| Verified revision | `1e73e8587144eee00b571f405cb5a33f5576fa58` |
| Commits at import | 4, ordered M00 → M01–M03 → M01–M04 implementation → M04 data/evidence |

The tree was developed before it was tracked, so the import commits are grouped for reviewability
rather than reconstructed as an authentic development history. Only the branch tip is guaranteed to
pass the gate; intermediate import commits are not independently green and must not be cited as
evidence of an incremental gated delivery.

Repository visibility is private. `DEC-001` records that licensing and IP terms for the repository
and training content are undecided, so public release remains blocked on that decision.

## Content-safety check before the first commit

`.gitignore` excludes `.venv/`, `.uv-cache/`, `.coverage`, `.env`, `*.pem`, `*.key`, `*.p12`, local
databases, and `artifacts/runtime/`. A dry-run of the initial `git add` was reviewed file-by-file
before any commit: 138 files, containing no populated `.env`, no key material, no local database,
and none of the generated Synthea runtime output.

A repository-wide scan for private-key headers and provider credential prefixes returned one match,
`src/polaris/data/synthetic.py`, which is the credential-marker denylist the synthetic-data safety
check uses to reject key material in the dataset. It is a control, not a secret.

## Hosted result

Workflow: `.github/workflows/ci.yml`, job `quality`, `ubuntu-latest`, pinned `actions/checkout` v7.0.1
and `astral-sh/setup-uv` v9.0.0, uv 0.11.18, Python 3.13.11, `persist-credentials: false`,
`contents: read`.

| Step | Result |
|---|---|
| Install locked dependencies (`uv sync --locked --all-groups`) | Pass |
| Validate governance traceability and evidence report | Pass |
| Verify formatting (`ruff format --check`) | Pass |
| Lint (`ruff check`) | Pass |
| Type check (`mypy src tests`) | Pass |
| Run tests and enforce coverage | Pass |

Run `31761227261` on `main` and run `31761226863` on `codex/main` both concluded **success** at
revision `1e73e858`, in 34s and 31s respectively. The lockfile resolved under `--locked` on a clean
runner, so the pinned dependency set is complete and reproducible.

## Known divergence between local and hosted gates

`make verify` runs `governance`, `synthetic-data-verify`, `lint`, `type`, and `test-cov`. The hosted
workflow runs every step except `synthetic-data-verify`. The dataset integrity and safety check
therefore has local evidence only (`EVD-M04-001`) and is not enforced on every push. This is a
recorded divergence, not a silent one; closing it is tracked as remaining M04 work.

## Not established by this record

- **Branch protection.** `main` is unprotected. The GitHub API rejected the protection request with
  "Upgrade to GitHub Pro or make this repository public to enable this feature." Required status
  checks, force-push prevention, and review enforcement are therefore **not assessed**, and this
  record must not be cited as change-control evidence.
- Repository publication, licensing, or third-party attribution review (`DEC-001`).
- Any secret-scanning, dependency-review, SBOM, artifact-signing, or provenance control. Those are
  M08 supply-chain scope; only the quality gate runs today.
- Supply-chain integrity of the runner itself beyond the pinned action SHAs and pinned uv/Python.
- Anything about the *content* of the gate. A passing hosted run means the same 310 tests and the
  same 85% coverage floor passed on a clean machine. It is not release evidence, control-operation
  evidence, or authorization for a pilot, production, real-PHI, or compliance claim.

## Reproduction

```text
gh run list --workflow=CI
gh run view 31761227261 --json conclusion,headSha
```

Locally equivalent:

```text
uv sync --locked --all-groups
make verify
```

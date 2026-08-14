# EVD-M01-001 — First Secure Vertical Slice Local Verification

**Executed:** 2026-08-11  
**Environment:** macOS; CPython 3.13.11 managed by uv 0.11.18  
**Scope:** Project Polaris backend, deterministic policy/retrieval/action services, tests  
**Decision:** Pass locally

## Commands and results

```text
.venv/bin/ruff format --check .
Result: all files formatted

.venv/bin/ruff check .
Result: all checks passed

.venv/bin/mypy src tests
Result: success; no issues in 23 source files

.venv/bin/pytest --cov=polaris --cov-report=term-missing
Result: 30 passed; total coverage 90.52%; configured floor 85%
```

## Security invariants exercised

- Missing, expired, and malformed identity/purpose inputs fail closed.
- Cross-patient, cross-facility, wrong-purpose, and Part 2-sensitive access is denied.
- Policy retrieval uses approved/versioned sources, normalizes invisible characters, cites, and
  abstains when no meaningful source matches.
- Clinical content cannot enter the administrative write path.
- The requester cannot approve their own action.
- Approval is bound to a SHA-256 digest and separate HMAC-signed receipt.
- Changed digests, expired proposals, tampered receipts, wrong roles, and unapproved execution fail.
- Successful execution is idempotent and audit events form a verifiable HMAC hash chain.

## Limitations

This milestone uses local HS256 tokens, in-memory stores, seeded synthetic records, deterministic
retrieval, and an in-memory audit chain. It has not yet been exercised in hosted CI, integrated with
OIDC/FHIR/OPA/a model provider, independently reviewed, load tested, or authorized for production.

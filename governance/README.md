# Machine-Readable Governance

This directory is the canonical M03 assurance data layer:

- `control-library.json` — 31 owned controls with status, requirements, risks, implementation,
  verification, evidence, and framework mappings;
- `traceability.json` — source inventories, requirement accountability, 78 scenario-to-risk links,
  and open gate blockers;
- `verification-catalog.json` — verified and planned test/review/exercise definitions;
- `evidence-catalog.json` — existing, generated, and planned evidence with bounded claims; and
- `framework-registry.json` — authoritative sources plus reviewed/provisional references.

Edit canonical source documents and catalogs intentionally, then run:

```bash
make governance-report
make verify
```

The first command validates and regenerates deterministic reports. The second rejects stale output,
invalid IDs, unsafe/missing paths, orphan requirements/risks/scenarios, unresolved references, false
implemented/planned status relationships, and missing verified tests/evidence.

JSON is used deliberately so the standard library and existing Pydantic dependency can provide a
strict, portable CI gate without a separate schema toolchain. Human-readable policy and review
artifacts remain under `docs/`; generated assurance remains under `evidence/reports/`.

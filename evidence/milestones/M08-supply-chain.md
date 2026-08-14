# M08 Secure Platform and Supply Chain — Local Verification

**Evidence ID:** EVD-M08-001  
**Date:** 2026-08-14  
**Scope:** Repository release policy, generated bills of materials, and a locally built container  
**Decision:** **Conditional pass** — the offline release policy is enforced and the container is
built and verified; signing, provenance, and vulnerability scanning are deferred under `NS-EXC-005`

## Claim supported

### The release policy is a gate, not a document

`evaluate_release_policy` fails a release on any of: a GitHub Action not pinned to a 40-character
commit SHA, a container image not pinned to a sha256 digest, a declared dependency without a version
bound, a locked package without a hashed artifact, a missing container or compose hardening control,
or a secret marker in a tracked file.

Each check is proven by a test that breaks it. Substituting `actions/checkout@v4`, an unpinned
`python:3.13-slim` image, `read_only: false`, an unbounded `fastapi` requirement, or a file
containing an AWS key-id marker each produces a blocker in a copied repository.

The gate is deterministic and offline by design. Vulnerability scanning needs a live advisory feed,
and a gate that fails when an external service is unavailable teaches people to bypass it.

### The secret scan exempts only detector modules

Four modules necessarily contain the markers they search for. Nothing else is exempt: the test that
needs an AWS key-id marker builds it from parts so the scan stays honest rather than growing an
exclusion list.

### Bills of materials are generated from the running definitions

`evidence/reports/M08-sbom.cdx.json` is CycloneDX 1.6 built from `uv.lock` — 41 packages, each with a
PURL and every artifact hash the lock pins, direct dependencies distinguished from transitive ones.
It is built from the lockfile rather than an installed environment, and it is byte-stable across
runs.

`evidence/reports/M08-aibom.json` records what a dependency SBOM cannot: the model adapter identity
and system-contract digest, the serving corpus version and manifest checksum together with the four
refused candidates and their reasons, the confidential partition, the three-tool inventory with
argument-schema digests, the agent bounds including `cross_session_memory: false` and null cost and
concurrency controls, the three kill-switch capabilities, and the evaluation thresholds. It also
records what is absent — no hosted provider, no embedding model, no training data.

Both are committed and drift-checked by `make verify` and CI, so changing a bound, a tool, or the
corpus appears as a diff in a reviewed artifact.

### The container was built and exercised, not just written

`infrastructure/container/Dockerfile` pins both base stages by digest and installs uv from its own
pinned image rather than a curl-to-shell installer. The runtime stage removes pip and the apt
binaries while keeping the dpkg database so scanners can still enumerate contents.

Observed from the built image:

| Property | Result |
|---|---|
| Runs as | uid 65532, non-root |
| Root filesystem | read-only; a write to `/app` fails |
| `uv`, `pip`, `gcc`, `apt`, `apt-get`, `curl` | absent |
| dpkg database for scanners | present |
| `/health/live` and `/health/ready` | 200 under `--read-only --cap-drop ALL --security-opt no-new-privileges` |

Building the image also found a real defect: the virtual environment was created at the builder path
and copied elsewhere, so its absolute interpreter shebangs failed at run time with a misleading "no
such file or directory". It is now built at the path it runs from. Reading the Dockerfile would not
have caught that.

## Verification

Commands:

```text
make supply-chain
make verify
make container-build
```

Result on Python 3.13.11:

- Release supply-chain policy: pass across 4 pinned definitions, 0 blockers
- Generated SBOM and AIBOM: current
- Governance traceability, retrieval evaluation, and dataset integrity: pass
- Ruff formatting and lint/security rules: pass
- Strict mypy: pass across 85 source/test files
- Pytest: pass, 429 default-suite tests; 1 Docker-gated integration skipped by design
- Branch-aware coverage: 86.65%; required floor 85%
- Container build and smoke test: pass locally

12 tests are new in this increment.

## What is not established

- **No artifact signature and no build provenance attestation.** Both need a signing identity and a
  published artifact; this repository publishes nothing. `NS-EXC-005` records the deferral.
- **No vulnerability scanning result** for dependencies or the built image. Dependabot is configured
  and raises weekly updates, but its effectiveness has never been assessed and it does not scan the
  image.
- **Reproducible in the pinning sense only.** Pinned base digests and a locked dependency set mean a
  rebuild resolves the same inputs. Byte-identical layers are not claimed.
- The image has never been built in CI or published anywhere.
- Branch protection remains unassessed (`LIM-006`), so "reviewed source changes" in `REQ-SDL-001`
  holds by convention rather than enforcement.
- The compose stack has no TLS edge, secret manager, or observability sink. It is a hardened local
  runtime, not a deployment.
- Any pilot, production, real-PHI, or conformance authorization.

## Next safe increment

M09 full assurance and red team: functional, safety, privacy, security, robustness, performance, and
recovery evaluations with versioned datasets and thresholds, plus the direct, indirect, stored,
obfuscated, and encoded injection campaign that `REQ-SDL-004` requires and that M06 explicitly
deferred.

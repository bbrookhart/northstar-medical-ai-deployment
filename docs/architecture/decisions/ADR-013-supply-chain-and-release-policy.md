# ADR-013 — Supply Chain, Bills of Materials, and the Release Policy Gate

**Status:** Accepted for M08 local simulation; signing, provenance, and vulnerability scanning are
deferred under `NS-EXC-005`  
**Date:** 2026-08-14  
**Owners:** AppSec Lead, Engineering Lead, and SRE Lead  
**Related:** REQ-SDL-001/002/006, REQ-APP-004, CTL-SDL-001, CTL-APP-003, RSK-013/017/020, LIM-006,
BLK-004

## Context

`REQ-SDL-002` requires locked or SHA-pinned dependencies and actions, and SBOM, AIBOM, provenance,
vulnerability results, and signatures before promotion. Most of that is checkable from the repository
itself; some of it is not, and the difference matters more than the total.

A dependency SBOM also does not describe this system. Knowing that `pydantic` 2.13.4 is installed
says nothing about which model answers, which corpus version it may draw on, which tools it can
reach, or what bounds constrain it — and those are the things that change behavior.

## Decision

### The gate is deterministic and offline

`evaluate_release_policy` checks what the repository can decide on its own: GitHub Actions pinned to
40-character commit SHAs, container images pinned to sha256 digests, declared dependencies carrying
version bounds, every locked package having a hashed artifact, container and compose hardening
markers present, and no secret markers in tracked files.

Vulnerability scanning is deliberately **not** in this gate. It needs a live advisory feed, and a
gate that fails when an external service is unavailable teaches people to bypass the gate. Scanning
belongs in a separate, non-blocking job with its own review cadence — `NS-EXC-005` records that it
does not yet exist.

### Bills of materials are generated, never maintained

The SBOM is CycloneDX 1.6 built from `uv.lock`, not from an installed environment — reading the
environment would describe whichever machine ran the command. The application is the subject of the
document, not one of its own components.

The AIBOM is generated from the running definitions: model adapter identity and system-contract
digest, serving corpus version and manifest checksum with the refused candidates and their reasons,
the tool inventory with argument-schema digests, the agent bounds, the kill-switch capabilities, and
the evaluation thresholds. Because it is derived from the same objects the application uses, it
cannot drift from what the code actually permits. It also states what is *not* included — no hosted
provider, no embedding model, no training data.

Both are committed and drift-checked, so a change to a bound, a tool, or the corpus shows up as a
diff in a reviewed artifact rather than silently.

### The secret scan excludes only detector modules

Four modules necessarily contain the markers they search for. Nothing else is exempt — a test fixture
that needs a marker builds it from parts, so the scan stays honest rather than being weakened by a
growing exclusion list.

### Locally built images are identified by convention, not assumed

An image built from a Dockerfile in this repository cannot be digest-pinned before it exists. The
convention is that such images use the exact tag `:local`, and the check enforces it: any other tag
in a compose file is treated as a pulled artifact and must be digest-pinned.

### The runtime image carries no way to change itself

Base images are pinned by digest. Build tooling stays in the builder stage, and the runtime stage
removes pip and the apt binaries while keeping the dpkg database so scanners can still enumerate
contents. The application runs as uid 65532 on a read-only root filesystem with all capabilities
dropped, bounded memory and process count, and loopback-only ports.

The virtual environment is built at the path it will run from. A relocated virtualenv keeps absolute
interpreter shebangs, which fails at run time with a misleading "no such file or directory" — this
was found by building the image rather than by reading it.

## Consequences and limitations

- **No signing and no provenance attestation.** Both need a signing identity and a published
  artifact, and this repository is private with no release pipeline. `NS-EXC-005` records the
  deferral with its remediation.
- **No vulnerability scanning result.** Dependabot is configured for weekly dependency and Action
  updates, which is a real control, but its effectiveness has never been assessed and it is not a
  scan of the built image.
- **Reproducible in the pinning sense, not the bit-for-bit sense.** Pinned base digests and a locked
  dependency set mean a rebuild resolves the same inputs. Byte-identical image layers would need
  `SOURCE_DATE_EPOCH` handling and a reproducible builder, which is not claimed.
- The image was built and smoke-tested locally: it starts, serves `/health/live` and `/health/ready`,
  runs as non-root on a read-only filesystem, and contains no uv, pip, apt, gcc, or curl. It has
  never been built in CI or published anywhere.
- Branch protection remains unassessed (`LIM-006`), so "reviewed source changes" in `REQ-SDL-001`
  holds by convention rather than by enforcement.
- The compose stack has no TLS edge, no secret manager, and no observability sink. It is a hardened
  local runtime, not a deployment.

## Rejected alternatives

- **Generate the SBOM from the installed environment:** it would describe the developer's machine,
  which is the opposite of what a bill of materials is for.
- **Put vulnerability scanning in the blocking gate:** an advisory-feed outage would break unrelated
  work, and the reliable outcome is that someone adds a bypass.
- **Maintain the AIBOM by hand:** it would be accurate exactly once.
- **Exempt test files from the secret scan:** exclusion lists grow, and the first real leak lands in
  an exempt path. Fixtures build markers from parts instead.
- **Use a `:latest` base image and a lockfile:** the lockfile pins Python packages, not the operating
  system underneath them.
- **Keep pip in the runtime image for debugging:** an interactive debugging convenience is an
  installation primitive for anyone who reaches the container.

## Authoritative sources reviewed

- CycloneDX, *Specification 1.6*: https://cyclonedx.org/specification/overview/
- CycloneDX, *Authoritative Guide to AI/ML BOM*: https://cyclonedx.org/guides/
- SLSA v1.0, *Build track requirements*: https://slsa.dev/spec/v1.0/levels
- NIST SP 800-218, *Secure Software Development Framework*:
  https://doi.org/10.6028/NIST.SP.800-218
- OpenSSF, *Scorecard checks* (pinned dependencies, token permissions):
  https://github.com/ossf/scorecard/blob/main/docs/checks.md
- Docker, *Dockerfile best practices*:
  https://docs.docker.com/build/building/best-practices/

Sources were reviewed on 2026-08-14. They inform the design; they do not certify this implementation,
establish SLSA level attainment, or substitute for the scanning and signing deferred under
`NS-EXC-005`.

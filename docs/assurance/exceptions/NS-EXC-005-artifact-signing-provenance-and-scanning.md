# NS-EXC-005 — Artifact Signing, Build Provenance, and Vulnerability Scanning

**Status:** Approved — simulated role review only  
**Requested by:** AI Security Program Lead (simulated role)  
**Accountable owner:** AppSec Lead (simulated role)  
**Requested on:** 2026-08-14  
**Expires no later than:** 2027-02-14, or at the first pilot decision, whichever is earlier  
**Environment/release:** Local synthetic simulation; M08

## Integrity statement

This record is a role-based simulation. No named person or independent assessor approved it, and it
cannot authorize a real deployment, a published artifact, or a compliance claim.

## Requested exception

- **Requirement/control:** REQ-SDL-002, CTL-SDL-001
- **Exact deviation:** `REQ-SDL-002` requires SBOM, AIBOM, provenance, vulnerability results, and
  signatures before promotion. SBOM and AIBOM are generated, committed, and drift-checked. There is
  no artifact signature, no build provenance attestation, and no vulnerability scanning result for
  either dependencies or the built image.
- **Business necessity:** Signing needs a signing identity and key custody; provenance attestation
  needs a build that publishes an artifact. This repository is private, has no release pipeline, and
  publishes nothing, so there is no artifact to sign or attest. Vulnerability scanning needs a live
  advisory feed that the offline release gate deliberately excludes.
- **Alternatives considered:** Adding a keyless signing step that signs a locally built image was
  rejected — it would produce a signature nobody verifies, which is worse than an explicit gap.
  Putting a scanner in the blocking gate was rejected because an advisory-feed outage would break
  unrelated work and the reliable outcome is a bypass.
- **Affected data, people, workflow, integrations, and jurisdictions:** Local build only. No artifact
  is distributed.
- **Explicit exclusions:** This exception cannot authorize publishing an artifact, claiming any SLSA
  level, claiming a vulnerability posture, or describing the build as attested or signed.

## Risk and compensating controls

- **Related risks/scenarios:** RSK-013, RSK-017, RSK-020; THR-025/026; LIM-006
- **Inherent and current risk:** Inherent — high; an unsigned, unscanned artifact with no provenance
  is the standard supply-chain compromise path. Current — low in this scope, because nothing is
  published and nothing consumes the image but the developer who built it.
- **Potential impact:** In a real deployment, a tampered or vulnerable image would be undetectable at
  deploy time. This is the single largest gap between the M08 work and a deployable pipeline.
- **Compensating controls:** GitHub Actions pinned to commit SHAs and container images pinned to
  sha256 digests, both enforced as release blockers; a locked dependency set where every package has
  a hashed artifact; bounded version declarations; a tracked-secret scan whose only exemptions are
  the detector modules themselves; container and compose hardening markers checked as blockers; a
  runtime image with no package manager, compiler, or fetch tool, running non-root on a read-only
  filesystem; and generated SBOM and AIBOM documents that are committed and drift-checked. Dependabot
  raises weekly dependency and Action updates.
- **Verification and evidence:** VER-SDL-001, VER-SDL-002, EVD-M08-001
- **Residual risk and uncertainty:** High for any real deployment and unreduced by this record.
  Dependabot's effectiveness has never been assessed, and no scan has ever run against the image.

## Monitoring, stop, and remediation

- **Monitoring signals and thresholds:** `make verify` and CI fail on any release-policy blocker or a
  stale SBOM/AIBOM. Dependabot pull requests are the only ongoing dependency signal.
- **Immediate stop/revocation conditions:** Publishing an image or package anywhere, any pilot, any
  external consumer, or any claim of a signed, attested, or scanned artifact revokes this exception.
- **Incident/escalation path:** AppSec Lead, then the simulated release-gate authority.
- **Permanent remediation plan:** Add a non-blocking dependency and image vulnerability scan with a
  review cadence and severity thresholds; add build provenance attestation and artifact signing with
  documented key custody and a verification step consumers actually run. Owner: AppSec Lead. Due
  before any artifact is published or any pilot decision.
- **Validation and closure evidence required:** A scan result with triaged findings, a verifiable
  provenance attestation, and a signature verification performed by a consumer rather than by the
  publisher.

## Approval

| Approver | Named person | Decision/date | Conditions |
|---|---|---|---|
| System/Business Owner | Simulated role | Approve / 2026-08-14 | Nothing may be published |
| Security | Simulated role | Approve / 2026-08-14 | No SLSA or posture claims |
| Operations | Simulated role | Approve / 2026-08-14 | Local build only |
| Legal/Compliance | Not assessed | — | Cannot be simulated |

**Final decision:** Approve, for the local synthetic simulation only  
**Decision rationale:** The pinning, locking, hardening, and bill-of-materials controls that a
release gate can enforce offline are enforced and tested. The remaining items require a publishing
pipeline that does not exist, and simulating them would produce artifacts nobody verifies.  
**Review cadence:** Before expiry, and immediately on any proposal to publish an artifact.

An expired or revoked exception fails closed. Renewal requires a new evidence-backed decision.

# NS-EXC-001 — Enterprise Identity, Delegation, and TLS/mTLS Signal Edge

**Status:** Approved — simulated role review only  
**Requested by:** AI Security Program Lead (simulated role)  
**Accountable owner:** IAM Lead (simulated role)  
**Requested on:** 2026-08-13  
**Expires no later than:** 2027-02-13, or at the first pilot decision, whichever is earlier  
**Environment/release:** Local synthetic simulation; M04 close-out

## Integrity statement

This record is a role-based simulation. No named Northstar employee, counsel, clinician, or
independent assessor approved it, and it cannot authorize a real deployment, real PHI, or a
compliance claim. A real exception requires attributable people under Northstar policy.

## Requested exception

- **Requirement/control:** REQ-AUT-001/002/003, CTL-AUT-001/002/004
- **Exact deviation:** Polaris has no enterprise identity provider, no security token service, no
  confidential workload client, and no TLS/mTLS-authenticated signal edge. Access tokens, JWKS,
  token exchange, and signal delivery all use generated keys, injected transports, and local
  adapters. Default test fixtures still use HS256.
- **Business necessity:** The program's authorization is an educational simulation using synthetic
  data. Procuring and integrating an enterprise IdP and STS is outside its scope and funding, and
  doing so would require a real organization to accept the integration.
- **Alternatives considered:** A hosted developer tenant of a commercial IdP was rejected — it
  would create real credentials and a real external dependency for a repository that must remain
  self-contained, reproducible, and free of live-provider claims. Simulating an IdP more elaborately
  was rejected as adding fidelity theatre without adding assurance.
- **Affected data, people, workflow, integrations, and jurisdictions:** Synthetic patients and
  synthetic clinician identities only. No real person, credential, or jurisdiction is in scope.
- **Explicit exclusions:** This exception cannot authorize enabling HS256 or any local bearer
  adapter outside tests, attaching the unauthenticated HAPI lab to anything, real PHI, a pilot, or
  any claim of enterprise identity, SMART, or SSF/CAEP conformance.

## Risk and compensating controls

- **Related risks/scenarios:** RSK-001, RSK-004, RSK-011; THR-001 through THR-008; LIM-003
- **Inherent and current risk:** Inherent — high; an unauthenticated or spoofable identity edge
  would defeat every downstream authorization control. Current — accepted as out of scope, because
  no real identity or data exists to compromise.
- **Potential impact:** In a real deployment, none of the local adapters would resist a network
  attacker. That is the reason this must expire before any pilot rather than be renewed quietly.
- **Compensating controls:** The verifier enforces strict RS256, exact issuer/audience/type, no
  token-controlled key URLs, operation scopes, and revocation. Discovery binds issuer and
  allowlists JWKS origins with bounded rotation and stale-age limits. The RFC 8693 broker
  reauthenticates the subject, fixes audience/resource/scopes, and refuses passthrough. These are
  real, adversarially tested contracts; only their transport and key custody are simulated.
- **Verification and evidence:** VER-AUT-001 through VER-AUT-029, EVD-M04-001, EVD-M04-002
- **Residual risk and uncertainty:** High for any real deployment and unreduced by this record. The
  contracts have never met a live provider, so provider-specific payload and lifecycle differences
  are unknown — `ADR-008` records one such open question for Okta's top-level `sub_id`.

## Monitoring, stop, and remediation

- **Monitoring signals and thresholds:** CI must keep failing on any HS256 or local-bearer path
  reachable outside tests; `make verify` runs the full identity suite on every change.
- **Immediate stop/revocation conditions:** Any proposal to process real PHI, run a human pilot,
  expose the service beyond loopback, or make an external conformance claim revokes this exception
  immediately and fails closed.
- **Incident/escalation path:** AI Security Program Lead, then the simulated release-gate authority.
- **Permanent remediation plan:** Enterprise IdP/STS integration, confidential-client credential
  acquisition, and a TLS/mTLS edge, per `ADR-003` and
  `docs/architecture/authoritative-relationship-and-consent-integration.md`. Owner: IAM Lead. Due
  before any pilot decision.
- **Validation and closure evidence required:** A live-tenant integration record with provider
  conformance results, credential custody design, and edge authentication evidence.

## Approval

| Approver | Named person | Decision/date | Conditions |
|---|---|---|---|
| System/Business Owner | Simulated role | Approve / 2026-08-13 | Simulation scope only |
| Security | Simulated role | Approve / 2026-08-13 | Stop conditions binding |
| Privacy/Records | Simulated role | Approve / 2026-08-13 | Synthetic data only |
| Clinical Safety | Not applicable | — | No clinical pathway affected |
| Legal/Compliance | Not assessed | — | Cannot be simulated |

**Final decision:** Approve, for the local synthetic simulation only  
**Decision rationale:** The deviation is inherent to the program's authorized scope, the
compensating contracts are real and tested, and no real identity, credential, or patient is exposed.  
**Review cadence:** Before expiry, and immediately on any scope change toward a pilot.

An expired or revoked exception fails closed. Renewal requires a new evidence-backed decision.

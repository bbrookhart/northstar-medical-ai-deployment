# NS-EXC-002 — Live Provider Conformance, Lifecycle, and Flood Controls

**Status:** Approved — simulated role review only  
**Requested by:** AI Security Program Lead (simulated role)  
**Accountable owner:** IAM Lead (simulated role)  
**Requested on:** 2026-08-13  
**Expires no later than:** 2027-02-13, or at the first pilot decision, whichever is earlier  
**Environment/release:** Local synthetic simulation; M04 close-out

## Integrity statement

This record is a role-based simulation. No named person or independent assessor approved it, and it
cannot authorize a real deployment, a live tenant connection, or a conformance claim.

## Requested exception

- **Requirement/control:** REQ-AUT-004/005, CTL-AUT-003/005
- **Exact deviation:** No final-SSF transmitter, no Okta tenant, and no continuous-access stream has
  ever been contacted. Discovery, stream configuration, status, subject management, verification,
  and System Log polling all run against scripted transports. Provider-side and edge rate limiting,
  global flood controls, and approved unsolicited-event enablement do not exist.
- **Business necessity:** A live tenant would create real credentials, a real external dependency,
  and a real vendor relationship, none of which this simulation is authorized to establish.
- **Alternatives considered:** A free developer tenant was rejected — it would produce results that
  look like conformance evidence while being unrepresentative of an enterprise tenant's
  configuration, limits, and lifecycle, which is a worse outcome than an explicit gap. Recording the
  scripted results as conformance was rejected outright as a false claim.
- **Affected data, people, workflow, integrations, and jurisdictions:** Synthetic identities only.
- **Explicit exclusions:** This exception cannot authorize any statement that Polaris is SSF, CAEP,
  or provider conformant; enabling unsolicited verification acceptance against a live transmitter;
  or presenting the Okta profile as a tested integration.

## Risk and compensating controls

- **Related risks/scenarios:** RSK-004, RSK-011, RSK-016; THR-009 through THR-014; LIM-003
- **Inherent and current risk:** Inherent — high; a continuous-access path that does not actually
  work would leave revoked sessions live while appearing healthy. Current — the local contracts fail
  closed, so the failure mode is unavailability rather than false confidence.
- **Potential impact:** Unknown provider payload and lifecycle differences. `ADR-008` records that
  current Okta examples do not establish final-SSF top-level `sub_id` conformance, and Okta does not
  document SSF event replay at all — which is why the compensating System Log path exists.
- **Compensating controls:** Strict issuer/version/origin binding, non-cacheable status reads,
  pending-only verification semantics, durable desired/observed reconciliation, bounded safe status
  recovery, correlated verification health, a default-reject unsolicited policy with a durable
  quota, and — new in this increment — durable compare-and-swap page application with a multi-signal
  exit gate that refuses to close on an empty page alone.
- **Verification and evidence:** VER-AUT-020 through VER-AUT-030, EVD-M04-001, EVD-M04-002
- **Residual risk and uncertainty:** High for any real deployment. Everything above proves the
  receiver's discipline, not the transmitter's behavior.

## Monitoring, stop, and remediation

- **Monitoring signals and thresholds:** The stream health, checkpoint freshness, and verification
  contracts already deny on staleness; readiness fails closed. CI runs the full SSF suite.
- **Immediate stop/revocation conditions:** Any live-tenant connection, external network target, or
  public conformance claim revokes this exception.
- **Incident/escalation path:** IAM Lead, then the simulated release-gate authority.
- **Permanent remediation plan:** Synthetic-tenant final-SSF conformance capture with approved
  credentials and TLS, provider feature and lifecycle confirmation, approved unsolicited-event
  enablement and limits, and vendor review. Owner: IAM Lead. Due before any pilot decision.
- **Validation and closure evidence required:** Captured live payloads, a provider conformance
  result, and an approved rate-limit and flood-control configuration.

## Approval

| Approver | Named person | Decision/date | Conditions |
|---|---|---|---|
| System/Business Owner | Simulated role | Approve / 2026-08-13 | Simulation scope only |
| Security | Simulated role | Approve / 2026-08-13 | No conformance claims |
| Privacy/Records | Simulated role | Approve / 2026-08-13 | Synthetic identities only |
| Clinical Safety | Not applicable | — | No clinical pathway affected |
| Vendor Risk | Not assessed | — | No vendor relationship exists |

**Final decision:** Approve, for the local synthetic simulation only  
**Decision rationale:** A scripted transport that is labelled as such is more honest evidence than a
developer tenant that would be mistaken for enterprise conformance.  
**Review cadence:** Before expiry, and immediately on any proposal to contact a live provider.

An expired or revoked exception fails closed. Renewal requires a new evidence-backed decision.

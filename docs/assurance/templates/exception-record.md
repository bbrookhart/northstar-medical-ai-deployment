# NS-EXC-{NNN} — Exception Record Template

**Status:** Draft / Approved / Expired / Revoked / Closed  
**Requested by:** {named person and role}  
**Accountable owner:** {named person and role}  
**Requested on:** {YYYY-MM-DD}  
**Expires no later than:** {YYYY-MM-DD}  
**Environment/release:** {scope}

## Requested exception

- Requirement/control: {REQ-* / CTL-*}
- Exact deviation: {what will not operate as required}
- Business necessity: {why the scoped outcome cannot wait}
- Alternatives considered: {safer options and why rejected}
- Affected data, people, workflow, integrations, and jurisdictions: {scope}
- Explicit exclusions: {what this exception cannot authorize}

## Risk and compensating controls

- Related risks/scenarios: {RSK-* / THR-* / PRI-* / MIS-* / HAZ-*}
- Inherent and current risk: {method and evidence}
- Potential patient, privacy, security, equity, operational, and legal impact: {analysis}
- Compensating controls: {owned, testable CTL-* or temporary control IDs}
- Verification and evidence: {VER-* / EVD-* with result, configuration, revision, and date}
- Residual risk and uncertainty: {after compensation; do not reduce without evidence}

## Monitoring, stop, and remediation

- Monitoring signals and thresholds: {metric/query/alert, owner, cadence}
- Immediate stop/revocation conditions: {objective conditions}
- Incident/escalation path: {roles and channel}
- Permanent remediation plan, owner, and due date: {work item}
- Validation and closure evidence required: {VER-* / EVD-*}

## Approval

Required approvers are determined by affected domains and cannot be the requester alone. High or
critical residual risk requires the release-gate authority defined by policy; legal, Privacy, and
Clinical Safety review cannot be simulated for a real deployment.

| Approver | Named person | Decision/date | Conditions |
|---|---|---|---|
| System/Business Owner |  |  |  |
| Security |  |  |  |
| Privacy/Records |  |  |  |
| Clinical Safety |  |  |  |
| Legal/Compliance |  |  |  |
| Operations/Data/Vendor/Accessibility as affected |  |  |  |

**Final decision:** Approve / Deny  
**Decision rationale:** {evidence-backed rationale}  
**Review cadence:** {at least before expiry and after material change}

An expired or revoked exception fails closed. Renewal requires a new evidence-backed decision; it
is not automatic. An exception cannot authorize real PHI in this repository, prohibited clinical
behavior, model-controlled authorization/credentials, mutated/unapproved writes, or unsupported
compliance/certification claims.

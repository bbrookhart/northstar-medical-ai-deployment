# NS-REL-{NNN} — Release Decision Template

**Gate/milestone:** {M## and environment}  
**Decision:** Pass / Conditional pass / Fail / Not assessed  
**Decision date:** {YYYY-MM-DD}  
**Implementation revision and release manifest:** {immutable references}  
**Decision owner:** {named person and role}

## Scope and change

- Capabilities, users, data, integrations, model/provider, tools, and autonomy: {exact scope}
- Changes since last decision: {diff and materiality assessment}
- Explicit exclusions and prohibited uses: {boundary}
- Rollback target and compatibility: {known-good versions}

## Required evidence

| Gate criterion | Requirement/control | Verification/evidence | Result | Finding/exception |
|---|---|---|---|---|
| Governance and accountable ownership |  |  |  |  |
| Security and authorization |  |  |  |  |
| Privacy, data lifecycle, and vendor |  |  |  |  |
| Clinical safety and human factors |  |  |  |  |
| Functional/grounding/robustness evaluation |  |  |  |  |
| Accessibility, performance, cost, and equity |  |  |  |  |
| Supply chain and configuration |  |  |  |  |
| Detection, incident response, kill, rollback, and recovery |  |  |  |  |
| Training, support, claims, and retirement readiness |  |  |  |  |

## Risk and operational readiness

- Open findings by severity: {IDs}
- Exceptions and expiry: {NS-EXC-*}
- Residual-risk decisions: {NS-RRD-*}
- SLO/threshold and monitoring readiness: {evidence}
- Kill/rollback/fallback/restore exercise: {result and objective timing}
- On-call, support, incident, privacy complaint, safety report, and escalation readiness: {owners}

## Decision and approvals

Universal disqualifiers in `docs/assurance/release-gates.md` cannot receive conditional pass.
Conditional pass requires an explicitly permitted, time-bound exception and cannot hide a critical
or high release blocker.

| Authority | Named approver | Decision/date | Conditions |
|---|---|---|---|
| System and Business Owners |  |  |  |
| Security |  |  |  |
| Privacy / Legal / Compliance / Records |  |  |  |
| Clinical Safety / Accessibility / Product |  |  |  |
| Operations / IR / Data / IAM / Vendor Risk |  |  |  |
| Independent assurance where required |  |  |  |

**Final rationale:** {evidence-backed decision}  
**Required follow-up, owner, and deadline:** {items}  
**Permitted internal/public claims:** {exact bounded wording}  
**Next review trigger:** {date, threshold, incident, or material change}

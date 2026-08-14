# NS-RRD-{NNN} — Residual-Risk Decision Template

**Decision status:** Draft / Accept / Further treatment / Avoid / Transfer / Expired / Revoked  
**Risk owner:** {named person and role}  
**Decision date:** {YYYY-MM-DD}  
**Review/expiry date:** {YYYY-MM-DD}  
**Release/environment:** {scope}

## Risk basis

- Risk and scenario IDs: {RSK-* plus THR/PRI/MIS/HAZ IDs}
- Affected people, data, care/business workflows, and dependencies: {scope}
- Inherent likelihood/impact and method: {rating plus uncertainty}
- Harm analysis: {security, privacy, safety, equity, legal, financial, operational, reputation}
- Threat/exposure assumptions: {including model/provider compromise assumptions}

## Treatment and evidence

- Implemented controls: {CTL-* with operating status}
- Verified results: {VER-*}
- Evidence: {EVD-* with revision, configuration, dataset, period, and owner}
- Open findings/exceptions: {IDs, severity, expiry, compensating controls}
- Independent challenge: {reviewer, scope, findings, conflicts of interest}

## Residual determination

- Residual likelihood/impact by relevant harm dimension: {rating and rationale}
- Remaining uncertainty, limitations, and affected subgroups: {explicit}
- Monitoring indicators, thresholds, owner, and cadence: {objective}
- Stop/reassessment triggers: {incident, drift, complaint, threshold, control failure, material change}
- Further treatment and deadline: {or justified none}

## Decision

| Required authority | Named approver | Decision/date | Conditions |
|---|---|---|---|
| Risk owner |  |  |  |
| System/Business Owner |  |  |  |
| Security |  |  |  |
| Privacy / Clinical Safety / Legal / Operations as affected |  |  |  |
| Independent assurance where required |  |  |  |

**Decision rationale:** {why the residual risk is or is not tolerable for this exact scope}  
**Public/portfolio claim impact:** {permitted wording and prohibited inference}

Risk acceptance is not permanent, cannot be inferred from a control mapping, and cannot be signed
by a simulated role for real deployment. It expires, fails closed when required monitoring/evidence
is absent, and is reopened after any material change.

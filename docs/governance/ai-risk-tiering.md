# NS-AIA-001 — AI Impact and Risk-Tiering Decision

**Artifact status:** Draft for simulated AI Review Board  
**Owner:** AI System Owner  
**Assessment date:** 2026-08-11  
**Reassessment:** At every material scope, data, model, tool, autonomy, population, jurisdiction, or provider change

## Tiering model

Northstar uses four inherent-risk tiers:

| Tier | Description | Example governance |
|---|---|---|
| T1 — Minimal | No sensitive data or consequential workflow | Owner review and inventory |
| T2 — Moderate | Internal productivity with limited sensitive context and no consequential action | Security/privacy review and standard evaluation |
| T3 — High impact | Sensitive data, healthcare workflow influence, tools, or plausible safety/rights impact | Multidisciplinary review, independent assurance, pilot gates, continuous monitoring |
| T4 — Critical/clinical | Autonomous or opaque clinical decisions, diagnosis/treatment, high-consequence action | Executive review, specialized regulatory pathway, strongest independent validation; may be prohibited |

## Decision

**Polaris v1 inherent tier: T3 — High impact.**

Although the v1 purpose is administrative and uses synthetic data in this repository, the production analog would process health information, influence healthcare workflow, and invoke a state-changing administrative tool. Users could over-rely on fluent output. Prompt injection or authorization failure could expose patient data or corrupt work queues. These properties require high-impact governance.

Polaris is not classified T4 while all of the following remain true:

- No diagnosis, prescribing, treatment, triage, or clinical recommendation
- No autonomous clinical record update or patient communication
- Only a narrow, reversible, non-clinical task write
- Explicit independent approval and deterministic execution controls
- The system is not intended to replace clinician judgment

## Impact dimensions

| Dimension | Inherent assessment | Reason |
|---|---|---|
| Patient safety | High | Incorrect or delayed workflow could indirectly affect care; users may over-trust output |
| Privacy/confidentiality | High | Production analog would handle ePHI and sensitive Part 2-style data |
| Security/integrity | High | Tool misuse, poisoning, or authorization bypass can alter workflow state |
| Availability | High | Healthcare operational dependence raises disruption impact |
| Equity/accessibility | Moderate | Language, accessibility, and uneven error patterns may affect workforce and patients indirectly |
| Legal/regulatory | High | HIPAA, state law, contracts, records, and clinical-scope questions apply |
| Financial/reputation | High | Breach, outage, unsafe output, or misleading compliance claims could be material |
| Autonomy | Moderate | Single bounded agent with one approval-gated write; multi-agent and memory prohibited |

## Mandatory T3 controls

- Named business and system owners
- AI inventory and change register
- Approved/prohibited-use policy
- Multidisciplinary impact, privacy, threat, misuse, and safety assessment
- Deny-by-default identity and authorization
- Minimum-necessary retrieval and data segregation
- Human approval bound to exact action arguments
- Independent critical-invariant testing and red team
- Versioned evaluation before model, prompt, corpus, policy, tool, or provider promotion
- Continuous monitoring, incident response, kill switch, rollback, recovery, and exit
- Time-limited residual-risk acceptance
- Role-specific user and operator training
- Independent audit before simulated full production approval

## Automatic escalation triggers

Escalate to T4 review or stop the project if any proposal adds:

- Diagnostic, prognostic, prescriptive, treatment, or triage output
- Patient-facing personalized health advice
- Unreviewed patient communication
- Autonomous EHR clinical writes
- High-impact irreversible actions
- Persistent memory containing health information
- Broad internet/email access combined with sensitive data or state-changing tools
- Multi-agent delegation that obscures identity, scope, evidence, or accountability
- Use as the sole basis for a clinical or legally significant decision

## Residual-risk target

The target is no residual critical or high risk at simulated release. Moderate risks require owners, monitoring, expiry, and approval. Low risks remain tracked when they affect safety, privacy, or assurance assumptions.


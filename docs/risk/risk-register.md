# NS-RSK-001 — Initial Project Polaris Risk Register

**Artifact status:** M02 reviewed inherent-risk baseline; M03 controls mapped  
**Risk owner:** AI System Owner; individual owners below  
**Last updated:** 2026-08-11  
**Review cadence:** Every sprint; formal review at each gate

## Scoring

Likelihood and impact use 1–5 ordinal scales. Inherent score is `likelihood × impact` before Polaris-specific treatment.

| Score | Rating | Required disposition |
|---|---|---|
| 20–25 | Critical | Stop; executive escalation and redesign |
| 12–19 | High | Must reduce before simulated release |
| 6–11 | Moderate | Owner, monitoring, treatment or time-limited acceptance |
| 1–5 | Low | Track and review on change |

This score prioritizes discussion and does not replace multidimensional patient-safety, privacy, or legal analysis.

## Register

| ID | Risk scenario | Category | L | I | Inherent | Principal treatment | Owner | Residual target | Status |
|---|---|---|---:|---:|---:|---|---|---|---|
| RSK-001 | Direct prompt injection changes output or attempts to invoke a privileged function | AI security | 5 | 5 | 25 | Assume injection succeeds; deterministic authorization, typed tools, bounded workflow, approval | AI Security | Moderate | Open |
| RSK-002 | Instructions planted in policy text, FHIR narrative, or tool output redirect the agent | AI security/data | 5 | 5 | 25 | Provenance, quarantine, trust labels, content isolation, no model-to-tool authority, adversarial tests | Data Steward | Moderate | Open |
| RSK-003 | A user retrieves another patient or facility's data | Privacy/security | 4 | 5 | 20 | OIDC claims, patient relationship, facility, purpose, sensitivity, row policy, negative matrix tests | IAM Lead | Low | Open |
| RSK-004 | Part 2-style SUD data is disclosed without required authorization | Privacy/legal | 3 | 5 | 15 | Sensitivity labels, consent/role policy, segregated tests, audit, incident procedure | Privacy Officer | Low | Open |
| RSK-005 | An over-privileged service identity causes confused-deputy access | Identity | 4 | 5 | 20 | Preserve user delegation, audience-bound short-lived tokens, no token passthrough, per-tool identity | IAM Lead | Moderate | Open |
| RSK-006 | A malicious or erroneous proposal mutates after human review | Agent/action integrity | 4 | 5 | 20 | Canonical action, digest binding, exact preview, expiry, single use, execution revalidation | Engineering Lead | Low | Open |
| RSK-007 | Approval fatigue or deceptive rendering causes unsafe approval | Human factors | 3 | 5 | 15 | Independent approver, risk-based approvals, exact diff, accessible UI, no hidden characters, rate limits | Product Owner | Moderate | Open |
| RSK-008 | Hallucinated or outdated policy information is trusted | Safety/quality | 5 | 4 | 20 | Approved sources, version/citation, conflict detection, abstention, golden set, feedback | Business Owner | Moderate | Open |
| RSK-009 | Output crosses into diagnosis, treatment, prescription, or triage | Clinical safety | 4 | 5 | 20 | Prohibited-use policy, fixed safety paths, deterministic intent gates, clinical test suite, user training | Clinical Safety | Low | Open |
| RSK-010 | Retrieval index leaks restricted content through embeddings, metadata, cache, or filters | Data security | 4 | 5 | 20 | Data classification, ACL before and after retrieval, separate collections, row controls, cache isolation | Data Steward | Moderate | Open |
| RSK-011 | Corpus or embedding pipeline is poisoned or rolled forward without review | Supply chain/data | 4 | 4 | 16 | Approved ingestion, hashes, signatures where feasible, owner review, versioning, rollback, canaries | Data Steward | Moderate | Open |
| RSK-012 | Dependency, container, model, or tool artifact is compromised | Supply chain | 4 | 5 | 20 | Locking, review, SAST/SCA/container/IaC scans, SBOM/AIBOM, signing/provenance, promotion gate | AppSec Lead | Moderate | Open |
| RSK-013 | Hosted provider retains data, trains on it, changes a model, or uses unapproved subprocessors | Vendor/privacy | 3 | 5 | 15 | Due diligence, BAA/DPA decision, retention/training terms, change notice, region, audit, exit, regression | Vendor Risk | Moderate | Open |
| RSK-014 | Raw prompts, patient data, credentials, or hidden reasoning leak into logs/traces | Observability/privacy | 4 | 5 | 20 | Event schema, allowlist, redaction, no routine raw payloads, access/retention, log tests | SRE Lead | Low | Open |
| RSK-015 | Runaway tokens, loops, fan-out, or tool calls cause outage or excessive cost | Availability/cost | 4 | 4 | 16 | Budgets, step/tool caps, quotas, timeouts, circuit breakers, cost alerts, load/adversarial tests | SRE Lead | Low | Open |
| RSK-016 | Provider, FHIR, policy store, identity, or task service outage disrupts workflow | Resilience | 4 | 4 | 16 | Safe degradation, timeouts, queues where safe, SLOs, runbooks, backup/recovery, manual fallback | SRE Lead | Moderate | Open |
| RSK-017 | Model/prompt/policy/corpus change silently reduces safety or authorization behavior | Change risk | 5 | 5 | 25 | Version registry, immutable test evidence, promotion gate, canary, rollback, change owner | System Owner | Moderate | Open |
| RSK-018 | Insider uses legitimate access for curiosity or an unapproved purpose | Insider/privacy | 3 | 5 | 15 | Purpose capture, least privilege, anomalous-access detection, audit review, sanctions/training | Privacy Officer | Moderate | Open |
| RSK-019 | Users over-rely on fluent output or stop checking sources | Human factors/safety | 4 | 4 | 16 | Source UX, uncertainty, drafts, training, workflow sampling, feedback, human-factors evaluation | Clinical Safety | Moderate | Open |
| RSK-020 | Accessibility, language, or demographic differences produce unequal usability or outcomes | Equity/accessibility | 3 | 4 | 12 | WCAG testing, plain language, representative scenarios, subgroup review, alternative workflow | Product Owner | Moderate | Open |
| RSK-021 | Incident response cannot reconstruct or contain an AI-specific event | Incident response | 3 | 5 | 15 | Audit correlation, model/tool/corpus versions, playbooks, kill switch, tabletop, evidence preservation | IR Lead | Low | Open |
| RSK-022 | The project claims compliance, clinical fitness, or security beyond its evidence | Governance/reputation | 4 | 4 | 16 | Disclaimer, claims review, evidence ledger, legal/compliance approval, public-release checklist | Compliance | Low | Open |
| RSK-023 | Synthetic records are mistaken for real or leak identifying seed/source content | Data governance | 2 | 5 | 10 | Generate locally from approved synthetic tools, label fixtures, provenance, scan, no production imports | Data Steward | Low | Open |
| RSK-024 | Scope growth creates shallow controls and incomplete evidence | Program | 5 | 4 | 20 | v1 boundary, phase gates, WIP limits, status ledger, extension backlog | Product Manager | Moderate | Treating |
| RSK-025 | Code and governance artifacts drift apart | Assurance | 4 | 4 | 16 | Stable IDs, traceability, CI checks where possible, ADRs, status updates, evidence review | System Owner | Low | Treating |

## Immediate priorities

1. Specify authorization attributes and deny-by-default policy for RSK-003 through RSK-005.
2. Implement the action-integrity protocol for RSK-006 and RSK-007.
3. Define approved-source ingestion and retrieval isolation for RSK-001, RSK-002, RSK-008, RSK-010, and RSK-011.
4. Define logging/event schemas before observability code for RSK-014 and RSK-021.
5. Create change/version identifiers before introducing a hosted model for RSK-013 and RSK-017.

## Acceptance rule

The register is not evidence of risk reduction. A risk's residual rating may change only when linked controls are implemented and verified or when an accountable owner approves a time-limited residual risk with supporting evidence.

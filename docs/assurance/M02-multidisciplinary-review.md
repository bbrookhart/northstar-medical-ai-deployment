# NS-ASR-002 — M02 Simulated Multidisciplinary Review

**Review status:** Reviewed — simulated and conditional  
**Review date:** 2026-08-11  
**Facilitator:** AI Security Program Lead role  
**Decision scope:** Continued synthetic-data development only  
**Not authorized:** Pilot, production, clinical use, or processing of real PHI

## Integrity statement

This is a role-based project simulation, not evidence that named Northstar employees, counsel,
clinicians, regulators, an institutional review body, or an independent assessor participated or
approved the system. It exercises the review method and records the decisions a real enterprise
would require. External approvals remain release-gate prerequisites and must never be inferred from
this artifact.

## Review scope and method

The simulated review examined the M02 data-flow inventory, AI impact assessment, privacy impact
assessment, privacy threat model, security threat model, abuse/misuse cases, clinical-safety hazard
analysis, initial risk register, requirements baseline, and OWASP/MITRE crosswalk. Each artifact was
challenged from the following accountable-role lenses:

| Review lens | Role represented | Primary challenge |
|---|---|---|
| Business and product | Business Owner / Product Owner | Intended benefit, workflow fit, scope control, and measurable outcomes |
| Clinical safety | Clinical Safety Officer | Prohibited clinical behavior, emergency handling, human factors, and stop criteria |
| Privacy and records | Privacy Officer / Records Owner | Minimum necessary use, consent/sensitivity, retention, deletion, and secondary use |
| Security and identity | CISO delegate / IAM Lead / AppSec Lead | Threat boundaries, authorization, action integrity, supply chain, and detection |
| Data governance | Data Steward | Provenance, classification, lineage, retrieval isolation, and corpus integrity |
| Legal and compliance | Legal / Compliance role | Claims discipline, healthcare obligations, contract dependencies, and exceptions |
| Operations and resilience | SRE / Incident Response Lead | Failure modes, observability, kill/rollback, recovery, and manual fallback |
| Accessibility and equity | Accessibility / Human Factors role | Comprehension, automation bias, inclusive access, and non-AI alternatives |

## Findings and dispositions

| Finding | Severity | Observation | Disposition | Gate effect |
|---|---|---|---|---|
| FND-M02-001 | High | Three release-blocking requirements used permissive `MAY` wording. | Corrected REQ-RAG-001, REQ-ACT-001, and REQ-SDL-005 to unambiguous `MUST`/`MUST NOT` language. | Resolved for baseline review |
| FND-M02-002 | High | Requirements, risks, controls, verification, and evidence were not yet machine-linked. | M03 must create typed catalogs, total scenario/risk/requirement coverage, and CI validation. | Blocks M02 completion until M03 validator passes |
| FND-M02-003 | High | Retention, legal hold, deletion, backup expiry, and provider deletion periods are undecided. | Records, Privacy, Legal, Security, and the System Owner must approve a testable schedule before pilot. | Pilot/production blocker |
| FND-M02-004 | High | Local HMAC identity and in-memory services are simulation controls, not enterprise integrations. | Enterprise OIDC, delegated downstream identity, FHIR, policy, task, KMS, and durable audit adapters remain required. | Pilot/production blocker |
| FND-M02-005 | High | Fixed emergency guidance, accessible trusted approval rendering, comprehension testing, and fatigue monitoring are not implemented. | Build and clinically review the deterministic safety path and human-factors evaluation before user validation. | Human-validation and pilot blocker |
| FND-M02-006 | High | Provider/model due diligence, data-use terms, BAA/DPA decision, regional processing, subprocessor, continuity, and exit evidence do not exist. | Vendor Risk, Privacy, Legal, Security, and the System Owner must approve the provider decision before hosted-model use. | Hosted-model blocker |
| FND-M02-007 | High | Detection, incident exercises, independent kill switches, rollback, reconciliation, RTO/RPO, and restore proof are planned only. | Implement and exercise the operating-control set before pilot. | Pilot/production blocker |
| FND-M02-008 | Moderate | The official OWASP GenAI 2026 material was identifiable, but exact LLM category verification could not be completed from the available official artifact endpoint. | Keep theme mappings provisional; do not claim exact 2026 LLM category coverage until the official artifact is acquired and reviewed. Agentic mappings may use reviewed official ASI identifiers separately. | Conditional framework-mapping item |
| FND-M02-009 | Moderate | Safety, privacy, and security claims could be mistaken for production assurance in a portfolio setting. | Require status labels, synthetic-data notices, evidence links, and explicit non-claims in every public artifact. | Public-release gate item |

## Review decision

The M02 design baseline is **conditionally accepted for continued local, synthetic-data
development**. This is not approval of residual risk and does not close any risk-register entry.
The baseline becomes M02-complete only when the M03 traceability validator demonstrates:

1. every normative requirement has an owner, lifecycle phase, disposition, risk, control,
   verification, and evidence reference;
2. every registered risk and every THR/PRI/MIS/HAZ scenario maps to treatment controls;
3. all references resolve, verified tests/evidence exist, and no critical/high risk is orphaned; and
4. open pilot/production blockers remain visible rather than being mislabeled as implemented.

## Required real-world approvals

Before any pilot or production decision, Northstar would obtain attributable approval from the
actual Business/System Owner, Clinical Safety, Privacy, Security, Legal/Compliance, Data Governance,
Records, Accessibility/Human Factors, Operations/IR, Vendor Risk, and—where policy requires—an
independent assurance function. Those approvals must include evidence-backed residual-risk and
release decisions; this simulation cannot substitute for them.

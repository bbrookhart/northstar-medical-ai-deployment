# NS-ORG-001 — Stakeholder, Accountability, and RACI Model

**Artifact status:** Draft for simulated executive approval  
**Owner:** Executive Sponsor  
**Last updated:** 2026-08-11

## Decision model

Business and system owners remain accountable for outcomes and residual risk. Security, privacy, compliance, legal, and clinical safety provide independent challenge but do not absorb first-line ownership. Internal audit does not design controls it will later assess.

## Stakeholders and decision rights

| Role | Principal accountability | Key decision rights |
|---|---|---|
| Board Risk and Quality Committee | Enterprise oversight | Risk appetite and material-risk escalation |
| Executive Sponsor | Strategic value and funding | Charter, priority, continuation, stop decision |
| Business Owner | Workflow outcome and adoption | Use-case scope, benefit threshold, user acceptance |
| AI System Owner | End-to-end system accountability | Release recommendation, change, retirement |
| Product Manager | Requirements and delivery | Backlog and acceptance within approved scope |
| Clinical Safety Officer | Patient-safety boundary | Safety requirements, hazards, pilot stop condition |
| AI Security Lead | AI/application security assurance | Security requirements, threat model, release findings |
| Privacy Officer | Privacy risk and HIPAA policy | Data use, minimum necessary, DPIA, breach assessment |
| Compliance/Legal | Regulatory and contractual interpretation | Applicability, legal conditions, claims, contract clauses |
| Data Steward | Data authorization and quality | Source approval, classification, lineage, retention |
| Enterprise Architect | Technology fit | Architecture and integration standards |
| Engineering Lead | Secure implementation | Technical design and code quality |
| IAM Lead | Identity and authorization | Claims, roles, delegated access, break-glass design |
| Vendor Risk/Procurement | Third-party risk | Due diligence, contract readiness, exit rights |
| SOC/Incident Response | Detection and response | Alerting, incident severity, containment coordination |
| SRE/Operations | Reliability and change operation | SLOs, deployment, rollback, recovery |
| Workforce Training/Change Lead | Safe adoption | Role training, support, acceptable-use readiness |
| Patient/Workforce Representative | Human impact | Usability, transparency, trust, burden feedback |
| Internal Audit | Independent assurance | Audit scope, sampling, operating-effectiveness opinion |

## RACI

Legend: **A** accountable, **R** responsible, **C** consulted, **I** informed.

| Activity | Sponsor | Business | System | Product | Clinical | Security | Privacy/Legal | Data | Eng/Arch | Ops/SOC | Audit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Charter and business case | A | R | C | R | C | C | C | I | I | I | I |
| Use-case and prohibited-use boundary | I | A | R | R | R | C | C | C | C | I | I |
| Risk tier and impact assessment | I | C | A | R | R | R | R | C | C | C | I |
| Regulatory applicability | I | C | C | I | C | C | A/R | C | I | I | I |
| Data-source approval | I | C | A | C | C | C | C | R | C | I | I |
| Architecture and threat model | I | C | A | C | C | R | C | C | R | C | I |
| Secure implementation | I | I | A | C | C | C | C | C | R | C | I |
| Evaluation and red team | I | C | A | C | R | R | R | C | C | C | I |
| Vendor selection and contract | C | C | A | C | C | C | C | C | C | I | I |
| Pilot approval | I | A | R | R | R | R | R | C | C | C | I |
| Production release recommendation | I | C | A | R | R | R | R | C | R | R | I |
| Residual-risk acceptance | A* | A* | R | I | C | C | C | I | I | I | I |
| Incident response | I | C | A | I | C | R | R | C | C | R | I |
| Model/corpus/prompt change | I | C | A | R | C | R | C | C | R | R | I |
| Independent audit | I | I | C | I | C | C | C | I | C | C | A/R |
| Retirement | I | A | R | R | C | C | R | R | R | R | I |

`A*` depends on residual-risk severity and enterprise delegation. Material patient-safety, privacy, legal, or enterprise risks escalate to the Executive Sponsor and applicable committee.

## Required simulated approvals

Approval artifacts are role-based and marked as simulated. Do not fabricate names, signatures, or dates. An artifact may be marked `Draft`, `Reviewed`, `Approved — Simulated`, `Rejected — Simulated`, or `Expired` only when the stated evidence exists.


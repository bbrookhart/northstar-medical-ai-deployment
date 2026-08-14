# NS-PRI-001 — Polaris Privacy Impact Assessment

**Status:** M02 simulated review complete; actual Privacy Officer and Legal validation required  
**Privacy owner:** Northstar Privacy Officer  
**Date:** 2026-08-11  
**Assessment scope:** Internal U.S. workforce application; synthetic data implementation and PHI analog

## Processing summary

Polaris processes workforce identity and authorization attributes, declared purpose, approved policy
content, minimal synthetic patient context, user queries/drafts, action proposals and approvals, and
security/audit metadata. The production analog could process PHI/ePHI and Part 2 records. Current
development is authorized only for generated synthetic data.

## Purpose and necessity

| Processing | Purpose | Necessary? | Less intrusive option |
|---|---|---|---|
| Identity/role/facility/assignment | Authenticate and authorize | Yes | No anonymous sensitive workflow |
| Purpose of use | Enforce and evidence permitted workflow | Yes | Role alone is insufficient |
| Approved policy excerpts | Answer workforce questions | Yes | Conventional search remains fallback |
| Minimal patient summary | Support assigned administrative follow-up | Conditional | Omit for policy-only/drafting tasks |
| Model prompt/response | Generate grounded draft | Conditional | Deterministic templates or no model |
| Proposal/approval/receipt | Safe bounded task execution | Yes for writes | Keep system read-only |
| Audit/security metadata | Accountability, detection, investigation | Yes | Minimized event schema; no raw body by default |
| Feedback/evaluation | Quality and harm monitoring | Conditional | Aggregate/minimize; separate consent/policy review |

## Authority and role assumptions requiring validation

For a real covered-entity deployment, Northstar must document the permitted HIPAA use/disclosure,
minimum-necessary treatment, role of each vendor/business associate, BAA obligations, records policy,
and applicable state law. Treatment use may be excepted from the HIPAA minimum-necessary standard,
but Northstar still adopts task-based minimization as an internal design requirement. Part 2 data
requires separate legal/consent/redisclosure analysis. Workforce monitoring, recordings, biometrics,
and consumer-facing extensions require separate assessments.

This artifact makes no legal conclusion and does not rely on consent as a blanket substitute for a
proper authority, necessity, or rights analysis.

## Privacy principles and controls

| Principle | Polaris requirement |
|---|---|
| Purpose specification | Every sensitive operation carries an allowlisted purpose; secondary use is denied |
| Minimization | Field-level views, no full chart, no unrestricted corpus, minimum provider context |
| Transparency | System card, workforce notice, source/provenance UI, logging/feedback notice |
| Individual participation | Real deployment must define access/amendment/accounting/complaint workflows |
| Quality | Authoritative source ownership, freshness, patient-link validation, correction workflow |
| Use limitation | No training, marketing, workforce scoring, or unrelated analytics without review |
| Security | Strong identity, deny-default policy, separation, encryption design, audit, response |
| Retention limitation | Periods and deletion verification approved before pilot; provider retention aligned |
| Accountability | Owners, decisions, evidence, vendor flow-down, incident and exception records |

## LINDDUN-oriented privacy risks

| ID | Scenario | Impact | Treatment | Validation |
|---|---|---|---|---|
| PRI-01 | Stable identifiers link activity across purposes or systems | Surveillance, secondary use | Purpose-partitioned access, minimized identifiers, prohibit productivity scoring | Data-flow and audit review |
| PRI-02 | Shared/service identity obscures the person who accessed data | No accountability or patient accounting | Preserve end-user identity and token context | Identity propagation tests |
| PRI-03 | Audit trails expose sensitive patient/workforce activity broadly | Stigma, insider misuse | Metadata minimization, tiered access, alert and review logging | Log schema/privacy tests |
| PRI-04 | Errors or opaque provenance cannot be challenged | Wrong task/source persists | Source/version display, feedback, correction and appeal route | Human-factors tests |
| PRI-05 | Workforce/patients lack meaningful notice of AI processing | Loss of autonomy/trust | Layered notices, training, system limitations, non-AI fallback | Notice review/usability test |
| PRI-06 | Prompt, embeddings, caches, traces, or provider copies disclose data | Confidentiality harm | Minimize, no-training/retention terms, ACLs, isolation, DLP, deletion verification | Adversarial exfiltration tests |
| PRI-07 | Excess collection or long retention creates latent exposure | Breach and secondary use | Data inventory, field allowlists, retention schedule, deletion job/evidence | Retention/deletion tests |
| PRI-08 | Part 2 sensitivity/consent is lost through derived data or task text | Stigma/legal harm | Propagated labels, segregated policy, redact/minimize task, downstream controls | Sensitive-path matrix |
| PRI-09 | Language/accessibility differences produce privacy mistakes | Wrong patient/purpose/approval | Accessible UI, confirmations, plain language, alternative path | Representative usability tests |
| PRI-10 | Synthetic data contains copied or identifiable source material | Real privacy exposure hidden as test data | Approved generator/provenance, scans, no production imports | Dataset provenance review |

## Third parties and cross-border processing

Before any hosted model, telemetry, support, or cloud service processes data, Vendor Risk, Privacy,
Security, Legal, and Procurement approve: service role; data elements; purpose; region and transfers;
subprocessors; training/retention; deletion; security; incident notice; audit rights; model changes;
government requests; business continuity; return/export; termination; and BAA/DPA/contract terms.
Consumer accounts, default provider logging, and provider reuse for training are prohibited.

## Rights, complaints, and human review for a real pilot

Define how patients/workforce receive notice, ask questions, complain, request correction, exercise
applicable access/amendment/accounting rights, and obtain human review. The application must not
silently alter the designated record set or become the authoritative record. Product feedback must
not be confused with a formal privacy complaint or record correction.

## Retention decisions and privacy gate

Exact retention and deletion rules for each object in `NS-DAT-001` remain open. A pilot privacy gate
fails until periods, owners, legal holds, backups, provider copies, derived embeddings, and deletion
verification are approved and tested.

## Current determination

Development with generated synthetic data may continue under the documented controls. Real PHI,
Part 2 information, a hosted provider, workforce analytics, patient-facing use, or a new jurisdiction
requires Privacy/Legal review and an updated assessment before processing begins.

# NS-ASR-003 — M03 Simulated Control-Owner Review

**Review status:** Pass — simulation baseline only  
**Review date:** 2026-08-11  
**Decision scope:** M03 catalog baseline and continued local synthetic development  
**Not authorized:** Hosted model, real PHI, human pilot, clinical use, production, or external claims

## Integrity statement

This artifact records a role-based simulation of control-owner review. It does not assert that named
Northstar employees, counsel, clinicians, an independent assessor, or any real organization approved
the controls. A real deployment must replace role placeholders with attributable people and capture
their decisions under Northstar policy.

## Material reviewed

- 31 controls in `governance/control-library.json`;
- 28 verification definitions and 21 evidence definitions;
- 70 normative requirements, 25 registered risks, and 78 THR/PRI/MIS/HAZ scenarios;
- the authoritative framework registry and one-to-many mappings;
- generated JSON/Markdown coverage reports and CI drift enforcement;
- the control/evidence standard, AI system card, and exception, risk, and release templates; and
- all open M02 findings and `BLK-001` through `BLK-006`.

## Owner challenge

| Domain | Simulated accountable reviewer | Challenge performed | Disposition |
|---|---|---|---|
| Governance and claims | System Owner / Compliance | Do status and evidence rules prevent policy/design from being mislabeled as operating control or compliance? | Pass; explicit `implemented`/`partial`/`planned` semantics and non-claims retained |
| Data and privacy | Data Steward / Privacy / Records | Are lifecycle, derived-data, label, minimization, provider, and secondary-use obligations visible? | Pass with BLK-001; retention/deletion remains a pilot blocker |
| Identity and authorization | IAM Lead | Do requirements cover delegation, context, deny-default attributes, privilege, revocation, and TOCTOU? | Pass as design; enterprise OIDC/delegation evidence remains BLK-002 |
| Retrieval and model | AI Platform / Data / AI Security | Are content, corpus, context, provider, memory, tool, validation, and resource risks controlled without trusting the model? | Pass for baseline; production RAG/model/provider controls remain partial/planned |
| Action integrity | Engineering / Product | Are proposal, independent approval, binding, execution, recovery, and fatigue treated separately? | Pass; accessible trusted rendering and workload evidence remain BLK-003 |
| Application and SDLC | AppSec | Are input/output, API, secrets/configuration, supply chain, evaluation, and adversarial gates represented? | Pass; production security suite and attestation remain planned |
| Clinical safety and human factors | Clinical Safety / Accessibility | Are prohibited clinical scope, emergency behavior, comprehensible state, accessibility, monitoring, and stop thresholds release-gated? | Pass with BLK-003; no clinical-validation claim |
| Operations and resilience | SRE / IR | Are audit, detection, response, kill, rollback, degraded mode, restore, and reconciliation separately testable? | Pass with BLK-005; operating evidence remains planned |
| Vendor and external frameworks | Vendor Risk / Legal / AI Security | Are provider decisions gated and framework mappings sourced without implying conformity? | Pass with BLK-004 and BLK-006; OWASP LLM 2026 exact categories remain provisional |
| Lifecycle and training | Product / Workforce / Compliance | Are competence, support, complaint/correction, lab safety, fallback, and retirement covered? | Pass as planned lifecycle controls |

## Automated integrity result

The typed validator passes with:

- 70 of 70 requirements assigned accountability and linked to risks, controls, verification,
  evidence, implementation, and framework references;
- 25 of 25 registered risks linked to controls, including every critical/high inherent risk;
- 78 of 78 threat, privacy, misuse, and clinical-safety scenarios linked to registered risks;
- all current implementation, verified test, document-review, evidence, and framework references
  resolving; and
- a deterministic generated report checked for staleness in CI.

This is structural and local assurance. It does not establish that partial/planned controls operate,
that a risk's residual rating changed, or that any exception/residual risk was approved.

## Findings

| Finding | Severity | Disposition |
|---|---|---|
| FND-M03-001 — Real owner names and attributable approvals are absent by design in the public simulation. | High for real deployment | Blocks pilot/production; retain role-based simulation label |
| FND-M03-002 — Six explicit blockers remain, covering lifecycle, enterprise adapters, human factors, provider review, operations, and a provisional external mapping. | High/Moderate | Retain as `BLK-001`–`BLK-006`; no silent closure |
| FND-M03-003 — Framework references are control-support mappings, not complete conformity assessments. | Moderate | Mapping notice and system-card non-claims accepted |
| FND-M03-004 — The CI workflow exists but has not run on a hosted repository. | Moderate | Keep hosted-CI status `Not assessed` until evidence exists |

## Decision

M03 **passes as a simulated control-system baseline**. The control statements and evidence
expectations are sufficiently testable for M04 design and local implementation to begin. This does
not waive any blocker and authorizes no new data, provider, model, tool, integration, user, or
autonomy scope.

The next safe increment is M04 identity/policy/synthetic-FHIR architecture and implementation. It
must preserve the deterministic baseline, introduce no real PHI, and produce enterprise-shaped
delegation, authorization, label, revocation, and failure evidence before the M04 gate can pass.

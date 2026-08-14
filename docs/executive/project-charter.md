# NS-CHR-001 — Project Polaris Charter and Business Case

**Artifact status:** Draft for simulated Gate 1 approval  
**Executive sponsor:** Chief Strategy and Digital Officer  
**Business owner:** Vice President, Care Coordination  
**System owner:** Vice President, Digital Platforms  
**Security owner:** Director, AI Security  
**Last updated:** 2026-08-11

## Purpose

Project Polaris will design, build, evaluate, and govern a constrained internal AI assistant that helps authorized Northstar workforce members find approved operational guidance, retrieve minimal synthetic patient context, and create approval-gated non-clinical follow-up tasks.

The project is also a portfolio and training reference implementation demonstrating complete, evidence-driven AI security engineering.

## Problem statement

Care coordinators and nurses spend time locating current policies and manually preparing routine follow-up work. Uncontrolled generative-AI adoption could create data leakage, misinformation, excessive agency, and accountability gaps. Northstar needs a bounded use case that creates measurable value while establishing reusable governance and technical controls.

## Objectives

| ID | Objective | Success measure |
|---|---|---|
| OBJ-001 | Improve policy discovery | At least 30% lower median simulated task time versus the baseline scenario |
| OBJ-002 | Improve answer traceability | Every substantive policy answer cites an approved source or abstains |
| OBJ-003 | Prevent unauthorized data access | Zero successful critical-suite cross-patient, cross-facility, cross-role, or wrong-purpose accesses |
| OBJ-004 | Bound agent actions | Zero state changes without deterministic authorization and valid action-bound approval |
| OBJ-005 | Establish lifecycle governance | Every release requirement links to a risk, control, implementation, test, owner, and evidence object |
| OBJ-006 | Demonstrate operational readiness | Kill switch, rollback, incident, backup/recovery, and provider-exit exercises completed before simulated production approval |
| OBJ-007 | Produce portfolio evidence | A reproducible repository and seven-minute recruiter demo explain tradeoffs and residual risk |
| OBJ-008 | Enable training conversion | Each lifecycle phase produces an adaptable lesson and hands-on lab outline |

Targets are simulation acceptance criteria, not performance claims about a deployed health system.

## Primary users

- Care coordinator: retrieves policies and minimal assigned-patient context; proposes follow-up tasks.
- Registered nurse: retrieves policies and assigned-patient context; drafts administrative follow-up content.
- Task approver: reviews exact action details and independently approves or rejects.
- Security/privacy analyst: reviews authorization, audit, alerts, and incidents.
- AI system owner: reviews performance, change, risk, and release evidence.

## In scope for v1

- Workforce-authenticated web experience and API
- Deterministic baseline model adapter and later provider-neutral hosted-model adapter
- Approved-policy ingestion, provenance, retrieval, citations, and abstention
- Read-only retrieval of minimal synthetic FHIR patient context
- Role, facility, patient, purpose, and sensitivity-aware authorization
- Typed proposal of a non-clinical follow-up task
- Independent human approval bound to the exact action and expiry
- Execution-time reauthorization, idempotency, and audit
- Security-safe telemetry, monitoring scenarios, incident playbooks, rollback, and retirement
- Secure SDLC, assurance, red-team, governance, audit, recruiter, and training artifacts

## Out of scope for v1

- Real PHI, PII, production secrets, or a connection to a real EHR
- Patient-facing chatbot, voice interface, or ambient recording
- Diagnosis, prescribing, treatment recommendation, emergency triage, or clinical decision support
- Autonomous EHR updates or patient messages
- General internet browsing, email access, shell access, filesystem access, code execution, or generic SQL tools
- Cross-session memory and self-modifying behavior
- Multi-agent orchestration
- Model fine-tuning on patient information
- Formal HIPAA, SOC 2, ISO, HITRUST, ONC, or FDA certification or submission
- Production cloud deployment in a real Northstar environment

## Principal deliverables

1. Executive and governance package
2. Regulatory/standards applicability and canonical control library
3. Requirements traceability and architecture package
4. Working secure reference implementation with synthetic data
5. Threat, privacy, misuse, and safety-hazard models
6. Automated assurance and adversarial test suites
7. Operational monitoring, incident, resilience, and retirement package
8. Evidence ledger and simulated release decision
9. Recruiter case study and demonstration
10. Training syllabus, lab plan, instructor assets, and licensing register

## Constraints

- Initial development must run locally without an external model API key.
- The project is built by one primary contributor using Codex, so phase gates control scope.
- Current facts about laws, standards, software, models, and vendors require primary-source verification and access dates.
- Public artifacts must not expose sensitive local details, secrets, exploit chains, or third-party copyrighted material beyond applicable license terms.
- Hosted-model and cloud decisions require later architecture and vendor-risk records.

## Milestones and gates

| Gate | Decision | Minimum evidence |
|---|---|---|
| G0 | Program foundation | Durable instructions, status, roadmap, evidence conventions |
| G1 | Use-case intake approval | Charter, scope, RACI, risk tier, applicability, initial risk register |
| G2 | Architecture approval | Requirements, DFDs, threat/privacy/safety models, ADRs, control design |
| G3 | Secure foundation acceptance | Identity, policy, audit, configuration, telemetry, CI tests |
| G4 | Agent/tool acceptance | Retrieval and action invariants pass negative and adversarial tests |
| G5 | Assurance release | Evaluation and red-team criteria met; no unresolved critical/high findings |
| G6 | Simulated production approval | Operations, incident, resilience, residual risk, owner signoffs |
| G7 | Closure and retirement | Audit, deletion, revocation, provider exit, lessons learned |

## Business case

The expected value is a reusable safe-adoption pattern, not merely a chatbot. A successful pilot would reduce routine information-search time, improve policy traceability, reduce shadow-AI pressure, and create standardized controls reusable by future Northstar AI use cases.

The principal costs are engineering, governance, evaluation, integration, security operations, clinical review, vendor services, and change management. The project will maintain a later total-cost model covering build, inference, storage, telemetry, testing, licensing, support, incident readiness, and exit.

## Stop conditions

Pause or stop the simulated rollout if:

- The use case crosses into clinical decision support without a new assessment.
- A critical authorization, privacy, safety, or action-integrity invariant cannot be evidenced.
- A provider cannot meet contractual data-use, retention, security, incident, or exit requirements.
- Monitoring cannot distinguish unauthorized or unsafe behavior.
- The benefit hypothesis fails the pilot threshold or introduces unacceptable workflow burden.


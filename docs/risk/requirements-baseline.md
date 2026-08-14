# NS-REQ-001 — Security, Privacy, Safety, and Assurance Requirements Baseline

**Status:** M02 reviewed simulation baseline; M03 traceability validated  
**Owner:** AI Security Program Lead  
**Date:** 2026-08-11  
**Normative terms:** `MUST` is release-blocking; `SHOULD` needs documented exception; `MAY` is optional

These are outcome requirements, not claims of current implementation. M03 will assign canonical
Northstar control IDs and map each requirement to risks, framework references, implementation,
tests, evidence, owner, and residual-risk decision.

## Governance and accountability

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-GOV-001 | Polaris MUST have named business, system, data, security, privacy, clinical-safety, and operations owners. | Approved RACI and inventory record |
| REQ-GOV-002 | Approved/prohibited uses, populations, data, tools, autonomy, and deployment boundaries MUST be technically and procedurally enforced. | Policy, architecture, negative tests |
| REQ-GOV-003 | A material change to model, prompt, corpus, policy, tool, data, provider, population, jurisdiction, or autonomy MUST trigger impact review and versioned evaluation. | Change record and release manifest |
| REQ-GOV-004 | Exceptions MUST identify scope, owner, rationale, compensating controls, residual risk, approver, and expiry. | Exception record and expiry alert |
| REQ-GOV-005 | Public/internal claims MUST trace to evidence and MUST NOT assert compliance, certification, clinical validity, or production readiness without authority. | Claims review checklist |
| REQ-GOV-006 | Kill, rollback, suspension, and retirement authority MUST be assigned independently of the model/provider. | RACI plus exercise evidence |

## Data and privacy

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-DAT-001 | This repository MUST contain only generated synthetic patient data with provenance and clear labeling. | Dataset inventory/provenance scan |
| REQ-DAT-002 | Every data element, source, destination, purpose, classification, owner, retention, and deletion path MUST be inventoried before pilot. | Approved processing inventory |
| REQ-DAT-003 | Sensitive retrieval MUST be minimized to fields necessary for the authorized task; full chart retrieval is prohibited by default. | Field allowlist and response tests |
| REQ-DAT-004 | Sensitivity, consent, tenant/facility, patient, purpose, and provenance labels MUST survive ingestion, retrieval, caching, model context, output, action, audit, and deletion flows. | End-to-end lineage tests |
| REQ-DAT-005 | Raw restricted prompts/responses, FHIR resources, secrets, tokens, and hidden model reasoning MUST NOT enter routine logs or traces. | Telemetry schema and canary tests |
| REQ-DAT-006 | Secondary use for training, marketing, workforce scoring, or unrelated analytics MUST be denied absent a new approved assessment. | Policy tests and data-use review |
| REQ-DAT-007 | Retention, legal hold, deletion, backup expiry, and provider deletion MUST be defined and testable per data object. | Records approval and deletion evidence |
| REQ-DAT-008 | Export, feedback, evaluation, and support datasets MUST be minimized, access controlled, and separately approved. | Data export controls and audit |

## Identity and authorization

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-IAM-001 | Production identity MUST use enterprise OIDC with validated signature, issuer, audience, expiry, token ID, and required claims; algorithms MUST be allowlisted. | OIDC contract and negative tests |
| REQ-IAM-002 | Sensitive operations MUST carry authenticated end-user identity and declared/validated purpose through every downstream decision. | Trace and downstream audit tests |
| REQ-IAM-003 | Authorization MUST deny by default using role, facility/organization, patient relationship, purpose, sensitivity/consent, resource, operation, tool, and environment. | Complete decision matrix |
| REQ-IAM-004 | The model, prompt, retrieved content, or client MUST NOT grant, alter, or waive authorization. | Injection-plus-authorization tests |
| REQ-IAM-005 | Shared/broad service identity and token passthrough MUST NOT substitute for user delegation; downstream tokens MUST be audience/resource bound and short lived. | Wrong-audience/scope tests |
| REQ-IAM-006 | Privileged administration and approval MUST use separate roles, step-up where risk warrants, least privilege, and attributable audit. | Role design and privileged-use test |
| REQ-IAM-007 | Revocation, role/assignment/consent change, and terminated sessions MUST take effect within approved bounds and be rechecked for writes. | Revocation/TOCTOU tests |

## Retrieval and model context

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-RAG-001 | The index MUST contain only owner-approved, malware/content-reviewed, classified, versioned, checksummed, and attributable sources. | Ingestion promotion record |
| REQ-RAG-002 | Access control MUST execute before any sensitive chunk enters model context and MUST be rechecked after retrieval where feasible. | Cross-resource canary tests |
| REQ-RAG-003 | Retrieved/user/FHIR/tool text MUST be labeled and treated as untrusted data, never executable instruction. | Context template and stored-injection tests |
| REQ-RAG-004 | Policy answers MUST use server-verifiable approved citations and source versions or explicitly abstain. | Citation/golden/abstention evaluation |
| REQ-RAG-005 | Conflicting, expired, revoked, or low-provenance sources MUST be excluded or surfaced through a defined safe conflict process. | Conflict/freshness tests |
| REQ-RAG-006 | Vector/index partitions, metadata, cache, backup, and export MUST enforce the same classification and authorization boundaries as source data. | Store policy and isolation tests |
| REQ-RAG-007 | Corpus/index versions MUST be immutable for evaluation and independently rollback-capable. | Corpus manifest and rollback drill |

## Model, orchestration, and tools

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-AI-001 | Model access MUST be behind a typed provider-neutral adapter; credentials MUST remain in a trusted broker and never in model context. | Interface review and secret-canary test |
| REQ-AI-002 | Model/provider use MUST meet approved data-use, no-training, retention, region, subprocessor, security, change-notice, incident, audit, continuity, and exit criteria. | Vendor decision and contract matrix |
| REQ-AI-003 | Orchestration MUST be an explicit bounded state machine with caps for input/output tokens, steps, tools, fan-out, time, concurrency, retries, and cost. | State tests and resource-exhaustion evidence |
| REQ-AI-004 | Persistent cross-session memory MUST remain disabled in v1; any future write MUST be privileged, scoped, reviewable, expiring, and reassessed. | Configuration and negative test |
| REQ-AI-005 | Tools MUST be statically approved, typed, narrowly scoped, versioned, authenticated, independently authorized per call, and separated into read and write capabilities. | Tool registry/control tests |
| REQ-AI-006 | Generic shell, code execution, browser, filesystem, database, email, and unrestricted network tools MUST NOT be present in v1. | Runtime inventory and negative test |
| REQ-AI-007 | Model output MUST receive structural, semantic, authorization, data-loss, citation, and clinical-safety validation before use. | Validator test suite |
| REQ-AI-008 | Model, provider, prompt, and tool failures MUST degrade safely without fabricated success or bypassed control. | Fault-injection scenarios |

## Actions and human oversight

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-ACT-001 | The model MUST be limited to proposing only allowlisted, reversible, non-clinical administrative actions with strict arguments. | Schema and prohibited-action tests |
| REQ-ACT-002 | Every write MUST have an independent authorized human approval displaying the complete canonical action through a trusted accessible renderer. | Role/UI/human-factors evidence |
| REQ-ACT-003 | Approval MUST be cryptographically bound to canonical arguments, requester, approver, decision, policy/version, and expiry using purpose-separated key material. | Mutation/signature tests |
| REQ-ACT-004 | Execution MUST validate receipt integrity, exact digest, expiry, single use/idempotency, executor, current requester authorization, current policy, and destination. | Full execution matrix |
| REQ-ACT-005 | Rejection, cancellation, timeout, downstream failure, and unknown outcome MUST be explicit, auditable, and safely recoverable. | State/failure/reconciliation tests |
| REQ-ACT-006 | Approval workload and rate MUST be monitored to prevent fatigue, bulk rubber-stamping, or denial of service. | Metrics, thresholds, usability/load tests |

## Application and API security

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-APP-001 | All external input MUST use strict type/schema/size/canonicalization validation; ambiguous or missing security context MUST fail closed. | Fuzz/boundary/negative tests |
| REQ-APP-002 | Model/retrieved output MUST render as inert data with contextual encoding, restrictive CSP, no remote active content, and safe link handling. | Browser XSS/CSP/exfiltration tests |
| REQ-APP-003 | API resources MUST prevent BOLA/IDOR, mass assignment, injection, replay, request smuggling, and unsafe error disclosure. | API security suite |
| REQ-APP-004 | Security keys/secrets MUST be purpose-separated, managed outside source/prompts/logs, rotated, and inaccessible to the model. | Configuration policy and rotation drill |
| REQ-APP-005 | Rate limits, quotas, timeouts, backpressure, duplicate suppression, and circuit breakers MUST protect users, dependencies, cost, and care operations. | Load/fault/denial-of-wallet tests |
| REQ-APP-006 | Development bypass/debug behavior MUST be impossible to enable silently in production. | Production configuration negative tests |

## Safety, human factors, and accessibility

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-SAF-001 | Diagnosis, prescribing, treatment recommendation, emergency triage, autonomous clinical decision/write, and patient communication MUST be blocked in v1. | Clinician-reviewed adversarial suite |
| REQ-SAF-002 | Urgent/emergency language MUST trigger fixed established-channel guidance and no autonomous action; the system MUST NOT assess urgency. | Emergency scenario tests |
| REQ-SAF-003 | The UI MUST distinguish draft/proposal/approved/executed/failed states and MUST NOT imply completion before trusted confirmation. | UX/state/failure tests |
| REQ-SAF-004 | Patient identity, source/version, uncertainty, destination, exact action, and material changes MUST be understandable at decision points. | Comprehension and automation-bias study |
| REQ-SAF-005 | The supported workflow and approval MUST meet current Northstar accessibility target (at least WCAG 2.2 AA design target) with a non-AI alternative. | Automated/manual accessibility evidence |
| REQ-SAF-006 | Safety events, near misses, complaints, overrides/edits, abstention, source defects, and subgroup performance MUST be monitored with approved stop thresholds. | Safety dashboard and gate record |

## Logging, detection, response, and resilience

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-OPS-001 | Security/audit events MUST capture correlation, actor, purpose, resource/action reference, policy/model/prompt/corpus/tool versions, decision, approval, and result without prohibited content. | Event schema and content tests |
| REQ-OPS-002 | Audit evidence MUST be tamper evident, time synchronized, access controlled, retained, searchable, and exportable for investigation. | Chain/signature/access/gap tests |
| REQ-OPS-003 | Detection MUST cover identity abuse, enumeration, cross-scope attempts, injection/poison canaries, DLP, abnormal tool/action volume, resource exhaustion, drift, and control disablement. | Detection-as-code tests and tuning record |
| REQ-OPS-004 | Incident playbooks MUST address data disclosure, injection/agent compromise, poisoning, provider/model compromise, unsafe output/action, outage, and supply-chain compromise. | Tabletop and after-action record |
| REQ-OPS-005 | Model/read/write capabilities MUST have independent kill switches; provider, prompt, policy, corpus, tool, and release rollback MUST be tested. | Game-day objective evidence |
| REQ-OPS-006 | SLOs, RTO/RPO, safe degraded mode, manual fallback, backup/restore, reconciliation, and dependency failure behavior MUST be approved for care operations. | Resilience exercise and restore proof |

## Secure development, supply chain, and assurance

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-SDL-001 | Source changes MUST receive review, required tests, secret/SAST/SCA scanning, and protected-branch release gates. | CI/policy records |
| REQ-SDL-002 | Dependencies and CI actions MUST be locked or immutable-SHA pinned; build artifacts MUST have SBOM/AIBOM, provenance, vulnerability results, and signatures before promotion. | Release supply-chain bundle |
| REQ-SDL-003 | Release evaluation MUST cover function, authorization, privacy, security, safety, grounding, robustness, accessibility, performance, cost, and recovery with versioned datasets/thresholds. | Evaluation report and manifest |
| REQ-SDL-004 | Adversarial testing MUST cover direct/indirect/stored/obfuscated injection, exfiltration, poisoning, tool/identity abuse, action mutation/replay, output injection, and consumption. | Red-team plan/results/retest |
| REQ-SDL-005 | A release MUST NOT proceed with an open critical/high gate blocker; accepted residual risk MUST be named, evidence-based, time-bound, monitored, and approved. | Risk/gate decision |
| REQ-SDL-006 | Evidence MUST be reproducible, minimal, public-safe where published, and traceable to a revision, configuration, test corpus, owner, and decision. | Evidence registry sampling |

## Training, support, and retirement

| ID | Requirement | Acceptance/evidence |
|---|---|---|
| REQ-LCM-001 | Users, approvers, operators, responders, developers, and auditors MUST receive role-specific limitations, safe-use, escalation, and incident training. | Training completion and assessment |
| REQ-LCM-002 | Users MUST have support, feedback, correction, privacy complaint, safety report, and non-AI fallback paths. | Service design and journey tests |
| REQ-LCM-003 | Training labs MUST use isolated synthetic targets, explicit authorization/rules of engagement, resets, and no real credentials/data. | Lab safety checklist |
| REQ-LCM-004 | Retirement MUST revoke access/credentials, stop providers/tools, export required records, delete data/embeddings per schedule, dispose artifacts, update inventory, and verify downstream termination. | Approved retirement and deletion evidence |

## Baseline gate

The M03 traceability report demonstrates that every `MUST` has an accountable role, related risks,
control, verification, evidence, lifecycle phase, and disposition. This satisfies the structural
M02 simulation gate; it is not actual owner approval or evidence that partial/planned controls
operate. Requirements may be deferred only through the explicit exception process.

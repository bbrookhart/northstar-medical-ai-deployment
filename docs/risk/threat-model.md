# NS-THR-001 — Project Polaris Security Threat Model

**Method:** Data-flow-centered STRIDE plus AI/agent abuse analysis  
**Status:** M02 baseline  
**Owner:** AI Security  
**Reviewers:** Architecture, AppSec, IAM, Privacy, Clinical Safety, Data, SRE, SOC  
**Date:** 2026-08-11

## Security objective

Preserve authorized confidentiality, integrity, availability, privacy, and traceability even when a
user, retrieved document, tool result, model output, dependency, provider, or integration is
malicious or wrong. A manipulated model must not gain authority to access data or cause an action.

## Scope and assumptions

In scope: browser/API, identity claims, policy evaluation, retrieval/ingestion, synthetic FHIR read,
model adapter, bounded workflow, proposal/approval/execution, task service, audit/telemetry,
configuration, CI/supply chain, operators, and future hosted provider boundary.

Assumptions to validate before pilot: managed devices; enterprise OIDC/MFA; approved network and
secret stores; accurate facility/patient assignment/consent attributes; authoritative policy owners;
contracted providers; staffed SOC/on-call; and tested manual fallback. The local implementation is
not evidence that these enterprise controls exist.

Out of scope only for current implementation—not ignored risks: real PHI, clinical recommendation,
patient communication, autonomous EHR writes, persistent memory, multimodal input, and multi-agent
delegation. Scope-change triggers reopen this model.

## Assets and security properties

| Asset | Confidentiality | Integrity | Availability/traceability |
|---|---|---|---|
| Workforce identity/session | Token and claims protected | Subject/audience/scope authentic; no confused deputy | Revocable; decision attributable |
| Patient/policy data | Only authorized minimum | Correct patient, provenance, label, version | Available with safe fallback; access audited |
| Policy and control configuration | Limited administrators | Reviewed, versioned, deny-default | Rollback and decision version available |
| Prompts/context/model output | Restricted by included data | Trust/source labels preserved; output untrusted | Bounded; transaction correlatable |
| Action and approval | Exact content protected | Canonical digest, independent receipt, single use | Expiry, idempotency, complete history |
| Credentials/signing material | Never exposed to model/user | Separate purpose-bound keys | Rotatable without silent bypass |
| Audit/evidence | Minimized sensitive content | Append/tamper evidence and time integrity | Searchable, retained, exportable for response |
| Build/model/corpus artifacts | Controlled distribution | Provenance, version, scan, approval | Reproducible and rollback-capable |

## Threat actors

- Unauthorized internet actor, compromised user device, stolen session, or malicious insider
- Authorized but curious, careless, coerced, or over-trusting workforce member
- Malicious policy/content contributor or poisoned external data source
- Compromised dependency, model, tool/MCP server, CI action, container, or model repository
- Hosted-provider administrator, subprocessor, compromised provider plane, or unexpected model change
- Faulty model, integration, policy, data pipeline, clock, queue, or human approver without malicious intent

## Attack surface and STRIDE analysis

| ID | Component/flow | STRIDE | Threat scenario | Required prevention/containment | Detection and test |
|---|---|---|---|---|---|
| THR-001 | Browser/session | S/E | Stolen token or session impersonates worker | OIDC/MFA, managed session, issuer/audience/expiry, CSRF design, step-up | Invalid/expired/replayed token tests; IdP/SIEM alert |
| THR-002 | Claims/attributes and identity signals | S/T/E/D | Client, stale source, spoofed transmitter, substituted management endpoint/response, extra receiver audience, redirected push destination, dropped required events, malicious subject mutation, leaked verification state, or forged/oversized/replayed/reordered/wrong-stream signal preserves access, leaks events, steals credentials, or creates false health | Signed claims, short TTL, critical-attribute lookup, transmitter authentication before cryptography, exact discovery/issuer/origin/audience/push/event binding, `events_delivered` completeness, explicit no-default subjects, fixed-issuer bounded subject calls with no invented verification, non-enumerating acknowledgements, secret-safe management calls, hashed single-use correlation, expiry, stream/media/body/rate limits, durable invalidation and replay/gap/freshness controls | Claim matrix plus discovery/config/status/subject/origin/redirect/auth/audience/delivery/event/verification receipt/race/timeout/reuse/tamper/size/confusion/replay/order/restart/staleness tests |
| THR-003 | Purpose header | T/R | User declares treatment/operations to hide curiosity access | Allowlisted purpose tied to workflow and role; anomaly review | Purpose mismatch and unusual-access detection |
| THR-004 | API objects | T/D | Oversize, malformed, duplicate, Unicode, or race payload bypasses validation | Strict schema, canonicalization, limits, concurrency control, fail closed | Fuzz/property/boundary and race tests |
| THR-005 | Direct model input | T/E | Prompt injection changes goal, reveals context, or requests tools | Treat model as compromised; no authority/credentials; bounded state; validators | Injection/jailbreak corpus; invariant assertions |
| THR-006 | Retrieved/FHIR content | T/E | Stored/indirect/multimodal instruction hijacks workflow | Content/instruction separation, provenance/trust labels, no content-derived permissions | Stored/encoded/invisible/cross-language injection tests |
| THR-007 | Retrieval filter | I/E | Model or user broadens ACL, metadata, tenant, patient, or purpose | Application/data-tier filters before context; post-filter; isolated caches | Cross-resource matrix; canary documents |
| THR-008 | Vector/embedding store | I/T | Membership inference, nearest-neighbor leakage, metadata/embedding exposure | Class/tenant partitions, row policy, encryption, export limits, sensitivity propagation | Unauthorized similarity queries; export review |
| THR-009 | Ingestion/corpus | T | Poisoned, obsolete, conflicting, or unapproved source is indexed | Owner approval, provenance/checksum, malware/content scan, version/rollback, conflict policy | Poison/canary/freshness/citation tests |
| THR-010 | FHIR read broker | I/E | IDOR/BOLA or broad service credential returns another record | End-user delegation, patient/facility/purpose/sensitivity policy, field allowlist | Full authorization matrix and service-scope test |
| THR-011 | Part 2 labels | T/I | Sensitive label/consent is stripped in transform, cache, output, or task | Label propagation, separate policy, default deny, downstream minimization | End-to-end sensitive-data lineage tests |
| THR-012 | Model/provider request | I | Context, identity, secret, or metadata leaks to provider/subprocessor | Minimum context, credential exclusion, contract/region/retention controls, egress | Payload inspection, DLP canaries, provider audit |
| THR-013 | Model/provider response | T | Hallucination, forged citation, hidden markup, unsafe clinical content | Typed output, source verification, clinical/semantic validation, encoding | Golden/adversarial/citation/XSS tests |
| THR-014 | Tool registry/description | T/E | Malicious tool or description changes goal or captures data | Approved static registry, signed/versioned metadata, least tools, no dynamic discovery by default | Registry diff/signature and tool-poison tests |
| THR-015 | Tool broker | E | Prompt chooses unauthorized function/arguments or chains privilege | Policy per call, typed allowlist, end-user context, separate read/write, budgets | Tool authorization/sequence/state-machine tests |
| THR-016 | Credentials | I/E | Token passthrough, confused deputy, long-lived or shared credential | Audience/resource-bound short-lived identity, brokered secrets, no model access | Wrong-audience/downstream-scope/secret-scan tests |
| THR-017 | Proposal | T | Action differs from visible/reviewed content | Canonical schema/digest, trusted renderer, normalized content | Mutation, hidden-character, canonicalization tests |
| THR-018 | Approval | S/R/E | Self approval, stolen approver session, fatigue, stale or bulk approval | Independent role, step-up, exact diff, rate/risk thresholds, expiry, audit | Self/wrong-role/expired/bulk/usability tests |
| THR-019 | Receipt/execution | T/R/E | Forged/replayed receipt or time-of-check/time-of-use change | Separate signing key, exact digest, single use, idempotency, current auth/policy, transaction | Signature/replay/race/policy-change tests |
| THR-020 | Task service | T/D | Duplicate, excessive, cross-facility, or malicious downstream task | Narrow service scope, quotas, idempotency, schema/outcome verification | Duplicate/flood/facility/rollback tests |
| THR-021 | UI rendering | T/I | Markdown/HTML/URL output causes XSS, request forgery, deceptive preview, exfiltration | Encode as data, restrictive CSP, no remote model content, trusted preview component | Browser XSS/CSP/link/image/accessibility tests |
| THR-022 | Logs/traces | I/R | Raw data/secrets leak or attacker erases/misattributes event | Allowlist schema, redaction, append/tamper evidence, protected time/sink, RBAC | Log-content, tamper, gap, clock, access tests |
| THR-023 | Resource control | D | Token/step/tool/fan-out loop causes cost spike, queue storm, or outage | Budgets, quotas, deadlines, circuit breakers, cancellation, backpressure | Load/soak/denial-of-wallet/loop tests and alerts |
| THR-024 | Dependency/build | T/E | Malicious package/action/image/model or CI compromise reaches runtime | Locked deps, SHA-pinned actions, least CI permissions, scans, SBOM/AIBOM, signed provenance | SCA/SAST/secret/container/IaC scan; verify signature |
| THR-025 | Configuration/secrets | I/T/E | Default/bypass/debug config or key reuse weakens controls | Typed required config, distinct keys, managed secrets, environment gates, rotation | Startup-negative/config-policy/secret scanning |
| THR-026 | Provider/change | T/R | Silent model/prompt/corpus/policy/tool change invalidates evaluation | Immutable version IDs, change diff/owner, regression, canary, rollback | Drift detection and release-manifest comparison |
| THR-027 | Admin/insider | I/T/R | Privileged user exports data, relaxes policy, or alters evidence | Separation, JIT admin, approval, immutable logs, anomaly detection, sanctions | Admin-use review and insider scenarios |
| THR-028 | Availability dependency | D | IdP/FHIR/policy/model/task/SIEM failure produces unsafe behavior | Dependency health, timeouts, safe degradation, manual fallback, recovery objectives | Fault injection, backup/restore, regional/provider rollback |
| THR-029 | Kill/rollback | T/D | Compromised system prevents shutdown or leaves queued actions active | Independent capability flags, revoke credentials, drain/cancel queues, tested rollback | Game day with objective stop-time evidence |
| THR-030 | Evidence/claims | R | Incomplete evidence or overstated compliance conceals residual risk | Stable IDs, traceability, independent review, claims approval, time-bound exceptions | Evidence sampling and public-release checklist |

## High-value attack trees

### Goal: expose another patient's information

Attacker may steal a user session; forge or exploit stale assignment attributes; enumerate patient IDs;
inject a retrieval filter; poison metadata; exploit cache/embedding isolation; abuse a broad service
identity; induce the model to echo hidden context; exploit rendered external content; or read logs.
The control strategy therefore spans identity, relationship/purpose policy, pre-context authorization,
isolation, minimum fields, output controls, and telemetry—not prompt filtering alone.

### Goal: cause an unauthorized state change

Attacker may hijack the model goal; poison a tool description; submit clinical/hidden arguments;
self-approve; deceive or fatigue an approver; mutate the action after review; forge/replay a receipt;
race a policy/assignment change; abuse executor credentials; or flood duplicate tasks. The required
chain is typed allowlist → propose-only model → policy → exact preview/digest → independent expiring
approval → signature → current authorization/policy → idempotent transactional execution.

### Goal: persist compromise across releases or sessions

Attacker may poison corpus/embeddings/memory; insert a malicious dependency/action/model; change
provider behavior; alter prompt/policy/config; compromise CI signing; or delete evidence. Persistent
memory is disabled in v1. Artifacts require provenance/version, gated promotion, detection, and rollback.

## Residual risk and design truth

Prompt injection and model error cannot be assumed eliminated. Residual risk is reduced by minimizing
what a compromised model can see and do. Local OIDC, durable SSF/CAEP-style invalidation, strict
transmitter discovery/status/verification-request handling, and synthetic FHIR/HAPI controls now
have bounded test evidence. Correlated verification receipt, timeout, and health plus explicit
default-reject/opt-in delivery-only unsolicited verification and durable quota now have local test
evidence. A durable local status-recovery cadence/lease/alert-state controller now suppresses
duplicate workers, reclaims crashed leases, rejects stale completion, and escalates unresolved
cycles; workflow/audit transitions have single-node transactional durability. Enterprise
identity/delegation/signal transport, live-provider stream lifecycle, approved unsolicited-event
enablement/flood controls, gap recovery, deployed scheduler/alert delivery, authoritative entitlements/consent, hosted providers, vector
retrieval, UI, production persistence/backup, and external-task reconciliation remain unimplemented; their threats stay open
until those controls and tests exist. No risk status changes based only on this document.

## Required assurance campaigns

Identity/authorization matrix; direct/indirect/stored/encoded/multilingual injection; cross-patient
and Part 2 exfiltration; corpus/tool poisoning; citation and clinical-boundary evaluation; approval
deception/mutation/replay/race; resource exhaustion; output/XSS; log leakage/tamper; supply-chain
verification; provider/corpus/policy drift; dependency failure; kill switch; backup/restore; and an
independent red-team retest after remediation.

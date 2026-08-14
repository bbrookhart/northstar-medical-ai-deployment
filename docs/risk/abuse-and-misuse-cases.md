# NS-MIS-001 — Abuse, Misuse, and Dual-Use Cases

**Status:** M02 baseline  
**Owners:** AI Security and Business Owner  
**Reviewers:** Privacy, Clinical Safety, SOC, Legal/Compliance, Workforce  
**Date:** 2026-08-11

## Personas

- Malicious outsider with no account or a stolen session
- Malicious or curious workforce member with legitimate access
- Careless or over-trusting user/approver
- Malicious content/data/tool contributor
- Compromised provider, integration, dependency, or administrator
- Well-intentioned user attempting an out-of-scope clinical shortcut

## Priority abuse cases

| ID | Actor goal and path | Potential harm | Prevention/containment | Detection/evidence |
|---|---|---|---|---|
| MIS-01 | Enumerate patient IDs and compare denial behavior | Patient disclosure and inference | Opaque resource denial, assignment/facility/purpose policy, rate limit | Enumeration/anomaly alert; cross-patient tests |
| MIS-02 | Claim an allowed purpose for curiosity access | Insider privacy violation | Workflow-bound purpose, least privilege, behavioral review, sanctions/training | Purpose/access outlier and audit sampling |
| MIS-03 | Inject “ignore policy” in query to retrieve more data | Cross-scope disclosure | Prompts never set authorization; pre-context policy | Injection plus auth-invariant test |
| MIS-04 | Plant instructions in policy/FHIR narrative | Goal hijack, data exfiltration, wrong action | Approved ingestion, trust labels, no model authority, output/tool controls | Stored injection canaries and source review |
| MIS-05 | Use encoded, multilingual, invisible, split, or multimodal payload | Filter evasion and unsafe behavior | Canonicalization, modality controls, compromised-model architecture | Mutation corpus and telemetry |
| MIS-06 | Ask for diagnosis, medication change, treatment, or triage | Direct clinical harm or delayed care | Deterministic scope classifier, fixed emergency path, no clinical tools | Clinical boundary test set and sampling |
| MIS-07 | Phrase clinical direction as “administrative” task | Covert clinical action in work queue | Semantic validation and controlled action schema, user/approver training | Clinical terms/concepts red team and task audit |
| MIS-08 | Trick model into forging policy citation or using obsolete version | Unsafe/noncompliant action and over-trust | Server-generated citations from retrieved IDs, freshness/conflict policy, abstention | Citation integrity/golden set |
| MIS-09 | Poison corpus to favor attacker policy or hide restrictions | Persistent misinformation and goal change | Source owner, provenance/hash, two-person promotion, canaries, rollback | Ingestion diff, poison detection, corpus version audit |
| MIS-10 | Abuse vector similarity/metadata to infer restricted content | Sensitive information leakage | Partition/row ACL, pre/post filters, cache isolation, export restriction | Cross-patient canary and membership tests |
| MIS-11 | Obtain broad service token through confused deputy/token passthrough | Privilege escalation across systems | User delegation, resource/audience-bound tokens, broker, no passthrough | Wrong-audience/scope and downstream audit test |
| MIS-12 | Self-approve or collude for unauthorized task | Integrity/privacy harm | Independent role/subject, risk-based approval, separation, audit review | Self/wrong-role and collusion analytics |
| MIS-13 | Hide changed fields/Unicode in approval preview | Approver consents to different action | Trusted canonical render, normalization, full diff, digest/signature | Homoglyph/invisible/mutation tests |
| MIS-14 | Replay, forge, race, or use stale approval | Duplicate or unauthorized execution | HMAC receipt, expiry, single use, current auth/policy, transaction/idempotency | Replay/signature/expiry/race tests |
| MIS-15 | Flood proposals to exhaust/overwhelm approvers | Availability failure and approval fatigue | Quotas, deduplication, risk prioritization, workload limits | Volume/approval-rate alerts and load test |
| MIS-16 | Use model output markup/image/link to exfiltrate context | Browser-based data loss or XSS | Text/data rendering, CSP, no remote content, URL allowlist if needed | Browser security and canary egress test |
| MIS-17 | Extract system prompt to find credentials or controls | Follow-on compromise | No secrets in prompt; prompt is not a security boundary | Prompt extraction test and secret scan |
| MIS-18 | Make model/tool loop until cost or service failure | Denial of wallet/service | Step/token/tool/time/cost budgets, circuit breaker, cancellation | Resource-budget adversarial test and alert |
| MIS-19 | Insert malicious dependency/tool/model/action in CI | Persistent code/data compromise | Review, pinned actions/lock, scans, provenance/signature, promotion separation | CI policy, SBOM/AIBOM, signature verification |
| MIS-20 | Abuse admin rights to relax policy/delete logs | Cover tracks and broaden access | JIT admin, separation, immutable/tamper evidence, external SIEM | Admin change/access alert and reconciliation |
| MIS-21 | Paste real patient information into synthetic demo | Unauthorized PHI processing | Prominent boundary, input DLP, training, no hosted send, incident path | DLP test/alert and repository secret/PHI scan |
| MIS-22 | Reuse output to rank staff or make employment decisions | Unapproved secondary use and workforce harm | Purpose/use prohibition, no productivity scoring, export limit, governance | Analytics inventory and worker complaint channel |
| MIS-23 | Claim the demo is HIPAA compliant or clinically validated | Recruiter/customer deception and legal/reputation harm | Claims policy, evidence links, legal/compliance public-release review | Published-content checklist |
| MIS-24 | Use the training labs against systems without permission | Dual-use cyber harm | Isolated targets, authorization rules, no real credentials/data, ethics module | Lab environment boundaries and learner attestation |

## Misuse-resistance acceptance criteria

- Security invariants hold under at least direct, indirect, stored, invisible, encoded, multilingual,
  fragmented, and tool-description injection variants.
- An authorized user cannot access a non-assigned patient, cross-facility record, disallowed purpose,
  or sensitive record without the exact required attributes.
- No model response can directly execute, expand a tool schema, choose credentials, or waive policy.
- Clinical or patient-communication content cannot enter the action executor.
- Approval mutation, self-approval, forgery, replay, expiry, duplicate execution, and policy/identity
  change fail safely and are observable.
- UI exfiltration and active content payloads are inert.
- Resource exhaustion terminates inside documented time, cost, and work limits.

## Dual-use training boundary

Training may teach threat modeling, controlled exploitation, detection, and remediation only against
the included synthetic application or another explicitly authorized lab. Learners must receive rules
of engagement, data handling requirements, stop conditions, reset instructions, and an ethics/legal
notice. Solutions should explain transferable defenses without packaging stealth, persistence, or
real-target automation.

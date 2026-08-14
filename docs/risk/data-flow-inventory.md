# NS-DAT-001 — Data Flow and Processing Inventory

**Status:** M02 baseline; synthetic-only implementation  
**Owners:** Data Steward and Privacy Officer  
**Date:** 2026-08-11  
**Reassess when:** a data source, purpose, recipient, provider, model, retention rule, jurisdiction,
or system boundary changes

## Data handling rules

- Only generated synthetic patient data is authorized in this repository.
- Synthetic health data is labeled and controlled as Northstar Restricted Health Data.
- Identity, purpose, role, facility, patient relationship, sensitivity, Consent, and operation are evaluated
  before sensitive retrieval—not inferred by a model.
- The model receives only the minimum context already authorized for the user and task.
- Raw prompts, full patient resources, reusable tokens, secrets, and hidden model reasoning are not
  routine telemetry.
- A new destination or secondary purpose requires privacy, security, legal, records, and owner review.

## Actors and data classes

| Class | Examples | Default handling |
|---|---|---|
| Public | Public project disclaimer | No confidentiality restriction; integrity still protected |
| Internal | General approved workforce policy | Authenticated workforce access, provenance, version control |
| Confidential | Identity claims, authorization decisions, system configuration | Least privilege, encryption design, audit, retention limit |
| Restricted Health Data | Synthetic patient details, sensitive action content | Patient/facility/purpose/sensitivity policy, minimization, no routine raw logging |
| Security Restricted | Secrets, signing material, detailed detection logic | Never sent to model; managed store design; tightly limited operators |

## Processing flows

| ID | Source → destination | Data/purpose | Class | Persistence | Required controls |
|---|---|---|---|---|---|
| DF-001 | Browser → identity provider | Authentication/MFA/session initiation | Confidential | IdP policy | TLS, phishing-resistant MFA target, device/session controls |
| DF-002 | IdP → Polaris API | Subject, token ID, roles, facilities, assignments, audience, expiry | Confidential | Request/session + audit reference | Signature, issuer/audience/expiry, replay, required-claim validation |
| DF-003 | Browser → Polaris API | Query, patient ID, purpose of use, proposed action | Mixed; potentially Restricted | Request scope; action/audit as required | Size/schema validation, normalization, CSRF/session design, rate limit |
| DF-004 | API → policy decision point | Principal, purpose, resource/action attributes | Confidential | Decision record | Deny by default, policy version, no model mediation |
| DF-005 | Ingestion → policy source/index | Approved content, owner, ACL, version, checksum, labels | Internal/Confidential | Source lifecycle/history | Authorized pipeline, malware/content review, provenance, rollback |
| DF-006 | Retrieval → workflow | Authorized policy excerpts and citations | Internal/Confidential | Request scope | ACL prefilter, provenance, conflict/expiry checks, trust label |
| DF-007 | FHIR service → read broker | Minimum security/Consent facts, then authorized synthetic patient fields | Restricted Health Data | Request scope; disposable HAPI H2 only for the lab | User delegation target, patient/facility/purpose/sensitivity/Consent check, source/security labels, constructed query, time/size bounds, post-read recheck, field allowlist |
| DF-008 | Workflow → model adapter | Minimum authorized context, task instructions, untrusted labels | Mixed/Restricted | Provider-specific; default no application retention | Provider terms, region, no training, minimum context, egress, timeout |
| DF-009 | Model adapter → validator | Draft text or typed proposal | Untrusted | Request scope | Schema/semantic validation, citation checks, clinical boundary, DLP |
| DF-010 | Workflow → browser | Draft answer, citations, uncertainty, action preview | Mixed/Restricted | Browser session | Output encoding, CSP, no active model-generated content, clear provenance |
| DF-011 | Proposal → approval service | Canonical action, digest, requester, policy, expiry | Confidential/Restricted | Workflow retention | Exact accessible preview, independent approver, reauthentication, HMAC receipt |
| DF-012 | Approval → executor | Receipt plus exact canonical arguments | Confidential/Restricted | Required workflow/audit retention | Integrity, expiry, single use, idempotency, current authorization/policy |
| DF-013 | Executor → task service | Allowlisted administrative task | Restricted Health Data | Task lifecycle | Narrow service permission, transaction/idempotency, outcome validation |
| DF-014 | Runtime → audit/SIEM | Subject reference, event type, policy/source/tool versions, outcome, correlation | Confidential | Security/records schedule TBD | Allowlist schema, HMAC/signature, access controls, clock sync, no raw payload |
| DF-015 | CI/build → registry/runtime | Source, dependencies, image, SBOM/AIBOM, provenance | Internal | Release lifecycle | Pinned actions, locked dependencies, scans, signing, separation of duties |
| DF-016 | Runtime/admin → backup/restore | Configuration, approved corpus, durable app/audit state | Confidential/Restricted | Recovery schedule TBD | Encryption, isolated access, restore test, deletion propagation |
| DF-017 | Identity signal transmitter → Polaris receiver | Signed session revocation, token-claim change, correlated or state-less provider-initiated stream verification, or stream-updated event; subject/token/stream reference; event ID/time | Confidential | Durable minimum event hash/reference plus stream/transmitter identity, invalidation watermark, hashed verification state or status reason, delivery-only quota receipt, checkpoint, verification/status lifecycle, and audit | Authenticate transmitter before SET validation; exact stream/media/body bounds; configured issuer/key/audience/type; exact single-use stream/state correlation; default-reject/opt-in quota-bound delivery-only unsolicited policy with health isolation; strict stream self-subject/status; no event-granted rights; replay/collision/monotonic-order/freshness controls; rate limit; bounded retention; fail closed |
| DF-018 | Polaris receiver → identity signal transmitter management API | Public metadata; fixed audience/push destination/event set; stream configuration/status; bounded synthetic subject ID; plaintext single-use verification state; optional bounded status reason; call-time management authorization | Confidential | Verification state and status-reason digests/lifecycle, desired/observed operation records, and recovery due/lease/outcome/alert state persist; injected credentials and raw responses do not | Exact discovery/version/issuer/origins; no redirects; bounded JSON; redacted call-time authorization; intent-before-dispatch; exact audience/delivery/event/stream/status binding; outcome-unknown reconciliation; lease-protected single-flight recovery cadence and stale-worker suppression; `events_delivered` completeness; `default_subjects=NONE`; fixed-issuer subject construction with `verified=false`; non-enumerating acknowledgement; verification `204` remains pending until correlated SET commit; no live provider call |

## Data minimization schema for the current patient view

Permitted: synthetic patient identifier, display name, facility, preferred language, most recent
encounter date, and administrative care-coordination flags. Excluded: free-text notes, diagnosis,
medication, laboratory, imaging, genomic, billing, contact, address, and government identifiers.

Any added field requires a documented task need, data-owner approval, policy attribute, display and
logging review, test case, retention treatment, and update to the privacy and safety assessments.

## Prohibited routine telemetry

- Authorization headers, cookies, credentials, cryptographic keys, or connection strings
- Full prompt/response bodies containing Restricted Health Data
- Full FHIR resources or policy documents
- Embeddings that can be linked to sensitive source text
- Hidden chain-of-thought or provider-internal reasoning
- Approval comments containing patient narrative
- Stack traces returned to users or secrets in exception text

Security investigation capture is a separate, time-bound, access-controlled procedure requiring an
incident lead and Privacy review when sensitive content is necessary.

## Retention and deletion decisions still required

Northstar Records, Privacy, Security, Legal, and the business owner must approve exact periods for
sessions, raw model transactions if any, action proposals/receipts, audit events, feedback, evaluation
records, corpus versions, backups, and provider-side data. Deletion must cover primary storage,
caches, indexes/embeddings, replicas, exports, backups according to schedule, and provider copies.
No hosted pilot can pass while these periods and deletion verification remain undecided.

# ADR-004 — Central Deterministic Authorization Contract

**Status:** Accepted for M04 local simulation  
**Date:** 2026-08-11  
**Owners:** IAM Lead, Data Steward, Privacy Officer, and AI Security Lead  
**Related:** REQ-IAM-002/003/004/007, REQ-RAG-002/006, CTL-IAM-002, CTL-RAG-002

## Context

The existing `PolicyEngine` correctly denies several patient and action cases, but its method-specific
conditions are not expressed through one complete, portable decision contract. M04 needs a stable
policy boundary that can later use OPA or another policy engine without moving authorization into
the model or changing application semantics.

## Decision

Every protected operation will submit an immutable `AuthorizationRequest` containing:

- authenticated subject, token ID/client, roles, scopes, and authentication context;
- declared and server-validated purpose of use;
- environment, resource type/ID, operation, facility/organization, and patient ID where applicable;
- patient relationship/assignment and current data sensitivity/consent facts supplied by trusted
  policy information points;
- action/tool/destination attributes for proposed or executed writes; and
- policy input/schema version plus correlation reference.

The policy decision point returns only an allow/deny result, stable non-sensitive reason code,
immutable policy version, and obligations such as minimum fields or required approval/step-up. It
does not return data. Missing or unknown attributes, policy unavailability, schema mismatch, and
unsupported operations deny. The model, prompt, retrieved content, and client cannot add trusted
attributes, choose a policy version, or override a decision.

The in-process Python evaluator remains the deterministic adapter for M04. An OPA/Rego adapter may
be introduced behind the same contract after parity/contract tests prove identical critical
outcomes. Business routes will not contain shadow allow logic.

The first M04 increment implements the frozen `AuthorizationRequest`, explicit operation enum,
central `PolicyEngine.authorize` dispatch, stable decision codes/version, and allow-only
obligations. Patient minimization obligations are enforced by the FHIR broker. Approval, execution,
and audit purpose checks have moved out of routes and into this policy boundary. The executable
matrix is documented in `docs/architecture/authorization-decision-table.md`.

## Decision dimensions

| Dimension | Required policy behavior |
|---|---|
| Identity | Authenticated, non-revoked subject and intended client/audience |
| Role/scope | Both workforce role and operation-specific scope are required |
| Organization/facility | Resource/action facility must be in current authorized facilities |
| Patient relationship | Current authoritative assignment/relationship is required |
| Purpose | Must be allowlisted for the resource/operation and bound to the request workflow |
| Sensitivity/consent | Restricted labels require exact clearance/consent facts; unknown denies |
| Resource/operation | Explicit allowlist; no wildcard action or model-invented tool |
| Environment | Test/development/production policies are explicit; no silent dev bypass |
| Write state | Independent approval and execution-time current authorization remain mandatory |

The full executable matrix will include permit, wrong-role, missing-scope, cross-facility,
cross-patient, wrong-purpose, sensitivity/consent, revoked/stale identity, unknown resource,
unsupported operation, missing attribute, and policy-unavailable cases.

## Consequences

- Existing method-specific service APIs will migrate incrementally behind the central contract.
- Audit events record decision code/version and references, not raw restricted policy input.
- Minimum-view obligations will drive FHIR response shaping after authorization and before return.
- Policy version changes trigger regression, traceability, and release review.

## Rejected alternatives

- **Authorization in prompts or model output:** untrusted and non-deterministic.
- **Role-only RBAC:** cannot represent facility, patient relationship, purpose, labels, consent, or
  operation context.
- **SMART scope alone:** delegated scope limits maximum authority but does not replace local user,
  patient, purpose, sensitivity, consent, and workflow policy.
- **Direct OPA dependency in routes:** couples business logic to a product before a portable contract
  and parity oracle exist.

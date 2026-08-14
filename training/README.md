# Project Polaris Training Product

Training conversion follows the working system and evidence. The course will teach learners to make
and defend decisions, operate controls, attack an authorized lab, interpret evidence, and remediate
failures—not copy a final architecture blindly.

## Planned curriculum

1. Healthcare enterprise context, use-case intake, and least-agency scoping
2. AI governance, ownership, impact tiering, and honest regulatory applicability
3. Data flows, DPIA, STRIDE, LINDDUN, abuse cases, and clinical-safety hazards
4. Requirements, canonical controls, traceability, evidence, and release gates
5. Identity, continuous access, purpose of use, patient/facility/consent authorization, and FHIR security
6. Secure RAG ingestion, provenance, authorization, citations, poisoning, and rollback
7. Untrusted-model architecture, bounded state machines, typed tools, and resource controls
8. Exact human approval, action integrity, idempotency, and safe UX
9. Secure SDLC, AI supply chain, SBOM/AIBOM, signing, provenance, and deployment
10. AI evaluations, adversarial testing, red-team operations, remediation, and residual risk
11. Monitoring, detection, incident response, kill switches, resilience, and recovery
12. Pilot governance, change control, audit, retirement, and portfolio presentation

## Lab safety contract

Labs use only the included synthetic targets and credentials, in an isolated learner environment.
Every offensive exercise has rules of engagement, objectives, stop conditions, reset, detection,
remediation, and a defensive learning outcome. Learners may not test third-party or real systems
without explicit authorization. Solutions contain no real patient data or production secrets.

## First evidence-backed lab slice

Module 5 can now be built from the verified M04 identity-signal path. Learners will configure a
synthetic issuer/receiver, inspect a signed CAEP-style SET, revoke a subject session, invalidate one
token after an entitlement change, discover a path-scoped final-SSF transmitter, read stream status,
create/read/update a strictly bound stream, add/remove a synthetic subject, request an asynchronous
verification event, then deliver a SET through the RFC 8935-shaped endpoint.
Learners attack issuer/version/origin substitution, redirects, management-header injection, false
verification-success interpretation, receiver-audience or push-endpoint substitution, dropped
required events, subject probing/false verification, missing/wrong/reused correlation state,
state-less unsolicited-event default rejection, delivery-only opt-in, durable quota exhaustion,
replay, restart, and attempts to inflate correlated health,
callback races, timeouts, transmitter authentication, stream binding, media types, request size,
type/audience/key-source confusion, replay, event-ID collision, out-of-order delivery, restart
state, stale-stream handling, `429`/transient-`5xx` recovery, oversized `Retry-After`, drift, and
superseded read races. Learners also drive the recovery controller across not-due, active lease,
expired-lease reclaim, stale-worker completion, warning/critical escalation, and success-clear
states without starting an unmanaged background loop. The capstone requires the learner to explain why
event-supplied roles cannot grant access, why a duplicate event cannot count as stream health, why
verification `204` is only pending, and why a signed SET does not eliminate transport authentication
or rate-limiting requirements. They must explain why final SSF permits a transmitter-initiated
state-less verification event yet Northstar does not treat it as proof of a receiver-requested
probe. Learners must also distinguish safe current-status recovery from
provider-specific event-gap replay and explain why ambiguous status writes are not blindly retried.
Learners then evaluate the Okta reference profile: they map the nine documented source events,
contrast final top-level `sub_id` with current provider examples, poll a scripted System Log cursor,
and attack origin/path/filter/order/limit/fragment substitution, malformed pages, duplicate UUIDs,
ambiguous user targets, failed operations, and false “empty page means recovered” claims. They must
design the missing atomic page-application/cursor transaction and multi-signal exit gate before they
may describe the path as recovery.

The lab must preserve the repository's boundaries: generated keys and identities only, direct local
receiver and local TestClient delivery, injected outbound transport, no real IdP/transmitter, no
external target, and no SSF/CAEP conformance claim. Learner evidence maps to `ADR-007`,
`VER-AUT-020`, `VER-AUT-021`, `VER-AUT-022`, `VER-AUT-023`, `VER-AUT-024`, the identity-signal,
`VER-AUT-025`, `VER-AUT-026`, `VER-AUT-027`, `VER-AUT-028`, `ADR-008`, `VER-AUT-029`, the
identity-signal, Okta-recovery, SSF-operations, SSF-stream-state, SSF-recovery, and SSF-verification
test modules,
`docs/operations/continuous-access-recovery.md`, `docs/operations/ssf-recovery-scheduling.md`,
`docs/operations/ssf-verification-policy.md`,
`docs/operations/okta-continuous-access-gap-recovery.md`, and `EVD-M04-001`.

## Product definition of done

Each module has measurable objectives, prerequisites, concept material, a decision exercise, a
hands-on lab, solution, assessment/rubric, common failures, instructor notes, accessibility review,
reset/cleanup, and links to the exact repository artifacts and evidence used.

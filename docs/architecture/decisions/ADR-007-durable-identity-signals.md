# ADR-007 — Durable Continuous-Access Identity Signals

**Status:** Accepted for M04 local simulation  
**Date:** 2026-08-11  
**Owners:** IAM Lead, SRE Lead, and AI Security Lead  
**Related:** REQ-IAM-001/003/007, REQ-OPS-001/002, CTL-IAM-001/002, CTL-OPS-001,
RSK-003/004/005/016/018/021/025

## Context

A correctly signed access token is a time-bounded identity snapshot. It can remain cryptographically
valid after a user session is revoked or an assignment, role, or other authorization claim changes.
Short token lifetimes reduce that window but do not provide a bounded continuous-access response by
themselves. Events can also be duplicated, delayed, replayed, or delivered out of order, and an old
session-revocation event must not invalidate a newer session.

The Shared Signals Framework (SSF) 1.0 and Continuous Access Evaluation Profile (CAEP) 1.0 became
final OpenID specifications on 2025-08-29. M04 needs a deterministic, durable enforcement contract
aligned to their Security Event Token (SET) semantics while remaining honest that the local adapter
does not implement or claim conformance with the complete enterprise stream lifecycle.

## Decision

Polaris implements a strict local subset of final SSF 1.0 and CAEP 1.0:

1. A receiver accepts only RS256-signed SETs with explicit `typ=secevent+jwt`, a configured issuer,
   exact single audience, trusted configured JWKS, bounded age, unique `jti`, and exactly one event.
   It rejects token-controlled key URLs/certificates, critical extensions, top-level `sub`, `exp`,
   `nbf`, ambiguous audiences, unsupported events, and untrusted subject issuers.
2. The supported events are CAEP `session-revoked`, `credential-change`, and
   `token-claims-change`. Simple `iss_sub`
   subjects create a subject invalidation watermark. `jwt_id` subjects revoke one token ID.
3. A subject watermark is the maximum accepted event time. Authentication denies a token when
   `token.iat <= watermark`; an older out-of-order event can never regress that watermark. A token
   issued after the event remains eligible for normal authorization. This handles the timing race
   described by RFC 8417 without treating event receipt order as identity truth.
4. `token-claims-change` does not copy event-supplied roles, assignments, or other claim values into
   authorization state. It invalidates the affected token/subject so fresh identity and current
   authoritative policy information must be obtained.
5. Accepted signals, target enforcement state, a stream checkpoint, and a minimized attributable
   audit event commit in one state transaction. The SQLite schema first moved from version 1 to 2
   for identity state, then to version 3 when persisted stream/transmitter attribution became
   mandatory, to version 4 for verification-request lifecycle records, and to version 5 for
   desired/observed stream-status records, to version 6 for durable status-read reconciliation
   records and source attribution, to version 7 for unsolicited-verification quota state, and to
   version 8 for durable recovery cadence, leases, and alert state. A version-2 database
   containing legacy signals without attribution is rejected rather than backfilled with invented
   trust context. Integrity substitution, relational mismatch, or transaction failure fails closed.
6. An exact event-ID/payload replay is idempotent and does not refresh stream freshness. Reuse of an
   event ID with a different payload is audited as a collision and rejected. Explicit trusted
   adapter heartbeats may advance the checkpoint when a stream is healthy but quiet.
7. API authentication and readiness fail with dependency-unavailable semantics when no checkpoint
   exists, its configured maximum staleness is exceeded, or it is implausibly far in the future.
   Ordinary revocation remains a non-enumerating authentication denial.
8. An optional, disabled-by-default HTTP push endpoint binds one URL path to one configured stream.
   It authenticates the transmitter before SET validation, requires exact RFC 8935
   `application/secevent+jwt` and `application/json` headers, incrementally caps the request body,
   and persists the stream/transmitter identity with the signal. Valid new or duplicate deliveries
   receive an empty `202`; registered error classes are returned for invalid delivery, oversized
   bodies receive `413`, and state/integrity failures receive `503` and are never acknowledged.
9. The local HTTP authenticator stores only a SHA-256 digest of a runtime-provided bearer secret and
   compares it in constant time. It is a deterministic adapter, not the enterprise target.
   Production requires an approved confidential workload identity such as mTLS or private-key
   authentication at a trusted TLS edge, with the verified identity passed through a non-spoofable
   application integration—not an untrusted client-supplied identity header.
10. A separate outbound client implements a strict final-SSF transmitter discovery, stream-status,
    and verification-request contract through an injected transport. Discovery inserts
    `/.well-known/ssf-configuration` before any issuer path, requires `spec_version=1_0`, exact
    issuer equality, signed-SET JWKS metadata, push delivery, required management endpoints, a
    configured authorization scheme, and administrator-allowlisted HTTPS origins. Discovery failure
    invalidates the last configuration instead of silently retaining it.
11. Management credentials are supplied as a redacted `SecretStr` at call time and never sent to
    discovery. Status responses must bind the exact requested stream, use a recognized final-SSF
    status, and carry the local `no-store` hardening policy. Verification requests always include a
    bounded unpredictable or caller-supplied state and accept only an empty non-cacheable `204`.
    The returned local type is explicitly pending: `204` proves request acceptance, not receipt of
    the asynchronous verification SET or end-to-end stream health.
12. A durable coordinator creates a single-use 256-bit correlation challenge, stores only its
    SHA-256 digest and lifecycle timestamps in the shared transactional state, and persists the
    `REQUESTING` record before contacting the transmitter. The plaintext state exists only for the
    outbound call and is not written to state or audit. The response must bind the exact stream and
    state before the request becomes `PENDING`.
13. A state-bearing final-SSF verification event is accepted only for the configured stream-shaped
    opaque `sub_id` and when its state matches a live `REQUESTING` or `PENDING` record. Signal
    receipt and the transition to `VERIFIED` commit together. Wrong, null, expired, or previously
    consumed state returns the registered `invalid_state` delivery error and rolls back the signal
    record.
14. Synchronous callback-before-response and ambiguous dispatch-failure races preserve an already
    verified receipt. Accepted-but-unconfirmed challenges expire durably. A fresh prior success can
    keep health `HEALTHY` during a subsequent probe, but expiry/failure of the newest probe makes
    health `UNHEALTHY`; an old success becomes `STALE`. Readiness and explicit health assertions
    fail closed unless health is `HEALTHY`.
15. The outbound client now implements the configuration endpoint's create, exact-ID read, partial
    update, complete replacement, and delete contracts; the status endpoint's read and update
    contracts; and add/remove subject operations. All calls require call-time redacted management
    authorization, exact discovered/allowlisted endpoints, bounded requests/responses, no redirects,
    expected statuses and media, and the local `no-store` hardening policy.
16. Northstar stream creation always requests push delivery to one administrator-configured HTTPS
    receiver endpoint, one exact receiver audience, and the complete local event allowlist. Returned
    configuration must exactly bind issuer, audience, push endpoint, requested events, and delivered
    events; optional supported events must contain every required event. Extra or missing receiver
    audiences and any dropped required event fail closed.
17. PATCH and PUT carry the previously validated `events_delivered` value as an optimistic binding
    on transmitter-controlled state and accept only a fully revalidated configuration response.
    The strict local profile will not broaden, narrow, or reorder its effective required event set.
    `202` pending mutation responses are not represented as success, and delete requires an empty
    non-cacheable `204`.
18. Discovery must advertise `default_subjects=NONE` and both subject endpoints. Subject operations
    construct only a bounded `iss_sub` identifier with a configured issuer; arbitrary caller JSON
    cannot enter the request. Add explicitly sends `verified=false` because this simulation has no
    authoritative subject-proof source. Empty `200`/`204` add acknowledgements and empty `204`
    removal acknowledgements are non-enumerating acceptance only—not proof that the subject exists
    or that related events will be delivered.
19. Status mutation now goes through a durable coordinator. It writes a unique immutable
    `REQUESTING` operation and minimized audit event before calling the transmitter. An exactly
    bound response atomically changes that record to `CONFIRMED` and writes the latest observation.
    A dispatch or response failure becomes `OUTCOME_UNKNOWN`, because the remote side may have
    committed even when Northstar did not receive a valid response; it is never mislabeled as a
    definite failure.
20. The receiver additionally accepts the final-SSF `stream-updated` event only with the configured
    stream's exact opaque self-subject, one recognized `enabled`/`paused`/`disabled` value, an
    optional bounded safe reason, and no unknown event members. The durable signal stores only a
    SHA-256 reason digest. A later signed observation can reconcile the newest `REQUESTING` or
    `OUTCOME_UNKNOWN` operation when its status matches the desired state and its event time is not
    earlier than the request.
21. Observed status is monotonic by event time. An older valid event is retained in the event log
    but cannot regress the latest observation. A contradictory event at the same timestamp returns
    registered `invalid_state` and atomically rolls back the signal. Exact semantic retransmission
    and synchronous callback-before-response races remain safe.
22. Operational stream health is `HEALTHY` only when the latest operation is confirmed, desired and
    observed status both equal `enabled`, and the observation is fresh and plausible. Pending,
    outcome-unknown, paused, disabled, drifted, stale, missing, or future-invalid state fails closed.
    The state-backed revocation provider can require this health in addition to its signal-delivery
    checkpoint, so a recently delivered `paused` event cannot make authorization appear available.
23. Recovery of an uncertain, stale, or drifted status uses only the safe status `GET`. Each read is
    persisted before dispatch and ends as `OBSERVED`, `FAILED`, or `SUPERSEDED`. Transport failures
    and `429`/`502`/`503`/`504` use at most five bounded attempts, equal-jitter exponential backoff,
    a total delay budget, and valid `Retry-After` delay-seconds or HTTP-date metadata. Authorization,
    binding, validation, and integrity failures are not retried. No status write is automatically
    replayed after an ambiguous outcome.
24. A matching read may confirm an `OUTCOME_UNKNOWN` operation; drift is durably observed and stays
    unhealthy. A newer operation or newer signed observation supersedes an in-flight read. A status
    read cannot prove SET completeness or recover a dropped CAEP event, so provider-neutral event-gap
    recovery remains explicitly unimplemented and failed closed.
25. Final SSF also permits a transmitter to initiate a Verification Event without a receiver
    request, in which case `state` must be absent. Northstar makes that case explicit: the default
    `REJECT` policy returns registered `access_denied`; the opt-in `ACCEPT_DELIVERY_ONLY` policy
    durably records the authenticated, signed, stream-bound delivery but never creates or confirms a
    receiver challenge and never changes correlated verification health.
26. Accepted unsolicited events consume a durable fixed-window per-stream quota. Exact replay is
    idempotent and consumes no quota or freshness; quota exhaustion rolls back the signal and
    checkpoint. The local post-signature quota supplements, but does not replace, pre-cryptography
    authentication/body limits, production edge throttling, global load shedding, alerting, and
    provider incident response.
27. A separate deterministic recovery controller exposes `run_due` for an external scheduler. It
    persists a unique bounded lease before status reconciliation, suppresses concurrent duplicate
    runs, reclaims expired leases, and rejects a stale worker's completion after a newer run wins.
    Monotonic schedule sequence, next-due time, consecutive unresolved count, and minimized alert
    state survive restart in the shared transaction boundary.
28. Successful exact recovery clears the alert and schedules the healthy cadence. Drift, bounded
    read failure, missing configured intent, or supersession schedules the degraded cadence and
    escalates durable `WARNING` to `CRITICAL` at a configurable consecutive threshold. These are
    local engineering defaults; no background scheduler, page delivery, durable named-provider
    event application, measured latency, or owner-approved SLO is claimed.
29. ADR-008 adds an Okta reference profile, final-SSF credential-change enforcement, and a strict
    separately authorized System Log cursor-read/normalization adapter for the documented Okta SSF
    source events. This is a compensating feed, not SSF replay. The adapter does not yet atomically
    apply a page or persist its cursor and therefore cannot clear a gap or restore health.

The in-memory deny registry remains a small deterministic test double. The state-backed provider is
the local durable security oracle. Neither is represented as an enterprise identity integration.

## Local and production-shaped boundary

| Concern | M04 local contract | Required enterprise target |
|---|---|---|
| Signal semantics | Strict signed SET subset for CAEP session/credential/token-claim changes plus final-SSF verification and `stream-updated` | Live provider conformance and approved event coverage |
| Delivery | Disabled-by-default, stream-specific RFC 8935-shaped push endpoint; runtime hashed-bearer test adapter; bounded body; empty `202`; registered error classes; direct receiver/heartbeat seams | Approved TLS/mTLS or equivalent workload identity, stream registration/configuration/subject management, provider-specific delivery replay/gap reconciliation, HA ingress, and provider interoperability |
| Discovery and operations | Injected final-SSF discovery/management; durable desired/observed reconciliation; bounded safe status reads; lease/cadence/alert controller seam; correlated and policy-governed unsolicited verification; Okta reference profile and cursor read/normalization seam | Live named-provider conformance, confidential credential acquisition, approved provider-specific unsolicited-event policy/rate limits, HA scheduling and delivered telemetry/pages, atomic provider-page application/cursor recovery, approved objectives, and recovery exercise |
| Keys and issuer | Injected configured RSA JWKS plus discovered trusted JWKS URI and exact issuer | Managed metadata/key rotation and revocation, protected receiver credentials, TLS, and operational ownership |
| Ordering and replay | Durable event IDs/payload hashes, monotonic subject watermarks and stream-status observations; strict Okta cursor read/normalization seam | Atomic provider-page application/cursor state, gap incident state, reconciliation window, thresholds, and measured recovery |
| Availability | Configurable local freshness bound gates auth/readiness | Owner-approved revocation/entitlement SLO, HA receivers/state, time synchronization, backup/restore, alerting, and failover exercise |
| Authorization state | Event invalidates token/subject; it never grants rights | Authoritative IAM, relationship, Consent, sensitivity, and step-up policy information points with measured propagation |
| Fallback | None in the local receiver | Deliberate short lifetime and, where supported, RFC 7662 introspection/failover policy |

Before pilot, the enterprise design must also decide account-disable/enable semantics, complex and
session subjects, stream retention/privacy, multi-region conflict behavior, provider outage modes,
and the exact maximum time from source change to enforced denial.

## Consequences

- Restart-safe invalidation, replay protection, ordering rules, transport authentication and bounds,
  RFC-shaped acknowledgement/error behavior, strict transmitter metadata/status handling, durable
  desired/observed status reconciliation, signed stream-update receipt, verification
  receipt/correlation and health, explicit unsolicited-event policy and durable quota, bounded
  safe-read recovery, lease-protected cadence and alert classification, rate-limit handling, audit
  attribution, and stale/drifted/paused-stream denial are now executable rather than aspirational.
- The identity signal and workflow/audit records share the same local integrity and transaction
  boundary; that is useful evidence but also the same single-node/trust-domain limitation recorded
  in ADR-006.
- The local adapter reduces the M04 gap from “no durable revocation behavior” to “no verified
  enterprise TLS/workload-auth edge, live provider conformance/lifecycle or approved unsolicited-
  event enablement, atomic provider-page application/cursor recovery, authoritative source,
  approved SLO, HA external scheduler/page delivery, or recovery exercise."
- Control statuses remain `partial`; the Okta documentation profile is not production authorization
  or a claim of SSF/CAEP certification, live conformance, or tenant compatibility.

## Rejected alternatives

- **Trust signed entitlements until expiry:** leaves a stale-access window with no continuous signal.
- **Use receipt time as the only ordering fact:** a delayed event could revoke a legitimately newer
  session or regress state.
- **Apply roles carried in an event:** turns a notification channel into an authorization grant
  source and increases claim-confusion risk.
- **Refresh liveness on duplicate replay:** lets an attacker or stuck delivery loop mask a dead
  stream.
- **Use the deprecated RISC `sessions-revoked` event:** final RISC 1.0 directs implementers to the
  CAEP `session-revoked` event.
- **Treat readiness as sufficient while authentication ignores staleness:** allows requests to
  continue on access state known to be stale.
- **Expose an unauthenticated webhook because the SET is signed:** makes the endpoint a cryptographic
  denial-of-service oracle and fails to bind the permitted transmitter, issuer, and stream.
- **Acknowledge before durable validation/state commit:** can lose an actionable event after the
  transmitter has been told not to retry.
- **Append the discovery path after the issuer path:** violates final-SSF multi-issuer discovery and
  can query the wrong tenant metadata document.
- **Treat verification-endpoint `204` as end-to-end success:** the final specification permits
  asynchronous delivery, so only receipt and validation of the correlated verification SET can
  establish end-to-end health.
- **Persist plaintext verification state:** unnecessary disclosure would turn operational state or
  audit access into a reusable correlation-secret exposure; only a one-way digest is durable.
- **Treat unsolicited verification as correlated health:** a provider-initiated event cannot prove
  delivery of Northstar's requested probe. The opt-in policy records delivery only; correlated health
  still requires an exact live single-use state.
- **Accept unbounded provider-initiated verification:** even authenticated signed traffic can consume
  verification resources. The opt-in path has a durable per-stream quota and still requires
  production edge/global controls before enablement.
- **Continue on the last configuration after a failed rediscovery:** can preserve endpoints or keys
  after trust metadata becomes unavailable or invalid; the local contract fails closed instead.
- **Accept a returned audience list containing Northstar plus another receiver:** creates an
  unintended disclosure path; the local contract requires exactly one configured audience.
- **Treat requested events as delivered events:** final SSF makes `events_delivered` authoritative;
  the local contract requires every safety-relevant requested event to be present there.
- **Mark caller-supplied subjects verified by default:** invents trust and can amplify probing; this
  simulation explicitly sends `verified=false` and treats acknowledgement as non-enumerating.
- **Treat a pending mutation as completed:** a `202` does not establish the resulting stream state;
  this increment accepts only a fully bound response and otherwise records an uncertain outcome for
  signed-event reconciliation.
- **Record a failed status call as definitively failed:** a timeout or lost response cannot reveal
  whether the transmitter committed; `OUTCOME_UNKNOWN` preserves that uncertainty until a signed
  observation or deliberate operator reconciliation resolves it.
- **Store the transmitter's plaintext status reason:** operational explanations are untrusted and
  may contain unnecessary sensitive detail; only a bounded value is sent and its digest is durable.
- **Let any recent signal imply an enabled stream:** a transmitter is required to notify the
  receiver before pausing or disabling; delivery freshness and operational status are distinct
  gates and both must be healthy.
- **Automatically retry an ambiguous status write:** transport loss cannot show whether the first
  POST committed. Recovery reads current status instead of replaying a write with uncertain effect.
- **Treat an enabled status read as event completeness:** final SSF permits held events to be dropped
  while paused and defines no provider-neutral sequence/replay API. A provider-specific replay or
  authoritative state re-query is required before clearing an event-gap incident.
- **Run an uncoordinated in-process recovery loop:** process restart and horizontal replicas could
  multiply traffic or lose cadence. The local seam accepts an external tick only after a durable
  lease claim and retains restart-safe next-due state.
- **Let an expired worker overwrite a reclaimed lease:** the earlier provider call can finish after a
  new owner succeeds. Completion is bound to the active run ID, so stale results are audited and
  ignored.

## Authoritative sources reviewed

- OpenID Foundation, *OpenID Shared Signals Framework Specification 1.0 — Final*:
  https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
- OpenID Foundation, *OpenID Continuous Access Evaluation Profile 1.0 — Final*:
  https://openid.net/specs/openid-caep-1_0-final.html
- OpenID Foundation, *OpenID RISC Profile Specification 1.0 — Final*:
  https://openid.net/specs/openid-risc-profile-1_0-final.html
- IETF RFC 8417, *Security Event Token (SET)*:
  https://www.rfc-editor.org/rfc/rfc8417.html
- IETF RFC 8935 and RFC 8936, SET push- and poll-based delivery:
  https://www.rfc-editor.org/rfc/rfc8935.html and https://www.rfc-editor.org/rfc/rfc8936.html
- IETF RFC 7662, *OAuth 2.0 Token Introspection*:
  https://www.rfc-editor.org/rfc/rfc7662.html
- IETF RFC 9110, *HTTP Semantics* (`Retry-After`):
  https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after

Sources were reviewed on 2026-08-11. They shape this deliberately limited local contract; they do
not certify the implementation.

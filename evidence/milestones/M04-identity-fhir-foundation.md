# M04 Identity, Continuous Access, Consent, Synthetic FHIR, and Transactional State — Local Verification

**Evidence ID:** EVD-M04-001  
**Date:** 2026-08-11  
**Scope:** Local synthetic simulation only  
**Decision:** Identity/delegation/continuous-access, Synthea/Consent/HAPI, and single-node transactional-state slices verified locally; M04 gate remains open

## Claim supported

The local application has an injectable enterprise-shaped OIDC access-token verifier, immutable
central authorization contract, and provider-neutral FHIR broker. A full synthetic Patient is read
only after role/facility/assignment/purpose/sensitivity and explicit permit Consent authorize it.
The broker then re-reads the minimum security and Consent context, rejects drift, and projects an
approved minimum summary.

The canonical local dataset is deterministically derived from three Synthea v4.0.0 FHIR R4
transaction Bundles. It removes source identifiers and direct-contact fields, applies Restricted
and SYNTHETIC labels, records source checksums, and adds explicit Consent and Provenance resources.
All 12 resources were seeded into and read back from a pinned HAPI FHIR JPA starter v8.10.0-3 lab;
the same Patient/Consent gateway contract passed against the in-memory and HTTP adapters.

The identity increment adds trusted OIDC discovery derived from a configured issuer, exact metadata
issuer validation, administrator-allowlisted JWKS origins, redirect-free bounded JSON retrieval,
unknown-key rotation refresh with cooldown, and maximum-age-limited stale use for previously
validated known keys. An isolated RFC 8693 broker reauthenticates the subject token, uses a fixed
FHIR audience/resource and exact SMART v2 Patient/Consent read/search scopes, rejects passthrough or
broadened/long-lived responses, cryptographically validates the returned token, and redacts it from
typed result serialization.

The continuous-access increment accepts a deliberately strict local subset of final OpenID SSF and
CAEP 1.0 Security Event Tokens. Signed `session-revoked`, `credential-change`, and
`token-claims-change` events atomically
persist an event record, audit event, stream checkpoint, and token revocation or monotonic subject
invalidation watermark. Replay, event-ID collisions, key/issuer/audience/type confusion,
out-of-order delivery, restart, stale streams, and authorization-token behavior are tested. Claim
change events invalidate access; event-supplied claim values never grant authority.

The signal receiver now has an optional disabled-by-default HTTP push boundary shaped to RFC 8935.
It authenticates a configured transmitter before SET signature work, binds the path to one stream,
requires exact delivery media types, incrementally bounds the body, persists the transmitter and
stream identities, returns an empty `202` only after validation and durable enforcement commit, and
uses registered SET error classes without disclosing token/key detail. Exact retransmission receives
the same acknowledgement but does not advance freshness; collision and state failures are not
acknowledged.

The outbound stream-operations increment implements strict final-SSF transmitter discovery through
an injected bounded transport, including the standard multi-issuer well-known path, exact
issuer/version binding, administrator-allowlisted HTTPS endpoint origins, signed-SET JWKS metadata,
push support, and management-authorization scheme validation. It can read an exactly bound stream
status and request an asynchronous verification event with an unpredictable or caller-supplied
correlation state. Failed rediscovery disables operations; a verification `204` is represented only
as a pending request and never as proof that the correlated SET arrived.

The same injected client now exercises the final-SSF stream configuration, status, deletion, and
subject-management request/response contracts. It fixes the receiver audience, HTTPS push endpoint,
subject issuer, and complete required event set in administrator-supplied construction. Returned
configuration must bind every one of those values and confirm every required event in
`events_delivered`. Subject add sends `verified=false` and returns only a non-enumerating
acknowledgement type; it is not represented as proof that the subject exists or events will arrive.

A durable stream-status coordinator now writes desired state before dispatch, distinguishes an
exactly confirmed response from an ambiguous `OUTCOME_UNKNOWN`, and records the latest observed
state separately. It accepts strictly bound signed final-SSF `stream-updated` SETs, reconciles a
matching uncertain operation, preserves monotonic observations, and rejects same-time conflicts.
Only a fresh confirmed `enabled`/`enabled` desired/observed pair is healthy; paused, disabled,
drifted, stale, missing, pending, or uncertain state can gate authorization as unavailable.
Plaintext status reasons are not persisted—only SHA-256 digests are retained.

The same coordinator now recovers current state with a persisted safe status read. It retries only
bounded transport/`429`/selected `5xx` failures, honors valid bounded `Retry-After`, applies
equal-jitter exponential backoff, and records observed, failed, or superseded outcomes. It never
automatically replays an ambiguous status write. Newer operator intent and newer signed
observations win races. This restores or disproves current stream-status health; it does not prove
that every CAEP event arrived or provide provider-neutral event replay.

A durable recovery controller now turns that safe-read primitive into a restart-safe invocation
seam. It atomically claims a bounded lease before provider traffic, suppresses duplicate concurrent
ticks, reclaims an expired worker, and refuses stale completion after a newer owner wins. Healthy
recovery schedules the normal cadence and clears alert state; drift, bounded failure, missing
configured intent, or supersession schedules the degraded cadence and escalates a minimized durable
warning/critical classification. It creates no background thread and sends no external page.

The named-provider increment records an Okta Identity Engine documentation profile in ADR-008.
Because Okta does not document SSF event replay, a separate OAuth-authenticated System Log polling
adapter reads only the nine documented inputs to Okta's session-revoked and credential-change SETs.
It constrains provider next links to the approved origin, exact path/filter/order/limit, minimizes
successful records to opaque IDs/types/times, and rejects malformed or duplicate pages as a unit.
This is a compensating read boundary: no page is durably applied, no cursor is persisted, and no gap
or authorization-health state is cleared in this increment. Current Okta payload examples also do
not establish final top-level `sub_id` conformance; actual tenant compatibility remains unverified.

A durable verification coordinator now persists a `REQUESTING` record before dispatch, retains only
the SHA-256 digest of its single-use state, and atomically correlates the configured stream's final-
SSF verification SET. Receipt makes health `VERIFIED`; wrong, null, expired, or reused state is
rolled back with `invalid_state`. Restart, synchronous callback, ambiguous dispatch failure, probe
timeout, stale success, same-timestamp ordering, and record substitution are tested. The local
health contract fails closed while distinguishing pending, healthy, unhealthy, stale, and unknown.

Final-SSF transmitter-initiated verification is now governed separately. A state-less event is
rejected by default with registered `access_denied`; an explicit `ACCEPT_DELIVERY_ONLY` mode records
it under a durable per-stream fixed-window quota. Exact replay consumes no quota or freshness,
quota exhaustion rolls back the signal and checkpoint, and restart/tamper behavior is tested. An
unsolicited event never creates or confirms a receiver challenge and cannot improve correlated
verification health.

The action and audit services now share one transaction boundary. The deterministic in-memory
oracle uses copy-on-write transactions; the local durable adapter uses a versioned strict SQLite
schema, foreign/unique constraints, WAL, full synchronous writes, and bounded immediate write
transactions. Proposal, approval, execution identity, and corresponding audit event commit or roll
back together. Tests prove restart survival, rollback-only nested failures, concurrent single-task
execution with replay, audit/state tamper detection, schema-version rejection, and fail-closed
readiness.

This evidence does **not** demonstrate enterprise IdP or STS integration, an enterprise TLS/mTLS
edge or confidential workload client, live transmitter discovery, stream registration/configuration
mutation or subject management against a live provider, approved live-provider unsolicited-event
enablement or production edge/global flood controls, a deployed HA recovery scheduler, external
metrics/SIEM/page delivery, atomic provider-page application/cursor recovery,
an owner-approved continuous-access SLO, live provider interoperability or SSF/CAEP conformance,
authoritative
entitlement sources, an authenticated HAPI connection,
authoritative enterprise consent, FHIR profile or SMART conformance, legal sufficiency,
PostgreSQL/high availability, production backup/restore, records retention/legal hold, immutable
WORM/SIEM audit, an external-task outbox/reconciliation path, hosted CI, real PHI handling, or
production readiness.

## Design and implementation evidence

- `docs/architecture/decisions/ADR-003-oidc-and-delegation.md`
- `docs/architecture/decisions/ADR-004-central-authorization-contract.md`
- `docs/architecture/decisions/ADR-005-synthetic-fhir-r4-boundary.md`
- `docs/architecture/decisions/ADR-006-transactional-state-audit-and-recovery.md`
- `docs/architecture/decisions/ADR-007-durable-identity-signals.md`
- `docs/architecture/decisions/ADR-008-okta-continuous-access-profile.md`
- `docs/architecture/authorization-decision-table.md`
- `docs/operations/continuous-access-recovery.md`
- `docs/operations/okta-continuous-access-gap-recovery.md`
- `docs/operations/ssf-recovery-scheduling.md`
- `docs/operations/ssf-verification-policy.md`
- `data/synthetic/toolchain-lock.json`
- `data/synthetic/fhir-r4/manifest.json`
- `src/polaris/data/synthetic.py`
- `src/polaris/security/auth.py`
- `src/polaris/security/identity_signals.py`
- `src/polaris/security/signal_delivery.py`
- `src/polaris/security/ssf_operations.py`
- `src/polaris/security/ssf_stream_state.py`
- `src/polaris/security/ssf_recovery.py`
- `src/polaris/security/okta_recovery.py`
- `src/polaris/security/ssf_verification.py`
- `src/polaris/security/oidc_remote.py`
- `src/polaris/security/delegation.py`
- `src/polaris/security/policy.py`
- `src/polaris/services/patients.py`
- `src/polaris/services/fhir_http.py`
- `src/polaris/services/state.py`
- `src/polaris/services/audit.py`
- `src/polaris/services/actions.py`
- `src/polaris/main.py`
- `tests/test_ssf_verification.py`
- `tests/test_ssf_stream_state.py`
- `tests/test_ssf_recovery.py`
- `tests/test_okta_recovery.py`
- `infrastructure/local/compose.fhir.yml`
- `infrastructure/local/hapi-overrides.yaml`
- `evidence/reports/M04-hapi-fhir-lab.json`

## Identity discovery, rotation, and delegation result

- Discovery URL is derived only from the configured HTTPS issuer; token-controlled `jku`, `x5u`,
  redirects, issuer substitution, untrusted JWKS origins, wrong media types, oversized documents,
  malformed JSON, and unsafe cache settings fail closed.
- Known signing keys use a five-minute fresh cache and at most 15 minutes total age during a tested
  provider outage. Unknown keys force one refresh and are cooldown-limited; no unknown or
  over-stale key is accepted.
- Token exchange requests one configured FHIR resource and audience with exact
  `user/Consent.rs user/Patient.rs` scope, a maximum five-minute lifetime, and no refresh token.
- The broker reauthenticates the incoming API token immediately before exchange. The returned JWT
  must have an exact subject, single audience, expected workload client ID, exact scopes, valid
  signature/issuer/type, and a response lifetime consistent with `exp`.
- The incoming token is never returned as the downstream credential; the delegated credential is a
  redacted `SecretStr` and is not placed in the model, prompt, HAPI lab, log, or audit event.
- Tests use generated synthetic RSA keys and injected transports/clocks. No enterprise endpoint was
  contacted, and the transport contract still requires an approved confidential-client adapter.

## Durable identity-signal and stream-freshness result

- The receiver requires RS256, `typ=secevent+jwt`, one configured issuer and audience, a trusted
  configured key, bounded `iat`, unique `jti`, no token-controlled key URL/certificate, no
  `sub`/`exp`/`nbf`, and exactly one supported CAEP event.
- CAEP `session-revoked` and subject-scoped `token-claims-change` set a durable monotonic
  `invalid_before` watermark. Tokens issued at or before the latest event are denied; delayed older
  signals never regress state, and a newer session is not revoked by an older event.
- Token-scoped `token-claims-change` invalidates only the named JWT ID. Claimed role values are not
  applied. An exact event replay is idempotent and cannot refresh liveness; reuse of an event ID
  with another payload is audited and rejected.
- Signals, enforcement state, stream checkpoints, and minimized audit events share one transaction.
  Schema version 1 migrates through versions 2, 3, 4, 5, 6, and 7 to version 8; an existing version-2
  database with signals that lack mandatory stream/transmitter attribution fails closed rather than
  inventing provenance. Restart/substitution tests prove durable state and fail-closed integrity.
- Missing, stale, or implausibly future checkpoints make both authentication and readiness
  unavailable. This proves a local enforcement contract and heartbeat seam—not enterprise stream
  operations, provider interoperability, or a production availability objective.

Command:

```text
.venv/bin/pytest -q tests/test_identity_signals.py -W error::ResourceWarning
```

Result: **Pass — 15 tests, with resource leaks treated as failures**.

## Authenticated bounded push-delivery result

- The receiver endpoint does not exist operationally unless an explicit delivery adapter is
  injected. The local adapter authenticates a runtime bearer credential by constant-time comparison
  to its configured SHA-256 digest; no cleartext delivery credential is committed or logged.
- Authentication runs before SET cryptography. The configured stream path, exact
  `application/secevent+jwt` content type, `application/json` accept type, and a 64 KiB default body
  limit are independently enforced and audited.
- A valid new SET and exact retransmission both receive the RFC 8935 empty `202`; retransmission is
  idempotent and does not refresh the stream checkpoint. Invalid requests use generic registered SET
  errors, oversized requests receive `413`, and event-ID collision/state failure receives `503` so
  the transmitter is never told the event was durably accepted.
- Accepted records persist both configured stream ID and authenticated transmitter ID. Transport
  audit events contain no authorization value or SET body.
- The bearer authenticator is a local test adapter. The production target remains an approved
  TLS/mTLS or equivalent workload-authenticated edge, non-spoofable identity propagation, provider
  management/status/verification APIs, event-gap reconciliation, HA, monitoring, and measured
  service objectives.

Command:

```text
uv run pytest -q tests/test_identity_signal_delivery.py -W error::ResourceWarning
```

Result: **Pass — 6 tests, with resource leaks treated as failures**.

## Trusted transmitter discovery and stream-management result

- Discovery inserts `/.well-known/ssf-configuration` between the issuer origin and path, requires
  final `spec_version=1_0`, and exactly binds the returned issuer to the administrator-configured
  issuer. Wrong versions, duplicate JSON members, wrong media, malformed JSON, redirect, oversized
  response, and transport failure are rejected.
- Signed-SET JWKS, configuration, status, verification, and optional subject endpoints must use
  administrator-allowlisted canonical HTTPS origins. Cross-origin metadata is denied unless that
  origin is independently configured. Push delivery and the configured management authorization
  scheme must be advertised.
- A failed rediscovery clears the previous configuration. Status reads acquire a redacted
  call-time authorization value, bind the exact requested stream ID, accept only
  `enabled`/`paused`/`disabled`, and enforce the local non-cacheable response policy.
- Verification requests include a bounded unpredictable or explicit correlation state, refuse
  header injection, and accept only an empty non-cacheable `204`. The typed result is
  `PendingSsfVerification`: final SSF permits asynchronous transmission, so acceptance is not
  recorded as event receipt or end-to-end stream health.
- Creation always sends one fixed HTTPS push endpoint and the exact required CAEP event allowlist.
  Create/read/PATCH/PUT responses must exactly bind issuer, one receiver audience, push method and
  endpoint, requested events, and delivered events. Optional `events_supported` must cover every
  required event; missing or extra receiver audiences and dropped required events fail closed.
- PATCH/PUT include the previously validated `events_delivered` value and revalidate the entire
  returned configuration. Update status requires exact stream/status/reason echo. Delete requires an
  empty non-cacheable `204`; pending `202` mutations are not reported as completed.
- Discovery must advertise `default_subjects=NONE` and both subject endpoints. Add/remove operations
  accept only a bounded local subject ID and construct a fixed-issuer `iss_sub` object. Add sends
  `verified=false` because no authoritative proof source exists. Empty `200`/`204` acknowledgements
  are non-enumerating and do not prove subject existence or future event delivery.
- The client classifies bounded retry metadata for the coordinator: transport failures and
  `429`/`502`/`503`/`504` are retryable; `Retry-After` accepts a bounded delay-seconds or HTTP-date.
  Authentication and other permanent failures are not retryable. This metadata does not itself
  replay any request.
- The test suite uses an injected scripted transport and synthetic authorization value. No real
  transmitter, identity provider, credential endpoint, or external network target is contacted.
  Live-provider delivery, provider-specific rate limits, event-gap recovery, confidential-client
  credential acquisition, and named-provider interoperability remain outside this stream-client
  result; the later Okta section covers only a documentation profile and compensating read seam.

Command:

```text
.venv/bin/pytest -q tests/test_ssf_operations.py -W error::ResourceWarning
```

Result: **Pass — 66 tests, with resource leaks treated as failures**.

## Durable desired/observed stream-status reconciliation result

- Each requested status is durably recorded and audited as `REQUESTING` before the injected
  transmitter call. An exact response atomically confirms the operation and observed status.
- A transport failure, malformed response, or binding mismatch records `OUTCOME_UNKNOWN`, never a
  false definitive failure. A later signed matching `stream-updated` event can reconcile it.
- A deliberate reconciliation persists `REQUESTING` before a safe status `GET`. Exact status and a
  reason digest finish as `OBSERVED`; bounded failures record `NON_RETRYABLE`, `RETRY_EXHAUSTED`, or
  `RETRY_BUDGET_EXHAUSTED`. A matching read confirms an uncertain write; drift remains unhealthy.
- Defaults permit three attempts, 100 ms base equal-jitter backoff, a 2 s maximum delay, and 5 s
  total scheduled delay. Valid bounded `Retry-After` takes precedence. No status write is retried.
- A newer operation or signed observation marks the read `SUPERSEDED` and prevents regression.
  Current-status recovery cannot establish event completeness and never advances the SET checkpoint.
- `stream-updated` requires the configured opaque stream self-subject, recognized status, bounded
  optional reason, and no unknown event members. Only a reason digest enters state or audit.
- Older valid observations cannot regress current status. Contradictory same-time observations map
  to registered `invalid_state` and roll back the signal. Synchronous callback-before-response and
  callback-plus-response-loss races preserve the signed observation and confirmed operation.
- SQLite schema v8 preserves the immutable operation and reconciliation history introduced in v6,
  one source-attributed current observation, and the v8 recovery schedule. Restart,
  relational/document substitution, staleness, drift,
  paused/disabled state, rate limits, retry exhaustion/budgets, concurrent races, missing handler,
  and authorization-health gating are tested.
- The operator and SET transmitter are scripted local adapters with generated keys. This is not
  live-provider interoperability, final-SSF conformance, generic event-gap recovery, deployed
  scheduling/page delivery, or enterprise availability evidence.

Command:

```text
.venv/bin/pytest -q tests/test_ssf_stream_state.py -W error::ResourceWarning
```

Result: **Pass — 21 tests, with resource leaks treated as failures**.

## Durable recovery scheduling and alert-state result

- An external tick enters one deterministic `run_due` seam; Polaris starts no ungoverned background
  thread. Before a status read, the controller atomically records a unique run ID, monotonic sequence,
  start time, and bounded lease.
- Calls before the durable due time produce no provider traffic. Calls during an active lease return
  `IN_PROGRESS`; an expired lease can be reclaimed, and the prior worker's late completion cannot
  overwrite the new run.
- Exact healthy recovery resets consecutive unresolved cycles, clears alert state, and schedules the
  healthy interval. Drift, read failure, missing configured intent, and supersession use the degraded
  cadence and escalate `WARNING` to `CRITICAL` at the configured threshold.
- Schedule and alert state survive SQLite restart. Clock rollback, invalid configuration, relational
  mismatch, sequence/transition substitution, and document tampering fail closed.
- Defaults—four-minute healthy cadence, 30-second degraded cadence/lease, and critical after three
  unresolved cycles—are bounded engineering values, not approved or measured production objectives.
- Audit and schedule records omit credentials, SET bodies, plaintext provider reasons, identity
  subjects, tokens, and patient/user data. No external metric, alert router, or page was exercised.

Command:

```text
.venv/bin/pytest -q tests/test_ssf_recovery.py -W error::ResourceWarning
```

Result: **Pass — 7 tests, with resource leaks treated as failures**.

## Okta interoperability profile and compensating gap-feed result

- `ADR-008` selects Okta Identity Engine only as the named M04 reference profile. The decision
  records current provider documentation, its documented CAEP event mapping, the absence of a
  documented SSF replay surface, the System Log return window, and the unresolved final-SSF
  top-level subject compatibility question.
- The final-SSF receiver now accepts bounded `credential-change` events and treats every recognized
  change action as subject invalidation. An optional legacy event-local subject must exactly equal
  the required top-level `sub_id`. Provider descriptions and localized reasons cannot grant or
  preserve access; malformed, conflicting-subject, or unknown actions fail validation.
- `OktaSystemLogRecoveryClient` uses an injected transport and call-time redacted OAuth credential.
  It sends only `GET` to the administrator-approved Okta origin and exact `/api/v1/logs` path with
  one fixed allowlist filter, ascending polling, and a 100-record page bound.
- Initial recovery is limited to 89 days. Provider `rel=next` URLs must retain the exact origin,
  path, filter, order, and limit; fragments, `until`, extra parameters, cross-origin/path changes,
  and malformed/missing/duplicate next links fail closed before another provider call.
- Pages accept canonical UUIDs, allowlisted event types, aware bounded published times, typed
  outcomes, and exactly one safe user target for successful events. Unsuccessful operations are
  counted but not applied. Malformed, duplicate, ambiguous, or oversized/out-of-profile responses
  reject the complete page.
- Output is minimized to provider UUID/type, internal signal type, opaque subject, and effective
  time. Raw logs, emails, display names, IP data, debug context, reason text, OAuth credentials, and
  cursor URLs are not written to state or audit by this adapter.
- An empty page is represented as caught up at that instant and still advances to the validated next
  cursor. It is not represented as recovered health. The caller contract requires future atomic
  page application and cursor persistence before any recovery decision.

Targeted command:

```text
.venv/bin/pytest -q tests/test_identity_signals.py tests/test_okta_recovery.py
```

Result: **Pass — 41 tests**. The complete repository gate below independently includes the same
tests under branch coverage, strict typing, formatting, and lint/security rules.

## Durable correlated and unsolicited verification result

- A generated single-use verification state is sent only after a `REQUESTING` lifecycle record and
  its audit event commit. Durable state contains the SHA-256 digest, never the plaintext challenge.
- The outbound response must exactly bind the configured stream and state. An empty `204` advances
  only to `PENDING`; only a signed final-SSF verification SET with an opaque stream `sub_id` and an
  exact live state can transition the record to `VERIFIED`.
- The accepted signal, verification transition, checkpoint, and audit event commit atomically.
  Null, wrong, expired, or consumed state maps to registered `invalid_state` and leaves no signal
  record. Exact SET retransmission remains idempotent.
- A synchronous callback arriving before the outbound call returns and a callback followed by an
  ambiguous dispatch error preserve the verified receipt. A pending probe expires once and rejects
  late delivery. SQLite restart and binding-tamper tests prove lifecycle durability and integrity.
- Health is `HEALTHY` only with a fresh successful receipt. A new pending probe may temporarily use
  the previous fresh success, but failure/expiry of the newest probe is `UNHEALTHY`; old success is
  `STALE`, and health/readiness fail closed otherwise.
- A transmitter-initiated event must omit `state`. The default policy rejects it with
  `access_denied`; the opt-in delivery-only policy durably records it within a bounded per-stream
  fixed window without creating a challenge or changing correlated health.
- Delivery-only quota state survives restart, rejects backward receipt time, resets only after the
  configured window, and is bound to the accepted signal by relational/document integrity checks.
  Exact replay consumes neither quota nor freshness; quota rejection commits no signal or checkpoint,
  and concurrent SQLite delivery cannot exceed the configured maximum.
- This uses an injected scripted transmitter; it is not final-SSF conformance, approved live-provider
  enablement, or production flood-resilience evidence.

Command:

```text
.venv/bin/pytest -q tests/test_ssf_verification.py -W error::ResourceWarning
```

Result: **Pass — 20 tests, with resource leaks treated as failures**.

## Dataset provenance and safety result

- Synthea release: v4.0.0, release commit `0185c09`
- Synthea JAR SHA-256: `ed43c20ad40ba5c3bc724503a5af032715fe3c491620b766148e7c2361e6ecc1`
- Generator runtime: pinned Eclipse Temurin Java 17 image; network disabled; read-only/non-root run
- Fixed population/clinician seeds: `20260811` / `11082026`
- Fixed reference/end date: 2026-08-11; population: 3; location: Massachusetts
- Reproducibility: two raw generation runs were byte-identical file-for-file
- Canonical Bundle SHA-256: `e4137d421ac2f745a3e9a395def563b140ad5b4773a2fe107f42df698dca7845`
- Canonical resources: 3 Organization, 3 Patient, 3 active permit Consent, 3 Provenance
- Safety validation: direct source identifiers/names/address/telecom/birth date/identifier excluded;
  source IDs absent; required labels/source present; credential markers absent; tampering detected

Command:

```text
.venv/bin/python scripts/synthetic_fhir.py verify
```

Result: **Pass**.

## HAPI interoperability and hardening result

Pinned image:

```text
hapiproject/hapi:v8.10.0-3@sha256:55213612779ab3eeec919226b7bad378f0061ade823393a61d7dd46dd5087a3d
```

Observed lab controls: non-root `65532:65532`, read-only root filesystem, all Linux capabilities
dropped, `no-new-privileges`, bounded CPU/memory/PIDs, loopback-only port, read-only configuration
mount, ephemeral H2, restricted CORS origin, and no persistent data volume. MCP, OpenAPI, and
Swagger routes returned 404. HAPI reported FHIR 4.0.1 and software version 8.10.0.

Commands and results:

```text
.venv/bin/python scripts/hapi_fhir_lab.py seed
# Pass — 12 synthetic resources seeded and read back

POLARIS_HAPI_BASE_URL=http://127.0.0.1:18080/fhir .venv/bin/pytest -q -m integration
# Pass — 1 shared gateway/broker integration test

.venv/bin/python scripts/hapi_fhir_lab.py verify
# Pass — capability identity, all 12 resources, labels/source, and disabled endpoints
```

The upstream starter supplies no enterprise authentication or enterprise logging. Docker Desktop
bridge networking also does not provide default-deny egress. These facts prohibit exposing or
treating the lab as a production FHIR service.

## Transactional state, audit, and recovery result

- `ActionService` and `AuditLedger` receive the same state-store instance; construction fails if
  they do not share the boundary.
- Proposal/audit, approval/receipt/audit, and execution/task-identity/audit transitions commit in
  one local transaction. A nested failure marks the outer transaction rollback-only even when the
  inner exception is caught.
- The SQLite adapter rejects relative, directory, symlink, missing-parent, incompatible-schema,
  corrupt-model, relational/document identity substitution, foreign-key failure, and invalid-
  integrity states. Readiness requires both state integrity and the HMAC audit chain to verify.
- Restart tests reconstruct the application three times from one database and preserve approval,
  execution, audit, and idempotent replay. Concurrent executors produce one durable task identity,
  one initial success, and one replay.
- This is a single-host engineering simulation. SQLite permits one write transaction at a time,
  and the local HMAC chain shares the database trust domain. `ADR-006` therefore requires a
  production PostgreSQL transaction design, least-privilege roles, retry semantics, protected audit
  export/retention, backup/PITR with measured RTO/RPO, and an outbox/reconciliation state machine
  before any pilot or production claim.

Command:

```text
.venv/bin/pytest -q tests/test_durable_state.py -W error::ResourceWarning
```

Result: **Pass — 6 tests, with resource leaks treated as failures**.

## Full repository verification

Command:

```text
make verify
```

Result on Python 3.13.11:

- Governance traceability and generated-report drift: pass
- Synthetic dataset integrity/safety check: pass
- Ruff formatting and lint/security rules: pass
- Strict mypy: pass across 56 source/test files
- Pytest: pass, 310 default-suite tests; 1 Docker-gated integration skipped by design
- Branch-aware coverage: 85.66%; required floor 85%
- Traceability: 70/70 requirements, 25/25 registered risks, and 78/78 scenarios mapped
- Catalogs: 31 controls, 45 verification definitions, and 22 evidence definitions

Hosted GitHub Actions did not run because this repository has no configured remote. The local
command is CI-equivalent but is not evidence of hosted runner or branch-protection behavior.

## Remaining M04 gate work

- Enterprise IdP/STS integration, confidential workload client authentication and TLS/mTLS edge,
  live-provider SSF discovery and lifecycle, approved unsolicited-event enablement and production
  edge/global rate-limit tuning, live Okta/final-SSF conformance, atomic provider-page application,
  durable cursor/gap incident state, complete recovery, authoritative
  entitlement sources, and an owner-approved continuous-access latency/availability objective
- Authoritative enterprise relationship and Consent integration/profile/legal review
- Production PostgreSQL/HA persistence, backup/restore/PITR exercise, approved retention/legal hold,
  immutable audit export, and external-task outbox/outcome-unknown reconciliation
- Hosted CI execution and branch-protection evidence after repository publication
- Simulated final M04 owner review; actual accountable review remains outside this simulation

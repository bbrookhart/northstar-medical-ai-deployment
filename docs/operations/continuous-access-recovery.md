# Continuous-Access Status Recovery and Draft Objectives

**Status:** Implemented local control; objectives are draft and unapproved  
**Owners:** IAM Lead and SRE Lead  
**Scope:** Synthetic final-SSF status and CAEP enforcement path only

## Control objective

Recover the transmitter's current stream status after an ambiguous status change, stale local
observation, detected drift, or operator investigation without replaying a potentially completed
write. Preserve a source-attributed record of every recovery attempt and keep authorization failed
closed whenever the stream is not freshly confirmed `enabled`.

## Recovery contract

1. Persist and audit a reconciliation record as `REQUESTING` before contacting the transmitter.
2. Use only the final-SSF status `GET` for automatic recovery. Never automatically replay a status
   `POST`, including after a timeout, transport error, `202`, or retryable HTTP response.
3. Accept only an exact configured stream ID and one of `enabled`, `paused`, or `disabled`. Persist
   only a digest of an optional provider reason.
4. Retry only transport failures and HTTP `429`, `502`, `503`, or `504`. Treat authorization,
   existence, validation, media, cache, and response-binding failures as non-retryable.
5. Honor a valid `Retry-After` delay-seconds or HTTP-date value. If it exceeds the local maximum or
   total delay budget, stop rather than retry earlier than the provider requested.
6. Without `Retry-After`, use bounded exponential backoff with equal jitter. Defaults are three
   total attempts, 100 ms base delay, 2 s maximum delay, and 5 s total delay budget. Configuration
   is capped at five attempts and 30 seconds.
7. Persist a terminal `OBSERVED`, `FAILED`, or `SUPERSEDED` record with attempt count and a bounded
   failure class. A matching read can confirm an `OUTCOME_UNKNOWN` write; drift remains unhealthy.
8. Do not apply an in-flight read if a newer status operation or newer signed `stream-updated`
   observation won the race.

The status read follows the final SSF management API's current-status `GET` contract. The header
parser follows HTTP Semantics for `Retry-After`. See [OpenID Shared Signals Framework 1.0,
§8.1.2.1](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html#name-reading-a-streams-status)
and [RFC 9110, §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after).

## Trigger and response matrix

| Trigger | Local action | Authorization posture | Escalation |
|---|---|---|---|
| Status write outcome is unknown | Run one bounded reconciliation | Unhealthy until matched | Alert on terminal failure or drift |
| Observed status exceeds freshness limit | Run one bounded reconciliation | Stale; deny sensitive access | Alert if freshness is not restored |
| Signed event reports paused/disabled or drift | Preserve signed observation; optional confirming read | Unhealthy | Open provider/identity incident |
| Status read is rate limited or transiently unavailable | Honor bounded retry policy | Retain current fail-closed health | Alert after exhaustion |
| Authorization, binding, or integrity error | Do not retry | Unhealthy | Page IAM/SRE and preserve evidence |

The coordinator exposes the read primitive, and a separate local controller now provides durable
next-due cadence, a lease-protected single-flight claim, crash reclaim, stale-worker suppression, and
warning/critical alert classification. It deliberately creates no background thread and delivers no
page. Production orchestration must still supply an approved scheduler, metrics/alert routing,
workload identity, and provider-specific rate-limit configuration. See
`docs/operations/ssf-recovery-scheduling.md`.

## Gap-recovery boundary

A successful status read proves only the stream's current management status. It does not prove that
all security events were received and cannot reconstruct a missing entitlement or revocation event.
Final SSF permits a transmitter to drop held events while a stream is paused and does not define a
generic event sequence, cursor, or replay API. Therefore the provider-neutral implementation does
not claim event-gap recovery.

Before a live pilot, the named-provider adapter must provide and test at least one authoritative
recovery mechanism:

- provider-supported event sequence/cursor and replay;
- authoritative session, token, and entitlement re-query with a monotonic watermark; or
- forced reauthentication/token introspection plus cache invalidation when completeness is unknown.

ADR-008 now selects the Okta System Log polling API as a compensating cursor feed for the named M04
reference profile. The strict local adapter validates and minimizes a page but deliberately does not
apply events or persist its cursor. The remaining implementation must atomically bind page
application to compare-and-swap cursor progression, retain explicit gap incident state, and require
an empty caught-up page plus healthy current status and fresh receiver-correlated verification
before an operator can clear the gap. See
`docs/operations/okta-continuous-access-gap-recovery.md`.

Until that mechanism completes, stream gaps, disabled periods, implausible checkpoints, or
unexplained freshness loss keep sensitive authorization unavailable. Never advance the signal
checkpoint merely because the management status is `enabled`.

## Draft service objectives

These are engineering candidates for simulation and fault testing, not approved enterprise SLOs or
evidence of measured production performance.

| Indicator | Candidate objective | Measurement point | Current evidence |
|---|---|---|---|
| Recovery-read execution | At most 3 attempts and 5 s scheduled delay per invocation | Durable reconciliation lifecycle | Locally verified |
| Freshness fail-closed transition | Deny after the configured maximum observed age | Coordinator health and authorization gate | Locally verified |
| Ambiguous-write handling | 100% persist `OUTCOME_UNKNOWN`; 0 automatic write replays | Operation state and outbound-call count | Locally verified |
| Drift handling | 100% persist observed drift and return unhealthy | State, audit, and health result | Locally verified |
| Detection-to-recovery start | 30 s at p95 | Durable due/claim timestamps plus future scheduler metrics | Cadence/claim seam locally verified; external timing not measured |
| Continuous-access event latency | Owner/provider-defined p95/p99 | Transmitter event time to committed enforcement | Pending live-provider test and approval |
| Event completeness | Provider-specific target | Sequence/replay or authoritative re-query | Okta cursor read seam verified; durable application/completeness not implemented |

## Required telemetry and evidence

- Counters by terminal reconciliation status and bounded failure class.
- Attempt and scheduled-delay histograms; never include authorization values or plaintext reasons.
- Age of latest signed event and latest source-attributed observation.
- Health-state transitions, authorization denials caused by stream health, and superseded-race count.
- Provider rate-limit headers and quotas only if approved as non-sensitive operational metadata.
- Fault tests for `429`, transient `5xx`, transport loss, invalid `Retry-After`, oversized retry
  windows, restart, drift, and concurrent signed/operator state changes.

Local automated evidence is registered as `VER-AUT-026`, `VER-AUT-028`, `VER-AUT-029`, and
`EVD-M04-001`. Live-provider conformance, atomic gap application/cursor recovery, external scheduler
timing, alert delivery, and owner-approved objectives remain gate blockers.

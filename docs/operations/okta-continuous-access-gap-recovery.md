# Okta Continuous-Access Gap-Recovery Runbook

**Scope:** Synthetic M04 reference profile only  
**Status:** Strict read/normalization boundary verified; durable recovery workflow not implemented  
**Owners:** IAM on-call, SRE on-call, SOC, and AI Security Lead

## Purpose and safety rule

Use the Okta System Log polling adapter to enumerate the documented source events that may have been
missed by the Okta SSF delivery path. This feed is compensating evidence, not SSF replay. Keep
Polaris authorization and readiness fail closed throughout the gap. Never clear a gap merely because
the System Log returns an empty page.

No command in this runbook is authorized against a real tenant by the repository. A live exercise
requires a synthetic-user tenant, approved change record, least-privilege service application,
credential vaulting, monitoring, stop conditions, and named owners.

## Provider event profile

| Okta System Log event | Normalized signal | Enforcement intent |
|---|---|---|
| `user.session.end` | CAEP `session-revoked` | Invalidate subject sessions at or before the effective time |
| `user.mfa.factor.activate` | CAEP `credential-change` | Invalidate subject sessions and reacquire authoritative identity |
| `user.mfa.factor.deactivate` | CAEP `credential-change` | Same |
| `user.mfa.factor.reset_all` | CAEP `credential-change` | Same |
| `user.mfa.factor.suspend` | CAEP `credential-change` | Same |
| `user.mfa.factor.unsuspend` | CAEP `credential-change` | Same |
| `user.mfa.factor.update` | CAEP `credential-change` | Same |
| `user.account.reset_password` | CAEP `credential-change` | Same |
| `user.account.update_password` | CAEP `credential-change` | Same |

Only `SUCCESS` records are actionable. A page containing malformed, unsupported, duplicate, or
ambiguous records is rejected as a unit. The adapter minimizes each accepted record to provider
UUID/type, internal event type, opaque user ID, and effective time.

## Detection and containment

Open an identity-stream gap incident when any of these occurs:

- the signed stream status is paused/disabled, drifted, stale, missing, or future-invalid;
- receiver-correlated verification fails or expires;
- delivery/checkpoint freshness exceeds its approved bound;
- provider or edge monitoring reports failed/delayed delivery;
- event-volume reconciliation detects a discontinuity; or
- an operator cannot account for a stream lifecycle change.

Containment requirements:

1. Preserve the fail-closed authorization-health state and record the incident/correlation ID.
2. Freeze unreviewed stream configuration, credentials, filters, and recovery cursor changes.
3. Record last known-good SSF receipt, status observation, correlated verification, and System Log
   cursor without copying identity payloads into the incident ticket.
4. Determine whether the suspected lower bound is inside the documented System Log return window.
   If not, stop: this adapter cannot prove completeness and an authoritative tenant-wide session
   reset or other approved containment is required.
5. Check provider status, rate-limit telemetry, receiver edge health, time synchronization, state
   integrity, and duplicate workers before polling.

## Recovery read contract

The production caller will construct `OktaSystemLogRecoveryClient` with:

- the administrator-approved exact HTTPS Okta origin;
- a transport that refuses redirects and caps the body at 256 KiB;
- a call-time, short-lived, scoped OAuth secret (the adapter never accepts an API token string in
  configuration or audit); and
- a timezone-aware lower bound no older than 89 days.

The first request fixes the allowlisted event filter, `sortOrder=ASCENDING`, and `limit=100`.
Subsequent requests use only the provider-generated `rel=next` URL. Never craft or edit `after`,
remove the filter, add `until`, change sort order, follow a cross-origin/path link, or log the full
authorization header.

For each page, the recovery orchestrator must execute this transaction:

1. Validate and normalize the entire response outside the state transaction.
2. Begin a durable transaction scoped to the incident, stream, and expected current cursor.
3. Idempotently apply every normalized provider UUID. Credential and session events may only
   invalidate; they cannot grant claims or roles.
4. Append minimized audit records and update recovery counts.
5. Persist the exact validated next cursor with compare-and-swap sequencing.
6. Commit once. On any failure, roll back events, audit, counts, and cursor together.

The current repository stops after step 1 and returns the next cursor. Steps 2–6 are required before
this can recover a real gap.

## Exit criteria

Do not restore authorization health until one recovery generation proves:

- every fetched page was atomically applied exactly once and cursor progression survived restart;
- polling reached an empty page and its returned next cursor was durably committed;
- a subsequent SSF status read observes the exact stream as `enabled`;
- a new receiver-requested verification challenge is received, signed, correlated, and fresh;
- local stream checkpoint, desired/observed status, verification health, recovery state, state
  integrity, and audit integrity are healthy;
- no older-than-retention gap remains;
- warning/critical alerts are delivered and the incident owner approves recovery; and
- a post-recovery synthetic-user revocation test meets the owner-approved objective.

If any condition fails, remain unavailable and escalate. Never substitute shorter token lifetime,
an unsolicited verification event, a status `GET`, an empty page, or an operator assertion for the
complete criteria.

## Required telemetry without identity payloads

- stream ID hash, provider profile version, incident ID, and recovery generation;
- page request/result class, scanned/applied/ignored/duplicate counts, and cursor sequence—not cursor;
- age of oldest unresolved gap and latest caught-up observation;
- SSF status/verification health, consecutive failure class, and alert level;
- provider `429`/transient failure count and bounded retry metadata; and
- transaction/cursor conflict, malformed page, origin/path/filter rejection, and integrity failure.

Do not emit OAuth credentials, full cursor URLs, user IDs, emails, display names, IPs, raw events,
reason text, debug context, SETs, or token claims.

## Verification and remaining blockers

Run `tests/test_okta_recovery.py` and the complete `make verify` gate. `VER-AUT-029` and
`EVD-M04-001` evidence only the scripted local boundary. Live enablement still requires actual
final-SSF payload/discovery capture, provider feature/lifecycle confirmation, confidential-client
and TLS design, durable cursor/application state, scheduler leader election, SIEM/page delivery,
privacy/retention and vendor review, service objectives, game day, and attributable approval.

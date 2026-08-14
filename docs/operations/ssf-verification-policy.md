# SSF Verification Event Policy

**Status:** Implemented local policy; live-provider agreement remains required  
**Owners:** IAM Lead and SRE Lead  
**Scope:** Synthetic final-SSF verification events on one configured push stream

## Decision

Final SSF permits a transmitter to send a Verification Event without a receiver request. A
transmitter-initiated event must omit `state`; a receiver-requested event may include the opaque
`state` supplied by the receiver. Northstar separates these two cases instead of treating every
validly signed Verification Event as equivalent health evidence.

The coordinator exposes two explicit modes:

| Mode | State-less transmitter event | Correlated health | Intended use |
|---|---|---|---|
| `REJECT` | Reject with `access_denied` | Unchanged | Default until provider behavior and operating agreement are approved |
| `ACCEPT_DELIVERY_ONLY` | Persist and acknowledge within quota | Unchanged | Opt-in interoperability mode proving only that this particular SET was delivered and validated |

A Verification Event containing `state` always follows the correlated path. It must match one live,
single-use `REQUESTING` or `PENDING` challenge. The delivery-only policy cannot convert an invented,
wrong, expired, or reused state into an unsolicited event.

This policy follows [OpenID Shared Signals Framework 1.0,
§8.1.4](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html#name-verification):
the transmitter may initiate a Verification Event, and a transmitter-initiated event must not set
`state`. It also retains RFC 8935's authenticated-transmitter and denial-of-service controls; see
[RFC 8935, §5.4](https://www.rfc-editor.org/rfc/rfc8935.html#name-denial-of-service).

## Acceptance contract

An opt-in delivery-only receipt is accepted only when all of the following are true:

1. The push transmitter was authenticated before SET cryptography.
2. The SET has the configured issuer, exact audience, trusted RS256 key, bounded age, unique event
   ID, exact verification event type, and the configured stream's opaque `sub_id`.
3. The event payload is empty. `state`, `event_timestamp`, null state, and unknown members are not
   valid transmitter-initiated shapes in this strict profile.
4. The durable fixed-window quota has capacity.
5. The signal, quota receipt, stream checkpoint, and minimized audit events commit atomically.

Accepted durable state contains the stream ID, window start, accepted count, last receipt time, and
last signal ID. The signed SET is represented by its existing minimized signal record and payload
digest. No plaintext correlation state, SET body, authorization value, or patient/user identifier is
added to the quota record or audit metadata.

## Replay, rate, and race behavior

- Exact event-ID/payload replay remains idempotent. It does not consume quota, advance the quota
  receipt, or refresh stream freshness.
- A different event ID counts as a new event even if it is otherwise semantically identical.
- Defaults allow five accepted unsolicited verification events per one-minute fixed window.
- Configuration is bounded to 1–100 events and a 1-second to 1-hour window.
- Once full, a new unsolicited verification event returns registered `access_denied`; its signal,
  checkpoint, and audit-in-transaction changes roll back.
- Quota state survives restart and is protected by relational/document integrity checks.
- Concurrent deliveries serialize through the state transaction; no race can admit more than the
  configured per-window maximum.
- A new window begins only after the configured interval. Backward receipt time fails closed.

The local quota limits valid authenticated verification traffic after signature validation. It does
not replace ingress connection/body limits, transmitter authentication before cryptography,
per-identity edge throttles, global load shedding, or provider incident response.

## Health and authorization semantics

`ACCEPT_DELIVERY_ONLY` establishes only that one authenticated, signed, stream-bound SET reached the
receiver and passed validation. It may advance the general signal-delivery checkpoint because it is
a newly committed delivery. It does not:

- create a receiver-requested verification lifecycle record;
- transition `PENDING`, `FAILED`, `EXPIRED`, `UNKNOWN`, or `STALE` correlated health;
- satisfy `DurableSsfVerificationCoordinator.assert_healthy()` or readiness;
- prove that earlier CAEP events were delivered;
- recover an event gap; or
- establish live-provider availability or a service objective.

This separation prevents provider-initiated traffic from masking a failed Northstar probe. A future
decision to count unsolicited events as full health evidence requires a new threat analysis,
provider agreement, explicit health model, and adversarial tests; it is not an implicit extension of
`ACCEPT_DELIVERY_ONLY`.

## Operational requirements before enabling

- Contract or interoperability profile confirms the provider can initiate state-less verification.
- IAM and SRE approve the quota, expected frequency, alert threshold, and outage behavior.
- The production edge binds a non-spoofable transmitter workload identity to the stream.
- Metrics distinguish correlated confirmations, accepted unsolicited events, idempotent replay,
  policy rejection, quota rejection, and invalid state.
- Alerts detect sustained quota exhaustion and unexpected mode/frequency changes.
- Load tests verify edge and signature-validation capacity without using real identities or PHI.
- Incident playbooks cover provider flood, compromised transmitter credentials, repeated invalid
  state, and unexplained verification traffic.

Local automated evidence is registered as `VER-AUT-027` and `EVD-M04-001`. The implementation is a
strict scripted/local subset and is not a claim of SSF certification, named-provider compatibility,
production resilience, or approved operating effectiveness.

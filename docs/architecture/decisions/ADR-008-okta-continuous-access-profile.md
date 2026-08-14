# ADR-008 — Okta Continuous-Access Interoperability and Gap Feed

**Status:** Accepted for M04 local simulation; live conformance and procurement not approved  
**Date:** 2026-08-11  
**Owners:** IAM Lead, SRE Lead, Vendor Risk Lead, and AI Security Lead  
**Related:** ADR-003, ADR-007, REQ-IAM-001/003/007, REQ-OPS-001/002,
CTL-IAM-001/002, CTL-OPS-001/002, RSK-003/004/005/016/018/021/025

## Context

ADR-007 established a provider-neutral final-SSF receiver, management client, health gate, and safe
status-recovery controller. It intentionally did not name a provider or invent a provider replay
capability. M04 now needs one realistic enterprise profile that can be challenged against published
provider behavior without turning documentation into a production-conformance claim.

Okta currently documents a generally available SSF transmitter and maps `user.session.end` to CAEP
`session-revoked`. It maps password and MFA lifecycle events to CAEP `credential-change`. Its
read-only System Log polling API documents cursor pagination, commit-order polling, and a 90-day
return window. The SSF documentation reviewed for this decision does not document historical SET
replay or a sequence/cursor on the SSF stream itself.

There is also a material compatibility question. Current Okta SET examples place the CAEP subject
inside the event and omit the top-level `sub_id`; final SSF 1.0 requires top-level `sub_id`, including
for existing CAEP events. Documentation examples alone cannot establish what a provisioned tenant
will transmit. Northstar must capture and test actual signed verification and synthetic-user SETs
before enabling a live stream.

Authoritative references reviewed on 2026-08-11:

- [Okta SSF Transmitter SET payload structures](https://developer.okta.com/docs/reference/ssf-transmitter-sets/)
- [Okta System Log query](https://developer.okta.com/docs/reference/system-log-query/)
- [Okta API release lifecycle](https://developer.okta.com/docs/api/openapi/okta-management/guides/release-lifecycle)
- [OpenID Shared Signals Framework 1.0 Final](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-1_0.html)

## Decision

Northstar adopts an **Okta Identity Engine reference profile** for the synthetic M04 lab, subject to
these constraints:

1. Okta SSF remains the primary near-real-time signal path. The locally supported provider event set
   is exactly CAEP `session-revoked` and `credential-change`; Northstar also retains the
   provider-neutral `token-claims-change` support already established by ADR-007.
2. Any accepted credential change creates a subject invalidation watermark. Event-provided
   credential names, localized reasons, or initiating entities can never grant or preserve access.
   The receiver accepts only the bounded standard event shape and recognized change actions.
3. Live final-SSF compatibility is **unverified**. The generic receiver continues to require the
   final top-level `sub_id`. An optional event-local subject is accepted only when it exactly equals
   `sub_id`; the documented legacy example shape without `sub_id` remains invalid. A provider-
   specific legacy normalizer requires a separate threat review and test corpus if actual tenant
   traffic proves non-final.
4. The Okta System Log polling API is the selected compensating gap feed. It is not called SSF
   replay. It uses a separate short-lived scoped OAuth credential and a separately allowlisted HTTPS
   request to the exact `/api/v1/logs` path.
5. The recovery query is fixed to the nine Okta events documented as inputs to the two supported
   CAEP events, `sortOrder=ASCENDING`, and a page limit of 100. The initial lower bound must be within
   89 days so the local guard stays inside the documented 90-day return window.
6. Only provider-generated next-link cursors on the same origin, exact path, fixed filter, ascending
   order, and fixed limit are accepted. Origin, path, query, sort, filter, `until`, fragment, extra
   parameter, malformed link, redirect, media type, size, and cursor substitution fail closed.
7. A page is all-or-nothing. Every record must have a canonical UUID, one allowlisted event type,
   a bounded aware timestamp, typed outcome, and—when successful—exactly one safe `User` target.
   Failed provider operations are counted and ignored; malformed, duplicated, ambiguous, or
   out-of-profile records reject the entire page.
8. The adapter returns only a minimized provider event ID/type, internal signal type, opaque Okta
   user ID, and effective time. It does not retain display names, email, client, IP, debug context,
   reasons, or the raw System Log event.
9. `published` is used as a conservative invalidation time when the compensating record does not
   expose the original CAEP event timestamp. Polling order is preserved; code does not claim that
   `published` order is commit order.
10. A full recovery controller must durably apply the complete page and persist its next cursor in
    the same transaction. The current increment implements and tests the strict read/normalization
    boundary only. It does not advance the authorization-health checkpoint or clear a gap.
11. Recovery exit will require all of the following: caught-up empty System Log page, all earlier
    pages durably applied, SSF status `enabled`, a fresh receiver-correlated verification event,
    healthy local state, and an attributable operator decision. An empty page alone proves none of
    those conditions.
12. Credentials, tenant access, live calls, measured latency, service level, provider contract,
    procurement, BAA/DPA, production recovery, or SSF/CAEP conformance are outside this local
    decision and remain blocked.

The executable profile is in `src/polaris/security/okta_recovery.py`; the operator contract is in
`docs/operations/okta-continuous-access-gap-recovery.md`.

## Consequences

- The project now has a named provider capability profile and an adversarially tested compensating
  cursor boundary based on current primary documentation.
- The final-SSF receiver covers Okta's documented credential-change event class without weakening
  final top-level subject binding.
- A provider outage or malformed recovery page remains fail closed. No raw identity-log payload is
  admitted to application state or evidence.
- The remaining work is materially narrower but still significant: live tenant conformance,
  confidential credential acquisition, durable page application/cursor commit, gap incident state,
  HA scheduling, metrics/pages, recovery exercise, retention/privacy approval, and owner SLO.
- Okta is a reference implementation choice for this simulation, not an enterprise purchasing
  decision or an assertion that Northstar Medical uses Okta.

## Rejected alternatives

- **Call stream status or verification “replay”:** those operations test current control-plane state
  or delivery and do not return missing historical CAEP events.
- **Accept event-local subject automatically:** that would silently weaken the final-SSF contract
  based on examples rather than observed, approved tenant behavior.
- **Use event hooks as the gap oracle:** Okta documents best-effort, at-least-once delivery, limited
  retry, out-of-order arrival, and no maximum delay. They are useful notifications, not the selected
  recovery ledger.
- **Use bounded System Log queries as the only recovery mechanism:** Okta documents that delayed
  events may be absent from a bounded result. Cursor polling is the safer compensating mode.
- **Advance the cursor before page application:** a crash would permanently skip unapplied access
  changes.
- **Store raw System Log records for convenience:** it adds unnecessary identifiers and operational
  context to the application trust domain.
- **Treat a caught-up page as authorization health:** it would ignore SSF status, correlated
  verification, local durability, and operator recovery criteria.

## Verification

`VER-AUT-029` exercises final-SSF credential-change invalidation, exact event mapping, unsuccessful
event handling, empty-page semantics, credential redaction, provider error classification,
same-origin/path/filter cursor validation, malformed/duplicate page rejection, and local static
analysis. `EVD-M04-001` remains local synthetic evidence only.

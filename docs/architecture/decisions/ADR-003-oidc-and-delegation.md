# ADR-003 — OIDC Access Tokens and Downstream Delegation

**Status:** Accepted for M04 local simulation  
**Date:** 2026-08-11  
**Owners:** IAM Lead and AI Security Lead  
**Related:** REQ-IAM-001/002/005/006/007, CTL-IAM-001/002, RSK-003/004/005/018

## Context

The M01 authenticator uses a shared HS256 development key and embeds roles, facilities, and patient
assignments in a local token. That is useful for deterministic regression tests but is not an
enterprise identity or delegation design. Polaris must distinguish ID tokens from API access
tokens, validate only configured issuers/keys/algorithms/audiences, preserve the end user, prevent
confused-deputy token passthrough, and recheck volatile authorization state before writes.

## Decision

Polaris will accept an RFC 9068-style JWT **access token**, not an OpenID Connect ID token, at its
API boundary. The M04 verifier will:

1. require explicit `typ=at+jwt`, `kid`, and an allowlisted asymmetric algorithm (`RS256` for the
   first adapter);
2. select keys only from a trusted, configured issuer JWKS—never token-supplied `jku`, `x5u`, or an
   arbitrary discovery URL;
3. validate signature, exact issuer, intended API audience, expiry, issued-at time, optional
   not-before time, subject, JWT ID, client ID, and required authorization claims;
4. reject missing, malformed, duplicate/unknown-key, revoked, future-issued, over-age, wrong-type,
   wrong-algorithm, wrong-issuer, and wrong-audience tokens with one non-enumerating API error;
5. map only allowlisted claim shapes into a typed principal; authorization remains a separate
   deterministic server decision; and
6. keep the HS256 authenticator only as an explicitly named legacy local fixture until all tests
   migrate, never as an automatic production fallback.

The current patient-assignment claim is a test attribute, not the production source of truth.
Production-shaped authorization will obtain volatile relationship, consent, and sensitivity state
from authoritative policy information points and recheck it for writes.

Polaris will never pass its incoming bearer token to FHIR, a tool, or another service. The local
token-exchange boundary uses OAuth 2.0 Token Exchange (RFC 8693) to request a distinct, short-lived,
resource/audience-bound token under a server-owned operation policy. The boundary reauthenticates
the subject token, prevents callers from choosing arbitrary resources or scopes, requires exact
SMART v2 `user/Patient.rs user/Consent.rs` scope for the synthetic patient-read operation,
cryptographically validates the returned RFC 9068-style token, rejects broadened scopes, multiple
audiences, the wrong workload client ID, refresh tokens, excessive lifetime, and incoming-token
passthrough, and redacts the credential in its typed result.

The exchange transport is deliberately injected: a production connector must authenticate Polaris
as a confidential workload using an approved mechanism such as private-key JWT or mTLS and must
enforce TLS, redirect, response-size, and secret-logging controls. The disposable HAPI lab has no
enterprise authorization server, so the broker is not connected to it and no synthetic token is
presented as SMART conformance evidence.

Trusted discovery is derived only from the configured HTTPS issuer. Metadata must return the exact
configured issuer; the JWKS endpoint must be HTTPS and on an administrator allowlist. The fetcher
disables redirects, bounds time and response size, validates JSON media types, and never consumes a
token-supplied URL. An unknown `kid` causes at most one cooldown-governed rotation refresh. During a
provider outage, only a previously validated known key may be used and only through a configured
maximum stale age; unknown or older keys fail closed.

Revocation begins with an injected deny registry for deterministic tests. The durable local adapter
defined in `ADR-007` additionally accepts a strict signed SSF/CAEP subset, persists event IDs and
token revocations or monotonic subject invalidation watermarks, rejects replay/confusion, and fails
authentication/readiness when stream freshness is outside its configured bound. Its optional local
push adapter authenticates and bounds RFC 8935-shaped delivery but does not represent an enterprise
TLS/workload edge or stream-management integration. The production pattern combines short token
lifetimes, key rotation, authenticated provider stream delivery or
introspection where supported, and live policy/relationship reauthorization for sensitive reads
and every write. No refresh token is stored in the model, prompt, agent state, browser-local
storage, log, or audit event.

## Local and production-shaped adapters

| Concern | M04 deterministic adapter | Production-shaped expectation |
|---|---|---|
| Issuer metadata | Static JWKS plus trusted discovery adapter with exact issuer and origin allowlist | Enterprise issuer metadata and endpoint ownership approved and monitored |
| Signing keys | Generated RSA tests; bounded cache, unknown-key refresh cooldown, known-key maximum stale age | Provider rotation/revocation events and operational cache objectives verified |
| Session/token | Short-lived API bearer token | Authorization code + PKCE/BFF decision in M07; secure cookie/session controls |
| Entitlements | Typed synthetic attributes | Authoritative IAM/relationship/consent policy information points |
| FHIR delegation | Isolated RFC 8693 broker contract; exact audience/resource/SMART scopes; no HAPI attachment | Confidential-client transport and enterprise authorization/FHIR enforcement verified end to end |
| Revocation | In-memory deny registry plus durable signed-SET receiver, authenticated push, strictly bound final-SSF management, desired/observed reconciliation, bounded safe status reads, lease/cadence/alert state, signed stream updates, correlated/unsolicited verification policy, credential/session/token invalidation, freshness gate, and an Okta cursor read/normalization seam | Enterprise TLS/workload-auth edge, live-provider conformance/lifecycle and approved flood controls, atomic provider-page application/cursor recovery or introspection, deployed HA scheduler/telemetry/page delivery, authoritative entitlements, approved latency SLO, and bounded token lifetime |

## Consequences

- Add PyJWT's cryptographic extra and use generated RSA keys only inside tests.
- Unknown, invalid, or over-stale keys fail closed; only a known validated key has bounded stale use.
- A signed token is evidence of authentication assertions, not authorization to a patient or tool.
- Enterprise IdP/STS integration, workload client authentication, enterprise TLS signal edge,
  live SSF stream lifecycle and approved unsolicited-event operating profile, gap-recovery policy,
  authoritative entitlement sources,
  step-up, and session/CSRF evidence remain required before the enterprise identity control can
  become `implemented`.

## Rejected alternatives

- **Keep HS256 as the primary design:** shared verifier/signing material is not a sound enterprise
  resource-server boundary.
- **Accept ID tokens at the API:** creates cross-JWT confusion and the wrong audience/semantics.
- **Forward the incoming access token to FHIR/tools:** creates confused-deputy, audience, scope, and
  leakage risk.
- **Let the client or model supply issuer/JWKS URLs:** creates SSRF and trust-substitution risk.
- **Treat token roles/assignments as permanently current:** cannot meet revocation or TOCTOU needs.

## Authoritative sources reviewed

- IETF RFC 9068, *JWT Profile for OAuth 2.0 Access Tokens*:
  https://www.rfc-editor.org/rfc/rfc9068.html
- IETF RFC 8725, *JSON Web Token Best Current Practices*:
  https://www.rfc-editor.org/rfc/rfc8725.html
- IETF RFC 9700 / BCP 240, *Best Current Practice for OAuth 2.0 Security*:
  https://www.rfc-editor.org/rfc/rfc9700.html
- IETF RFC 8693, *OAuth 2.0 Token Exchange*:
  https://www.rfc-editor.org/rfc/rfc8693.html
- IETF RFC 8707, *Resource Indicators for OAuth 2.0*:
  https://www.rfc-editor.org/rfc/rfc8707.html
- IETF RFC 8414, *OAuth 2.0 Authorization Server Metadata*:
  https://www.rfc-editor.org/rfc/rfc8414.html
- OpenID Foundation, *OpenID Connect Core 1.0 incorporating errata set 2*:
  https://openid.net/specs/openid-connect-core-1_0.html
- OpenID Foundation, *OpenID Connect Discovery 1.0 incorporating errata set 2*:
  https://openid.net/specs/openid-connect-discovery-1_0.html
- HL7, *SMART App Launch 2.2.0 — Scopes and Launch Context*:
  https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html

Sources were reviewed on 2026-08-11. These standards inform the architecture; they do not certify
the implementation.

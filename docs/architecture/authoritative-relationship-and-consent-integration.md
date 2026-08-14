# NS-ARC-002 — Authoritative Treatment Relationship and Consent Integration Design

**Status:** Design only; no integration is implemented or authorized  
**Date:** 2026-08-13  
**Owners:** Engineering Lead, Privacy Owner, Clinical Safety Lead, and Security Lead  
**Related:** ADR-004, ADR-005, REQ-AUT-*, CTL-AUT-*, RSK-002/003/010, PRI-*, LIM-003, BLK-001,
NS-EXC-001

## Context

Two facts decide every patient read in Polaris: whether the requesting clinician has a treatment
relationship with the patient, and whether Consent permits the disclosure for the stated purpose.

Today both are fixtures. Relationship comes from `assigned_patients` inside the access token, and
Consent comes from `seed_consent_decisions()` in
[patients.py](../../src/polaris/services/patients.py) — a static map of three synthetic patients to
`PERMIT`. The authorization logic around them is real and adversarially tested; the *facts* are not.

This is the largest remaining honesty gap in the M04 authorization story, and it cannot be closed by
writing more local code. It requires authoritative enterprise sources that this simulation does not
have. This document specifies what those sources must provide and how the existing behavior must be
preserved when they arrive, so the gap is a specified integration rather than an open question.

## Why the token is the wrong source for relationship

`assigned_patients` arrives as a claim. Claims are asserted by the identity provider at token
issuance and are stale by construction: a care assignment can end, a patient can transfer, and a
clinician can be removed from a care team while a valid token is still in flight. `ADR-003` already
establishes that event-supplied claim *values* never grant authority; the same reasoning applies to
a relationship list carried in a token.

The token remains the source of *identity* and *purpose*. Relationship must become a lookup against
an authoritative source at decision time.

## Required properties of an authoritative relationship source

The source is the enterprise scheduling, care-team, or ADT system of record — not the FHIR sandbox,
which in this repository is a synthetic mirror.

| Property | Requirement |
|---|---|
| Question answered | "Does subject S have an active treatment relationship with patient P at facility F, now?" — not "list S's patients", which invites enumeration |
| Response | A decision plus a source version and an as-of timestamp, never a patient list |
| Freshness | An explicit maximum age; an answer older than that maximum is not usable |
| Failure | Distinguishable `PERMIT`, `DENY`, and `UNKNOWN`; `UNKNOWN` denies |
| Latency budget | Bounded, with a timeout that produces `UNKNOWN` rather than a hung request |
| Authorization | Its own credential and least-privilege scope; Polaris never reuses the end-user token |
| Auditability | Source system, version, and decision recorded; no patient roster copied into audit |

Relationship break-glass is explicitly out of scope for v1. Emergency access is `BLK-003` and
requires human-factors work before any override path can exist.

## Required properties of an authoritative Consent source

Consent must come from the enterprise consent registry, with the FHIR `Consent` resource as the
interchange representation rather than the record of account.

The existing contract in [patients.py](../../src/polaris/services/patients.py) already models the
right semantics and must be preserved exactly:

- three explicit states — `PERMIT`, `DENY`, `UNKNOWN` — with `UNKNOWN` denying;
- Consent evaluated *before* any full resource read, so a denial never follows a disclosure; and
- Consent and security context re-read after authorization and before projection, with drift
  rejected.

What the authoritative source must add:

- **Scope.** A Consent decision is bound to purpose of use, requesting organization, and data class.
  A `PERMIT` for treatment is not a `PERMIT` for healthcare operations, and Part 2 material is a
  separate determination that cannot be inferred from a general permit.
- **Withdrawal latency.** A stated maximum interval between a patient withdrawing consent and
  Polaris denying. This is a patient-safety and privacy commitment and must have a number, an owner,
  and a test. Cached decisions must not outlive it.
- **Provenance.** Which consent instrument, version, and effective period produced the decision.
- **Non-enumeration.** The interface answers about one patient at a time.

## Preserving current behavior

The integration must not weaken what already passes. Specifically:

- `denial before full read` — the pre-authorization security context lookup stays minimum-scope and
  must not become a full resource fetch to obtain Consent;
- `post-read recheck` — the second evaluation must query the same authoritative sources, not a cache
  populated by the first;
- `fail closed` — a source that is unavailable, stale, or ambiguous denies, and the in-memory and
  HTTP gateways must keep passing the same shared broker contract; and
- `no token passthrough` — relationship and Consent calls use their own credentials, as the RFC 8693
  broker already does for FHIR.

The cleanest seam is to extend the existing `FhirPatientGateway` protocol with a relationship query
and to move `consent_decision` out of the gateway constructor and behind the same protocol, so the
in-memory oracle and any enterprise adapter remain interchangeable under one contract.

## Staleness is the hard problem

Both facts are revocable, and a cache is the obvious way to meet a latency budget. A cache is also
how a withdrawn consent keeps permitting disclosure.

The position taken here: relationship and Consent decisions may be cached only within an interval
the Privacy Owner approves, that interval must be shorter than the stated withdrawal latency, and
the cache must be invalidated by the same continuous-access signal path that already invalidates
sessions. If the enterprise cannot supply a withdrawal signal, the cache interval must be zero and
the latency budget met by the source, not by Polaris.

## What this design does not decide

- Retention of relationship and Consent decision records (`BLK-001`).
- Legal sufficiency of any Consent model. That is a Legal and Privacy determination and cannot be
  simulated.
- Whether Part 2 material may be disclosed under any consent instrument. The current behavior —
  deny — remains until a real determination exists.
- Vendor or product selection for either source (`BLK-004`).

Until those exist, the fixtures stay, `LIM-003` stays open, and no claim of authoritative
relationship or Consent enforcement may be made. `NS-EXC-001` records the deferral.

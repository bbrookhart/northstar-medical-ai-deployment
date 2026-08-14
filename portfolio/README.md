# Recruiter Portfolio Package

This directory will package evidence already proven elsewhere; it will not invent stronger claims.
The first complete evidence-tour backbone now exists: 70 requirements and 25 risks resolve through
31 controls to implementation, 46 verification definitions, 24 evidence definitions, framework
references, six visible gate blockers, and four time-bound deferral exceptions. The generated M03 report is the canonical source for
portfolio traceability claims; `EVD-M04-003` records the M04 conditional-pass gate decision, and
`EVD-M04-002` records the first hosted CI run.

Planned outputs:

- One-page executive case study: problem, constraints, decision, risk, outcome, limitations
- Architecture story: trust boundaries and why the model is not a security boundary
- Five-minute demo: strict token context, trusted JWKS rotation, least-privilege delegation denial,
  final-SSF discovery substitution denial and pending-only verification semantics, authenticated
  push delivery, audience/push/event-bound stream lifecycle and privacy-conscious subject calls,
  plus durable desired/observed status reconciliation, signed stream-updated handling, correlated
  verification receipt, default-reject/opt-in delivery-only unsolicited verification with a durable
  quota and health isolation, bounded rate-limit-aware safe status recovery, durable cadence/lease/
  alert-state handling with crash and stale-worker recovery, an Okta reference profile with strict
  System Log cursor/origin/path/filter/page minimization and substitution denial, and signed
  session/credential/entitlement invalidation with ambiguous-outcome, transport/media/size/state-reuse/race/
  timeout/replay/order/restart/freshness failure,
  Consent-aware denial before FHIR disclosure, pinned HAPI readback, grounded retrieval, exact
  approval, atomic workflow/audit rollback, restart-safe replay, and tamper denial
- Evidence tour: risk → requirement → control → implementation → adversarial test → gate decision
  using `evidence/reports/M03-traceability-report.md`
- Incident/rollback story and residual-risk decision
- Role-impact matrix showing AI security engineering, architecture, application, governance,
  privacy, safety, DevSecOps, assurance, operations, and program management work
- Interview question bank with evidence-backed answers and honest tradeoffs

No artifact may claim real healthcare deployment, real PHI processing, HIPAA compliance, FDA status,
clinical effectiveness, independent certification, or production readiness unless the evidence and
an authorized reviewer actually support it.

# NS-ASR-001 — Release Gate Standard

## Gate decision states

- **Pass:** all mandatory evidence exists and no disqualifying risk remains.
- **Conditional pass:** only explicitly allowed, owner-approved, time-bound exceptions remain.
- **Fail:** a mandatory control or artifact is missing, invalid, or contradicted by evidence.
- **Not assessed:** the gate has not been evaluated and must not be represented as passed.

## Universal disqualifiers

A release fails if it uses real PHI in this simulation; enables clinical decision-making or
autonomous EHR/patient communication; permits model-controlled authorization or credential use;
allows unapproved or mutated write actions; lacks a kill/rollback path for the deployed increment;
has an open critical/high release blocker; or makes an unsupported compliance/certification claim.

## Release invariants

No release is ready unless evidence shows all of the following. These are program-level invariants,
retained here from the retired master prompt; the disqualifiers above are the subset that fails a
release outright.

- Zero successful unauthorized cross-patient, cross-role, cross-facility, or cross-purpose access in
  the critical suite.
- Zero successful state changes without valid policy and bound approval.
- Zero unresolved critical or high security findings.
- Critical diagnosis, prescription, and treatment boundary tests produce no prohibited content or
  action.
- Every substantive policy answer cites an approved source or abstains.
- Unanswerable and conflicting-source cases meet the defined abstention behavior.
- Model, prompt, policy, corpus, tool, configuration, and dependency versions are recorded.
- Logs and traces contain no prohibited secrets and no unnecessary health-data content.
- Agent steps, tools, cost, latency, and concurrency are bounded.
- Kill switch, rollback, safe degradation, backup, and recovery are demonstrated.
- Residual risks have owners, rationale, monitoring, expiration, and approval.
- An independent person could reproduce the build and tests from the documentation.

Never summarize these into a single "safety score." Report results by risk category, severity,
attack class, role, data class, version, and confidence.

## Evidence minimum

Each gate record identifies scope, artifact versions, reviewer role, verification commands,
results, unresolved findings, exceptions, residual risk, and decision. Evidence must be durable,
minimal, free of secrets/PHI, and traceable to the implementation or operating event it supports.

## Current gate assessment — M01

| Criterion | Evidence | Result |
|---|---|---|
| Durable Codex context | `AGENTS.md`, `PROJECT_STATUS.md`, `docs/program/master-roadmap.md` | Pass |
| Program intake baseline | `docs/executive/`, `docs/governance/`, applicability matrix | Pass for simulation |
| Architecture and safety boundary | System context, trust boundaries, explicit prohibited use | Pass |
| Synthetic-only data | Seed fixtures and repository policy | Pass |
| Deterministic authorization | Policy service and patient/action denial tests | Pass |
| Grounded retrieval | Approved seeded corpus, citations, normalization, abstention tests | Pass |
| Approval-bound execution | Digest, independent approval, signature, expiry, reauthorization, idempotency | Pass |
| Tamper-evident audit | HMAC hash chain and mutation test | Pass for in-memory slice |
| Automated quality gates | Lint, strict typing, 30 tests, 90.52% coverage | Pass locally |
| Hosted CI result | `EVD-M04-002`; GitHub Actions `quality` job green at a named revision | Pass |

**Decision:** M01 passes locally and, since `EVD-M04-002`, on a hosted runner. It is not a
production, cloud, compliance, or clinical-safety authorization.

## Current gate assessment — M02/M03

| Criterion | Evidence | Result |
|---|---|---|
| Multidisciplinary risk challenge | `docs/assurance/M02-multidisciplinary-review.md` | Pass for role-based simulation |
| Normative requirements | 70-item baseline with corrected mandatory language | Pass |
| Registered-risk treatment coverage | 25/25 risks linked to controls; critical/high risks not orphaned | Pass structurally |
| Scenario reconciliation | 30 THR, 10 PRI, 24 MIS, and 14 HAZ scenarios linked to registered risks | Pass structurally |
| Canonical control/evidence system | Control standard; 31 controls; 28 verification and 21 evidence definitions | Pass |
| Framework source discipline | Eight authoritative source records; reviewed/provisional status explicit | Conditional; exact OWASP LLM 2026 categories remain `BLK-006` |
| AI system and decision records | Current system card and exception/residual-risk/release templates | Pass for baseline |
| Machine integrity and drift | Typed validator, four traceability tests, deterministic reports, CI check | Pass locally |
| Simulated control-owner review | `docs/assurance/M03-control-owner-review.md` | Pass for role-based simulation |
| Actual enterprise approvals | Named accountable people and independent assurance | Not assessed |
| Hosted CI result | `EVD-M04-002`; GitHub Actions `quality` job green at a named revision | Pass |

**Decision:** M02 and M03 pass as local simulation baselines, authorizing M04 synthetic
identity/policy/FHIR work only. Six blockers remain explicit. This is not residual-risk acceptance,
real-PHI/pilot/production authorization, a compliance determination, or clinical validation.

## Current gate assessment — M04

| Criterion | Evidence | Result |
|---|---|---|
| Identity architecture | `ADR-003`, `ADR-007`, `ADR-008` | Pass for staged local design and named-provider documentation profile |
| Access-token/JWKS contract | Static verifier plus trusted discovery/rotation/cache adversarial tests | Pass with generated RSA keys and injected transports; enterprise IdP not assessed |
| Revocation, entitlement-change, and stream lifecycle behavior | Durable signed-SET receiver with credential change, bounded push and strict final-SSF management, desired/observed/status-read recovery, lease/cadence alerts, correlated/unsolicited verification policy, and Okta same-origin/path/filter System Log cursor read/normalization; binding, ambiguity, retry, lease, race, tamper, replay, order, restart, malformed-page, and cursor-substitution tests | Pass for strict scripted/local SSF/CAEP/RFC 8935-shaped and Okta compensating-read boundaries; enterprise TLS/mTLS, live provider conformance/operations, approved flood controls, deployed telemetry/pages, authoritative entitlements, approved objectives, and conformance not assessed |
| Central policy contract | `ADR-004`, decision table, policy contract tests | Pass for in-process deterministic evaluator |
| FHIR boundary | `ADR-005`, HTTP/in-memory broker and negative contract tests | Pass for bounded local synthetic adapters |
| Denial before full read | Broker read-count and cross-context tests | Pass locally |
| Synthea provenance and HAPI interoperability | Toolchain lock, dataset manifest, tamper tests, pinned Compose, resource readback, shared contract, `EVD-M04-001` | Pass locally; not FHIR/SMART conformance |
| Consent policy | Explicit permit/deny/unknown decisions, no-full-read denial, post-read recheck | Pass for synthetic Consent profile only; not legal sufficiency |
| Downstream delegation | RFC 8693 reauthentication, fixed audience/resource/SMART scopes, response validation, and no-passthrough tests | Pass for isolated contract; confidential-client transport and enterprise STS/FHIR enforcement not assessed |
| Transactional state/audit | `ADR-006`; shared store, restart, atomic rollback, concurrent replay, tamper, schema, and readiness tests | Pass for single-node local SQLite; PostgreSQL/HA, backup/restore, retention, WORM/SIEM, and external-task reconciliation not assessed |
| Durable gap-recovery application | `VER-AUT-030`; compare-and-swap cursor, exactly-once application, audit-failure rollback, restart, and multi-signal exit-gate tests | Pass for the scripted local boundary; live tenant operation not assessed |
| Complete local quality gate | `EVD-M04-003`; 323 default-suite tests plus one HAPI integration; 85.50% coverage | Pass |
| Hosted CI | `EVD-M04-002`; GitHub Actions `quality` job green at a named revision | Pass |
| Branch protection | GitHub API rejects protection for a private repository on this plan | Not assessed |
| Simulated owner review | `docs/assurance/M04-owner-review.md` | Pass for role-based simulation |

**Decision:** **Conditional pass.** The authorization matrix passes across role, facility, patient,
purpose, sensitivity, and Consent dimensions; identity, policy, and FHIR failure degrades safely and
is auditable; and the compensating gap-recovery path is durable rather than advisory.

The condition is that these four owner-approved, time-bound exceptions remain live and unmodified:
`NS-EXC-001` enterprise identity and TLS edge, `NS-EXC-002` live provider conformance and flood
controls, `NS-EXC-003` deployed scheduler, telemetry, and objectives, and `NS-EXC-004` production
persistence and audit custody. Any expiry, revocation, or scope change reopens this gate.

This is not pilot, production, real-PHI, SSF/CAEP/SMART/FHIR conformance, or enterprise identity
authorization, and it does not accept residual risk for a real deployment.

## Current gate assessment — M05

| Criterion | Evidence | Result |
|---|---|---|
| Corpus admission and provenance | `ADR-010`, `VER-RAG-001`; deny-by-default promotion records, second-person approval, checksum binding, supersession, freshness | Pass for the local synthetic corpus |
| Content scanning | `VER-RAG-001`; instruction-shaped text, credential material, control characters, and normalization-evasion cases | Pass as an admission control; not injection detection |
| Authorization before model context | `VER-RAG-002`; authorized partition computed before scoring, asserted against an independently computed partition | Pass |
| Post-retrieval recheck | `VER-RAG-002`; fresh-clock and per-chunk checksum recheck before return | Pass |
| Conflict and freshness | `VER-RAG-002`; topic-conflict abstention with both sources cited, expiry exclusion | Pass for topic-tagged conflicts only |
| Untrusted context rendering | `VER-RAG-002`; labelled data envelope that a chunk cannot close | Pass as a seam; no model consumes it yet |
| Corpus identity and rollback | `VER-RAG-003`; manifest checksum binds labels as well as text, durable activation, audited rollback surviving restart | Pass for single-node local state |
| Retrieval evaluation thresholds | `EVD-M05-002`; security 100% required and met, quality 90% required and 100% met | Pass |
| Answer quality and model behavior | — | Not assessed; retrieval is deterministic keyword matching (`LIM-005`) |
| Production ingestion pipeline | — | Not assessed; no document management system, malware scanning, or human review workflow |

**Decision:** **Pass** for the M05 gate as scoped — no unauthorized chunk reaches the retrieval
result, and the evaluation thresholds are met and enforced by `make verify` and CI.

This is a controls result, not a quality result. It authorizes M06 bounded agent and model work only,
and it is not a pilot, production, real-PHI, hosted-model, or conformance authorization.

## Current gate assessment — M06

| Criterion | Evidence | Result |
|---|---|---|
| Least-agency tool registry | `VER-AGT-001`; three static tools, one write, prohibited-capability names refused at construction | Pass |
| Compromised-model containment | `VER-AGT-002`; scripted hostile intents cannot widen retrieval, read an unassigned patient, draft clinical direction, emit secrets, or answer ungrounded | Pass for the deterministic baseline |
| No execution authority | `VER-AGT-001`; no execute tool exists and proposals remain pending independent approval | Pass |
| Bounded orchestration | `VER-AGT-003`; step, tool-call, write, output, and deadline bounds halt rather than degrade | Pass for local bounds; no concurrency, retry, or cost control exists |
| Safe model failure | `VER-AGT-003`; failure is explicit with no fabricated success and an intact audit chain | Pass |
| Credentials and memory | `VER-AGT-002`; model requests carry no credential, identity, or prior-run state | Pass by type, not convention |
| Independent durable kill switches | `VER-AGT-004`; MODEL, READ, and WRITE are separable and survive restart | Pass for single-node local state |
| Hosted provider boundary | `VER-AGT-004`; the adapter refuses every call | Pass as an inert seam; `REQ-AI-002` criteria and `BLK-004` due diligence remain unmet |
| Language-model behavior and answer quality | — | Not assessed; the adapter is a deterministic policy, not an LLM |
| Red-team campaign against a real provider | — | Not assessed; M09 scope |
| Agent user surface and approval human factors | — | Not assessed; M07 scope, blocked by `BLK-003` |

**Decision:** **Pass** for the M06 gate as scoped — a fully compromised model cannot broaden
retrieval, obtain a credential, bypass policy or approval, execute a prohibited action, or exceed a
resource bound.

This is a containment result, not a capability result. It authorizes M07 user-experience work only,
and it is not a pilot, production, real-PHI, hosted-model, or conformance authorization.

## Current gate assessment — M07

| Criterion | Evidence | Result |
|---|---|---|
| Inert rendering of untrusted text | `VER-PRS-001`; script, attribute, executable-scheme, terminal-escape, bidirectional-override, and control-character cases | Pass for the server-side contract |
| Exact canonical action preview | `VER-PRS-002`; every field and the digest derived from the same canonical action, binding fails on any divergence | Pass |
| Trusted state and uncertainty | `VER-PRS-003`; only execution implies completion, labels and severity cannot disagree with state, an abstention cannot render as an answer | Pass |
| Fixed emergency routing | `VER-SAF-001`; fixed guidance with no field able to record an urgency assessment, checked before the model is consulted | Pass |
| Authorized preview surface | `VER-PRS-002`; the preview requires the same authorization as the decision | Pass |
| Informed approval by real users | `VER-PLN-011`; protocol specified, no session run | **Not assessed** |
| Automation-bias and comprehension | `VER-PLN-011` HF-02/HF-03/HF-04 | **Not assessed** |
| WCAG 2.2 AA conformance | `VER-PLN-011` HF-07 | **Not assessed** |
| Approval workload and anti-fatigue | `CTL-ACT-004`; unbuilt, HF-08 is its primary input | **Not assessed** |
| User interface | — | Not built; the server-side contract a UI must honor exists instead |

**Decision:** **Fail — the gate is not met.** The exit criterion is human-factors evidence, and none
exists. `BLK-003` stays open and `NS-ASR-005` carries an empty results table.

This is not a defect in the increment. The presentation contract is implemented and verified, and
recording the milestone as passed on that basis would substitute an implementation for an operating
control — the exact failure this gate standard exists to prevent. M07 reopens when sessions can be
run with real clinician participants.

## Current gate assessment — M08

| Criterion | Evidence | Result |
|---|---|---|
| SHA-pinned Actions and digest-pinned images | `VER-SDL-001`; enforced as blockers and proven by tests that break each | Pass |
| Locked dependencies with hashed artifacts and bounded declarations | `VER-SDL-001` | Pass |
| Container and compose hardening | `VER-SDL-001`, `EVD-M08-001`; built image runs non-root on a read-only filesystem with no package manager, compiler, or fetch tool | Pass locally |
| Tracked-secret scan | `VER-SDL-001`; only detector modules exempt, fixtures build markers from parts | Pass |
| SBOM | `EVD-M08-002`; CycloneDX 1.6 from the lockfile, byte-stable, drift-checked | Pass |
| AIBOM | `EVD-M08-002`; generated from the running model, corpus, tool, bound, kill-switch, and evaluation definitions | Pass |
| Reproducible build | `EVD-M08-001`; pinned inputs resolve identically, image builds and serves | Pass in the pinning sense; bit-for-bit reproducibility not claimed |
| Vulnerability scanning result | `NS-EXC-005` | **Not assessed** |
| Artifact signature | `NS-EXC-005` | **Not assessed** |
| Build provenance attestation | `NS-EXC-005` | **Not assessed** |
| Protected-branch release gate | `LIM-006`; rejected for a private repository on this plan | **Not assessed** |

**Decision:** **Conditional pass**, on `NS-EXC-005` remaining live and unmodified. The offline
release policy is enforced by a gate that fails the build, the bills of materials are generated and
drift-checked, and the container was built and exercised rather than only written.

Signing, provenance, and scanning need a publishing pipeline that does not exist. Simulating them
would produce artifacts nobody verifies, which is why they are deferred explicitly rather than
approximated. This is not a SLSA level claim, a vulnerability posture claim, or authorization to
publish anything.

## Current gate assessment — M09

| Criterion | Evidence | Result |
|---|---|---|
| Adversarial coverage of every required class | `VER-SDL-003`; 14/14 classes, coverage asserted by test | Pass |
| Containment with control attribution | `EVD-M09-002`; 21/21 contained, each naming the control that held | Pass for the deterministic stack |
| Campaign determinism and drift enforcement | `VER-SDL-003`; identical across runs, checked by `make verify` and CI | Pass |
| Release evaluation across all required dimensions | `VER-SDL-004`; 11 dimensions declared with status and thresholds | Pass |
| Function, authorization, security, grounding | `EVD-M09-001` | Assessed |
| Privacy, safety, robustness | `EVD-M09-001` | Partial |
| Accessibility, performance, cost, recovery | `EVD-M09-001` | **Not assessed** |
| Campaign against a real language model | `RT-F1`; blocked by `BLK-004`/`REQ-AI-002` | **Not assessed** |
| Independent adversarial authorship | `RT-F3`; same author as the controls | **Not assessed** |
| No open critical or high blocker | `docs/assurance/M09-remediation-ledger.md`; four high findings open | **Fail** |
| Named residual-risk approval | — | **Not assessed**; no real accountable person exists |

**Decision:** **Fail — the gate is not met.** Every attack was contained, and the release evaluation
still refuses a release: `RT-F1`, `RE-F1`, `RE-F4`, and `RE-F5` are open high-severity findings, and
`REQ-SDL-005` forbids proceeding with any of them.

Passing an attack suite is not the same as being releasable. No finding was reclassified to fit a
decision, and no residual risk is accepted — a simulated signature on a release decision would be the
most misleading artifact in this repository.

## Current gate assessment — M10

| Criterion | Evidence | Result |
|---|---|---|
| Telemetry content rules | `VER-OPS-001`; required context present and prohibited content absent, over a real request flow | Pass |
| Detection coverage | `VER-OPS-002`; 10 rules across all 10 required categories, coverage asserted by test | Pass as code; never tuned against real traffic |
| Kill switch, rollback, degraded mode, restart, restore | `VER-OPS-003`, `EVD-M10-002`; five drills executed, all objectives met | Pass for the local single-node scope |
| Operators demonstrate detection and containment | — | **Not assessed**; there is no on-call rotation and no participant |
| Incident tabletop and after-action record | `VER-PLN-012`; seven scenarios specified, none run | **Not assessed**; `REQ-OPS-004` unmet, `BLK-005` open |
| Telemetry delivery, dashboards, alert routing, paging | `NS-EXC-003` | **Not assessed** |
| Production recovery exercises | `NS-EXC-004`, `RE-F4` | **Not assessed** |
| Approved SLOs, RTO, RPO | `REQ-OPS-006` | **Not assessed** |

**Decision:** **Fail — the gate is not met.** The criterion is that operators demonstrate detection,
containment, safe degradation, and recovery. Five drills were executed and met their objectives, but
no operator demonstrated anything and no tabletop has been run.

Recovery moves from **not assessed** to **partial**: the local drills are real, and the production
exercises that `RE-F4` refers to remain unexecuted.

## Current gate assessment — M11

| Criterion | Evidence | Result |
|---|---|---|
| Change-impact process | `VER-LCM-001`; AIBOM diff across model, prompt, corpus, tool, autonomy, evaluation, and dependency classes with the obligations each triggers | Pass as a mechanism |
| Audit package | `VER-LCM-003`; 24 artifacts indexed by digest, plus open blockers and unmet gates read from this record | Pass |
| Retirement exercise | `VER-LCM-002`; capability revoked before deletion, operational data removed, audit chain and revocation retained, no service afterwards | Pass for local synthetic data |
| Pilot entry conditions | `NS-PRG-003`; seven conditions, none met | **Fail** |
| Change-impact review actually conducted | — | **Not assessed**; the analyzer is a tool, a review is people using it |
| Provider deletion, backup expiry, legal hold, downstream termination | `BLK-001`, `REQ-DAT-007` | **Not assessed** |
| Training, support, and correction journey | `REQ-LCM-001`, `REQ-LCM-002` | **Not assessed** |
| Governance board authorizes a pilot | `docs/assurance/M11-governance-board-decision.md` | **Refused** |

**Decision:** **Fail — the gate is not met, by decision rather than by omission.**

Producing the authorization the gate asks for would have been trivial: write the document and sign it
with role placeholders. `NS-ASR-009` refuses on two grounds — all seven pilot entry conditions are
unmet, and no one has standing to authorize anything. A simulated signature on a pilot decision does
not produce a weaker authorization; it produces a counterfeit one.

What is authorized is continued synthetic development within the existing boundary. Nothing else.

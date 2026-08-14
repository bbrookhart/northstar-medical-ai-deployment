# NS-PRG-001 — Project Polaris Master Roadmap

**Owner:** AI Security Program Lead  
**Baseline date:** 2026-08-11 (updated 2026-08-13)  
**Delivery model:** Evidence-gated increments; one production-shaped vertical slice  
**Current position:** M00–M09 built as local simulations, with M04 a conditional pass on four
time-bound exceptions and M05/M06 passing their gates for the deterministic baseline; the repository
is under version control with a green hosted CI run; enterprise integration, live provider operation,
hosted-model due diligence, authoritative relationship/Consent sources, and production
persistence/recovery are specified, deferred, and unbuilt; M07's presentation contract is built but
its gate is not met without human-factors evidence (`BLK-003`); M08 is a conditional pass with
signing, provenance, and scanning deferred under `NS-EXC-005`; M09's campaign contains every attack
yet its gate is not met because four high-severity findings are open; M10 operations and incident
readiness is next

## Delivery doctrine

Polaris is not complete when the chatbot works. It is complete when Northstar can show why the
system exists, who is accountable, which risks were accepted, which controls operate, how those
controls were tested, how failure is detected and contained, and how the system can be retired.

Every milestone ends with a gate. A gate passes only when its required evidence is reviewable.
Documentation without implementation is not control evidence, and an implementation without a
test or operating record is not release evidence.

## Workstreams

| Workstream | Outcome |
|---|---|
| Program and product | Charter, ownership, funding assumptions, scope, backlog, gates, success measures |
| Governance and compliance | Inventory, policy, impact assessment, accountability, applicability, exceptions |
| Security, privacy, and safety | Threat/privacy/hazard models, requirements, controls, residual-risk decisions |
| Application and agent engineering | Secure UI/API, bounded orchestration, retrieval, tools, approvals, model adapters |
| Platform and data | Identity, policy service, FHIR sandbox, storage, secrets, telemetry, deployment |
| Assurance and red team | Evaluation corpus, adversarial tests, independent review, remediation, release case |
| Operations and resilience | Detection, response, rollback, continuity, change control, retirement |
| Portfolio and training | Executive narrative, technical demo, evidence tour, labs, instructor material |

## Milestones and gates

| ID | Milestone | Principal deliverables | Exit gate | State |
|---|---|---|---|---|
| M00 | Repository and Codex foundation | `AGENTS.md`, master prompt, status ledger, conventions, lockfile | A new Codex session can resume safely and reproduce checks | Complete locally |
| M01 | Intake and first secure vertical slice | Charter, enterprise profile, approved use, RACI, risk tier, applicability matrix, context architecture, risk register, deterministic API | Synthetic policy/read/action flow enforces core invariants and all local quality gates pass | Complete locally |
| M02 | Requirements and risk design | AI impact assessment, DPIA, STRIDE, LINDDUN, ATLAS/OWASP mapping, misuse cases, clinical hazards, abuse trees, security/privacy/safety requirements | Every material risk has an owner, treatment, control, test, and residual target | Complete — simulated review |
| M03 | Canonical control system | Northstar control library, framework crosswalks, evidence schema, exception/risk-acceptance workflow, AI system card | Control owners approve testable control statements and evidence expectations | Complete — simulated review and CI validation |
| M04 | Identity, policy, and FHIR integration | Local OIDC, end-user identity propagation, continuous-access signals, SMART-style scopes, centralized policy adapter, Synthea FHIR/HAPI sandbox, consent/security labels, transactional application/audit state | Authorization matrix passes across role/facility/patient/purpose/sensitivity/consent dimensions | Conditional pass — trusted discovery/rotation, isolated delegation, durable local SSF/CAEP invalidation, bounded authenticated push, strictly bound final-SSF management, desired/observed reconciliation, safe status reads, lease-protected recovery cadence, correlated/unsolicited verification policy, durable compare-and-swap gap-page application with a multi-signal exit gate, Synthea/HAPI/Consent, SQLite, hosted CI, and simulated owner review complete; enterprise identity/TLS, live provider conformance, deployed scheduler/telemetry, SMART enforcement, authoritative relationship/Consent sources, and production persistence deferred under `NS-EXC-001` to `NS-EXC-004` |
| M05 | Secure RAG | Authorized ingestion, provenance, classification, poisoning defenses, retrieval filters, citation verification, corpus rollback | No unauthorized chunk reaches model context; retrieval evaluation thresholds pass | Complete locally — deny-by-default admission with promotion records, authorization computed before scoring, integrity and freshness recheck, topic-conflict abstention, data-only context rendering, manifest identity binding labels, durable audited corpus rollback, and a gated golden set at 100% security and 100% quality; production ingestion, malware scanning, human review, durable corpus storage, and answer quality remain |
| M06 | Bounded agent and model layer | Explicit state machine, deterministic adapter, hosted-provider adapter contract, typed tools, resource budgets, kill switch | Compromised-model tests cannot bypass authorization, approval, or execution controls | Complete locally — explicit transition table, three-tool least-agency registry with prohibited-capability refusal, per-call authorization re-derived from the principal, grounding/disclosure/clinical output validation, step/tool/output/deadline budgets, independent durable MODEL/READ/WRITE kill switches, and an inert hosted-provider seam; language-model behavior, provider due diligence, red-team campaign, and the agent user surface remain |
| M07 | User experience and approval safety | React UI, transparent sources, uncertainty, safe rendering, exact action preview, reauthentication, accessibility | Human-factors tests show informed approval and safe refusal/degraded behavior | **Gate not met** — the server-side presentation contract is implemented and verified (inert rendering, canonical action preview bound to its recomputed digest, states where only execution implies completion, uncertainty that cannot be dropped, fixed emergency routing), but the human-factors evidence the gate requires does not exist; `BLK-003` and `NS-ASR-005` remain open |
| M08 | Secure platform and supply chain | Containers, local compose, CI security suite, SBOM/AIBOM, signed artifacts, provenance, secrets and IaC patterns | Reproducible build and deploy passes vulnerability and configuration release policy | Conditional pass — an offline release gate enforces SHA-pinned Actions, digest-pinned images, bounded and hashed dependencies, container hardening, and a tracked-secret scan, each proven by a test that breaks it; CycloneDX SBOM and a generated AIBOM are committed and drift-checked; the container is built and smoke-tested non-root on a read-only filesystem. Signing, provenance, and vulnerability scanning deferred under `NS-EXC-005`; branch protection remains `LIM-006` |
| M09 | Full assurance and red team | Functional/safety/privacy/security/robustness/performance evals, adversarial campaigns, remediation ledger, independent review simulation | No open critical/high release blockers; residual risk receives named approval | **Gate not met** — 21 attacks across all 14 required classes were contained with control attribution, and the release evaluation declares all 11 dimensions with four not assessed; four high-severity findings remain open (`RT-F1`, `RE-F1`, `RE-F4`, `RE-F5`) so no release may proceed and no residual risk is accepted |
| M10 | Operations and incident readiness | Telemetry, detections, dashboards, SLOs, runbooks, incident playbooks, tabletop, backup/restore, rollback drills | Operators demonstrate detection, containment, safe degradation, and recovery | Planned |
| M11 | Pilot, change control, audit, retirement | Pilot plan, training, support, monitoring thresholds, change impact, audit package, exit/retirement plan | Simulated governance board authorizes pilot and later production/retirement decisions | Planned |
| M12 | Recruiter case study and paid training | Executive brief, architecture/evidence tour, demo script/video plan, lab guides, solutions, assessments, instructor notes | Independent learner can reproduce labs; portfolio claims trace to repository evidence | Planned |

## Critical path

M02 risk and requirements work precedes deeper integrations. M03 now provides the traceability system
used by every later gate. Identity/policy/FHIR (M04) and secure RAG (M05) precede hosted model and
agent capability (M06). The UX (M07) must expose the guarantees already enforced by the backend.
Platform hardening (M08) precedes full assurance (M09), which precedes operational authorization
(M10–M11). Portfolio and training work begins throughout but is packaged only after evidence exists.

## Definition of done for every increment

- Scope and assumptions are explicit.
- Security, privacy, patient-safety, and compliance impact are assessed.
- Threats and failure modes have deterministic mitigations where feasible.
- Behavior is covered by positive, negative, boundary, and adversarial tests.
- Source, dependency, configuration, and evidence changes are reviewable.
- Verification commands and results are recorded.
- Known limitations, residual risk, and next safe increment are honest.
- Recruiter claims and training learning objectives reference real artifacts.

## Program success measures

| Dimension | Target |
|---|---|
| Traceability | 100% of release-critical requirements map to controls, tests, evidence, and owners |
| Authorization | 100% pass rate for deny-by-default identity/purpose/resource/action matrix |
| Grounding | All substantive policy answers cite approved, versioned sources or abstain |
| Agency | No write executes without exact-argument approval, reauthorization, integrity, expiry, and idempotency checks |
| Privacy | No real PHI; no prohibited sensitive payloads in normal logs, traces, screenshots, or evidence |
| Safety | No diagnosis, treatment, prescribing, autonomous clinical decision, EHR write, or patient message in v1 |
| Assurance | No open critical/high gate blockers; exceptions are time-bound and owner-approved |
| Recovery | Kill switch, provider/corpus/prompt rollback, and safe degraded mode proven through exercises |
| Reproducibility | A clean environment can install from the lockfile and pass the documented gates |

## Explicit deferrals

Real PHI, real EHR access, production cloud deployment, autonomous clinical actions, patient-facing
communication, persistent agent memory, multi-agent systems, and vendor selection are outside the
current authorization. Each requires a documented scope change and renewed legal, privacy,
security, clinical-safety, and governance review.

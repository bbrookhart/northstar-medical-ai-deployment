# NS-AIA-002 — Polaris AI Impact Assessment

**Status:** M02 simulated multidisciplinary review complete; real owner validation required  
**System tier:** T3 — High impact  
**Owners:** AI System Owner and Business Owner  
**Reviewers:** Clinical Safety, Privacy, Security, Legal/Compliance, Workforce, Accessibility, Data  
**Date:** 2026-08-11

## Decision being assessed

Whether Northstar should continue developing and testing Polaris as an internal care-coordination
assistant with policy retrieval, minimal synthetic patient context, drafting, and one bounded,
approval-gated administrative action. This assessment does not authorize a real-data pilot.

## Intended benefit and evidence needed

| Intended benefit | Measurement before pilot | Guard against |
|---|---|---|
| Reduce time locating approved policy | Task-completion time and correct-source rate versus baseline | Faster but wrong/outdated answers |
| Reduce administrative drafting burden | Time saved, edit distance, user acceptance, defect sampling | Automation bias and hidden clinical content |
| Improve follow-up consistency | Required-field completeness and queue error rate | Unnecessary or duplicate tasks |
| Improve policy/action traceability | Citation, decision, approval, execution, and audit completeness | Surveillance or excessive data collection |
| Provide reusable secure AI pattern | Control/test/evidence traceability and independent review | Portfolio claims exceeding evidence |

No benefit may be claimed from synthetic usability tests as a demonstrated patient outcome.

## Affected parties

- Care coordinators, nurses, approvers, help desk, SOC, privacy/compliance, clinical-safety staff
- Patients whose production-analog information or care workflows could be affected
- People with disabilities, limited English proficiency, limited digital fluency, or atypical care paths
- Northstar data stewards, system owners, leaders, auditors, and third-party providers
- People represented in source policies or workforce analytics, even if not direct users

## Alternatives considered

| Alternative | Benefit | Risk/limitation | Disposition |
|---|---|---|---|
| Do nothing | No new AI attack surface | Existing search and workflow burden remains | Baseline comparator |
| Improve conventional search/forms | Predictable, lower AI risk | Less flexible language support | Must remain fallback; evaluate first |
| Retrieval-only assistant | High value with less agency | Still has privacy, injection, grounding risk | Preferred initial pilot capability |
| Drafting without patient context | Lower disclosure risk | Lower task usefulness | Use where patient data is unnecessary |
| Full autonomous agent | Maximum automation | Unacceptable safety, agency, accountability risk | Prohibited |

## Impact analysis

| Dimension | Plausible beneficial impact | Plausible adverse impact | Required treatment |
|---|---|---|---|
| Patient safety | More consistent administrative follow-up | Wrong/delayed task, clinical advice, missed escalation | Non-clinical scope, fixed emergency language, clinical hazard tests, human workflow |
| Privacy | Less copying across systems if minimized | Cross-patient disclosure, curiosity use, provider/log leakage | Purpose/resource policy, minimization, sensitivity labels, DLP, audit |
| Security | Centralized guarded integration | Prompt injection, poisoned sources, tool abuse, stolen identity | Untrusted-model design, typed tools, provenance, deny default, red team |
| Autonomy/dignity | Workers retain decisions with assistive drafting | Patient/workforce decisions become opaque or depersonalized | No sole-basis decisions, review/edit, disclose role in workflow where appropriate |
| Equity | Language/accessibility support may reduce burden | Uneven errors, inaccessible approval, dialect/name failures | WCAG, subgroup scenarios, language-quality review, alternate path |
| Workforce | Less repetitive work and clearer evidence | Deskilling, surveillance, workload compression, job anxiety | Worker participation, training, no hidden productivity scoring, feedback/appeal |
| Legal/rights | More consistent use of approved policy | Inaccurate legal/policy statement or retained data | Citations, versioning, legal review, records/privacy decisions, abstention |
| Operations | Standardized traceable action | Provider dependency, cost spike, queue flood, outage | Budgets, SLOs, safe degradation, rollback, duplicate protection |
| Environment/cost | Bounded model usage can be measured | Unnecessary inference/resource use | Least-agency architecture, budgets, model/right-sizing metrics |

## Human oversight design

The user chooses the purpose and request. Deterministic code authorizes data. The application shows
sources and uncertainty. The user may edit or abandon drafts. A distinct authorized approver reviews
the exact action. Execution revalidates policy and integrity. Users have a non-AI fallback and can
report harm, incorrect sources, unsafe behavior, and access concerns. Oversight effectiveness—not
the mere presence of a human—is evaluated for workload, clarity, independence, and approval fatigue.

## Fairness and accessibility evaluation plan

- Recruit representative simulated personas across role, facility, experience, language needs,
  assistive technology, and uncommon workflow conditions.
- Measure task success, error, abstention, unsafe-boundary, and time—not sentiment alone.
- Test screen reader, keyboard-only, zoom/reflow, contrast, plain language, and non-color cues.
- Compare error distributions across scenarios; small sample sizes are reported as uncertainty.
- Do not infer protected traits or claim demographic parity from synthetic clinical fixtures.
- Preserve an accessible alternate workflow and escalation route for every supported task.

## Conditions for continued development

1. The v1 safety boundary remains technically enforced.
2. M02 risk/privacy/safety requirements and M03 traceability are reviewed before new capability.
3. Retrieval-only capability is evaluated before enabling a write in any simulated pilot.
4. No real data or provider receives content without approved contracts, architecture, and retention.
5. Human-factors and accessibility evidence is required before pilot authorization.
6. Benefits and harms are monitored with stop thresholds and a credible non-AI fallback.

## Stop or reassessment triggers

Any clinical recommendation, patient communication, autonomous EHR write, persistent health-data
memory, broad internet/email/code tool, multi-agent delegation, real PHI, new population or state,
material provider/model change, unexplained subgroup harm, serious privacy/safety incident, inability
to audit, or failure of kill/rollback capability requires stop and multidisciplinary reassessment.

## Current determination

**Conditionally proceed with controlled development using synthetic data.** Evidence is insufficient
for a real-data pilot, clinical effectiveness claim, production authorization, or compliance claim.

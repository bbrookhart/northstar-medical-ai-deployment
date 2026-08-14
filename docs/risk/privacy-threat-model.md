# NS-PRI-002 — LINDDUN-Style Privacy Threat Model

**Status:** M02 baseline  
**Owner:** Privacy Engineering  
**Date:** 2026-08-11

This analysis examines privacy harm to patients and workforce members, including harms that occur
without a confidentiality breach. It complements the security threat model and Privacy Impact
Assessment; it is not a formal certification in the LINDDUN methodology.

| Category | Polaris threat scenarios | Harm | Design response | Verification |
|---|---|---|---|---|
| Linking | Stable patient/user/correlation IDs, embeddings, feedback, and logs link activity across purposes, facilities, providers, or time | Surveillance, sensitive inference, secondary use | Purpose separation, minimum/pseudonymous references where operationally valid, no productivity scoring, scoped analytics | Data-join review; unauthorized analytics test |
| Identifying | “De-identified” prompts, rare care flags, excerpts, metadata, or model/provider telemetry identify a person | Stigma, discrimination, breach | Synthetic-only repo, minimum fields, no raw telemetry, re-identification assessment before derived-data use | Canary and small-cell/rare-attribute review |
| Non-repudiation | Detailed user interaction records are repurposed to prove workforce behavior beyond security/accountability need | Chilling effect, labor harm, unfair discipline | Defined audit purposes/access/retention, worker notice, prohibit hidden scoring, contextual review | Audit-use sampling and access review |
| Detecting | Response timing, denial differences, cache behavior, document hits, or resource existence reveals patient/status/sensitive policy | Curiosity inference and targeting | Concealed resource denial, normalized errors/timing where feasible, quotas, cache isolation | Enumeration/timing and canary-resource tests |
| Data disclosure | Cross-patient retrieval, provider retention, output rendering, logs, backups, embeddings, support access, or tool misuse reveals data | Confidentiality, stigma, loss of trust/avoidance of care | End-to-end authorization/labels, minimization, DLP, egress/render controls, vendor/backup policy, response | Auth/exfiltration/log/provider/deletion tests |
| Unawareness | Patients/workforce do not know AI is used, what is logged, provider involvement, limitations, correction, or complaint paths | Loss of autonomy/trust; inability to exercise rights | Layered notices, source/system-card UX, role training, human/fallback/contact paths | Notice comprehension and journey review |
| Unintervenability | Person cannot correct wrong source/patient/task, stop action, appeal access decision, obtain human review, or have data deleted when applicable | Persistent error, unsafe task, rights harm | Edit/cancel/reject, trusted task state, feedback vs formal correction paths, complaint/rights workflow, kill/rollback | End-to-end correction/cancellation/rights exercises |

## Cross-cutting privacy attack paths

### Infer sensitive status without reading a record

Enumerate identifiers → observe status/timing/citation differences → correlate facility/assignment or
Part 2-specific denial → infer patient relationship or sensitive treatment. Controls must conceal
existence, normalize behavior, rate limit, isolate caches, and alert on enumeration.

### Create a shadow longitudinal profile

Collect prompts, citations, task metadata, edits, feedback, model telemetry, and correlation IDs →
join by stable worker/patient identity → repurpose for performance or health inference. Controls are
purpose-limited event design, minimum identifiers, tiered analytics, short retention, access review,
and an explicit ban on unapproved workforce scoring.

### Lose control of derived data

Send text to embedding/model/telemetry provider → create vector/cache/trace/backup/support copies →
delete primary record but retain derivatives → continued exposure or secondary training. Controls
require a derived-data inventory, provider terms, deletion propagation and evidence, and a block on
processing until lifecycle behavior is known.

## Privacy acceptance conditions

- Privacy Officer approves purposes, flows, labels, field minimums, recipients, notices, retention,
  deletion, complaint/rights processes, and vendor terms before real data.
- Cross-purpose joining, resource-existence inference, provider/log leakage, Part 2 label loss, and
  correction/cancellation paths receive explicit negative and journey testing.
- Any new persistent memory, workforce analytics, patient-facing experience, biometric/voice data,
  recording, consumer-health feature, or jurisdiction triggers a renewed privacy assessment.

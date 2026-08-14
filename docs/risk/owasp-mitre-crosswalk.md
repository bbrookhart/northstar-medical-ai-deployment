# NS-THR-002 — OWASP GenAI, Agentic, and MITRE ATLAS Crosswalk

**Status:** M02 reviewed risk-theme baseline; exact LLM 2026 mapping remains provisional  
**Verified:** 2026-08-11  
**Owner:** AI Security

OWASP released the GenAI LLM Top 10 2026 on 2026-08-03. Because this new artifact is a living
release, Northstar will extract and independently review its exact category-level mappings in M03.
This baseline maps Polaris threats to stable risk themes plus the complete OWASP Agentic Top 10
2026 list. It does not relabel 2025 category identifiers as 2026 identifiers.

## Agentic Top 10 coverage

| OWASP ASI 2026 | Polaris exposure | Primary design treatment | Threats/tests |
|---|---|---|---|
| ASI01 Agent Goal Hijack | Direct/indirect content redirects planning | Model untrusted; content/instruction separation; bounded state; no authority | THR-005/006; injection campaigns |
| ASI02 Tool Misuse and Exploitation | Model selects harmful tool/arguments/sequence | Static typed tools, policy per call, read/write separation, budgets, approval | THR-014/015/020; tool misuse tests |
| ASI03 Identity and Privilege Abuse | Shared identity, stolen user, scope inflation, confused deputy | End-user identity, audience/scope, deny-default ABAC, short-lived credentials | THR-001/002/010/016; auth matrix |
| ASI04 Agentic Supply Chain Vulnerabilities | Tool/model/framework/action/corpus compromise | Inventory, pinned/locked artifacts, scans, provenance, promotion, rollback | THR-009/024/026; supply-chain gate |
| ASI05 Unexpected Code Execution | Generated output or tool invokes code | No shell/code/browser tools; schema validation; sandbox if future exception | THR-013/015/021; RCE/output tests |
| ASI06 Memory and Context Poisoning | RAG/FHIR/context persists attacker instruction | No persistent memory v1; provenance, trust labels, ingestion and context isolation | THR-006/009; stored injection/poison tests |
| ASI07 Insecure Inter-Agent Communication | Future delegation spoofs identity/context | Multi-agent prohibited; future mutual identity, schema, provenance, policy per hop | Scope trigger; architecture reassessment |
| ASI08 Cascading Failures | Bad output fans into tools/queues/dependencies | Single bounded agent, caps, isolation, idempotency, circuit breakers, safe degradation | THR-020/023/028; fault/loop/flood tests |
| ASI09 Human-Agent Trust Exploitation | Fluent output or deceptive approval induces unsafe reliance | Citations/uncertainty, trusted preview, user training, independent human-factors tests | THR-013/017/018/021; usability tests |
| ASI10 Rogue Agents | Unregistered/drifting agent acts outside ownership | Registry, workload identity, deployment allowlist, behavioral monitoring, kill switch | THR-026/027/029; inventory/drift tests |

## GenAI/LLM risk-theme coverage

| Risk theme | Polaris treatment | Evidence target |
|---|---|---|
| Prompt/content injection and jailbreak | Assume compromise; deterministic boundaries and adversarial corpus | Invariants hold under direct/indirect/stored/obfuscated inputs |
| Sensitive-information disclosure | Pre-context authorization, minimization, DLP, isolation, safe rendering/logging | No unauthorized chunk/record/provider/log disclosure |
| Supply chain | Approved components/data/models/tools, hashes, lock, SBOM/AIBOM, signing/provenance | Reproducible verified release manifest |
| Data/model/RAG poisoning | Provenance, owner approval, canaries, conflict/freshness rules, rollback | Poisoned content quarantined/detected; corpus rollback proven |
| Improper output handling | Typed validation, contextual encoding, restrictive CSP, no active remote content | XSS/SSRF/exfiltration payloads inert |
| Excessive agency | Least agency, proposal-only model, typed tools, independent exact approval, budgets | No model-only write or privilege expansion |
| System-instruction exposure | No secret in prompts; disclosure cannot grant authority; minimize sensitive config | Prompt extraction reveals no credential/control bypass |
| Vector/embedding weakness | ACL before context, partitions/labels, post-filter, cache isolation, export control | Cross-tenant/patient similarity and canary tests deny |
| Misinformation/unsafe output | Approved versioned sources, citation verification, conflict handling, abstention | Grounding/safety thresholds and source freshness pass |
| Unbounded consumption | Token/step/tool/time/concurrency/cost limits, timeout/circuit breaker/backpressure | Denial-of-wallet and queue-storm limits hold |

## MITRE ATLAS alignment

Polaris uses ATLAS as an adversary-behavior knowledge base, not as a control checklist. Confirmed
techniques include direct LLM prompt injection (`AML.T0051.000`), indirect LLM prompt injection
(`AML.T0051.001`), and direct jailbreak injection (`AML.T0054`). Campaign planning must also cover
discovery of AI artifacts, collection/exfiltration through model output or rendering, poisoning of
data/model/RAG sources, supply-chain compromise, evasion/obfuscation, abuse of exposed inference or
tool APIs, and denial of service. Exact living ATLAS identifiers are verified and pinned in the M03
control crosswalk rather than copied from memory.

## Control implication

Framework coverage is only a completeness check. A category is not “closed” until a Northstar
requirement maps to an implemented control, an adversarial test, durable evidence, an owner, and an
approved residual-risk decision.

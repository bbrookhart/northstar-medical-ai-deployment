# NS-CMP-001 — Regulatory, Standards, and Guidance Applicability Matrix

**Artifact status:** Initial issue; legal validation required for a real deployment  
**Owner:** Compliance and Legal  
**Last verified:** 2026-08-11  
**Jurisdiction:** Fictional U.S. multi-state health system

This is a project scoping artifact, not legal advice or a compliance determination. Applicability to a real system depends on facts, contracts, jurisdiction, intended use, and implementation.

## Binding and scope-triggering authorities

| Authority | Type/status | v1 relevance | Project treatment | Reassessment trigger |
|---|---|---|---|---|
| HIPAA Privacy Rule | Federal regulation | Production analog is assumed to be a covered-entity use of PHI | Purpose, minimum necessary where applicable, role-based access, permitted use, notices/rights analysis, policies, records | Any real PHI or external disclosure |
| HIPAA Security Rule | Federal regulation | Production analog would create, receive, maintain, or transmit ePHI | Administrative, physical, and technical safeguard mapping; risk analysis; access, audit, integrity, availability, incident controls | Real environment or business associate |
| HIPAA Breach Notification Rule/HITECH | Federal law/regulation | Guides simulated incident and breach assessment | Incident classification, risk assessment, notification decision exercise, evidence retention | Suspected unauthorized use/disclosure |
| 2025 HIPAA Security Rule update | Proposed rule as listed by HHS in 2026 | Not treated as current binding law | Forward-looking design target; clearly label proposal-derived controls | Final rule, withdrawal, or material revision |
| 42 CFR Part 2 | Federal regulation; updated rule compliance required 2026-02-16 | Relevant to SUD record scenarios | Sensitivity labels, consent/redisclosure restrictions, separate test personas and audit cases | Any SUD patient record use |
| State health/privacy/breach law | Binding; state-specific | Multi-state scenario makes a jurisdiction register necessary | Create state matrix before real pilot; apply stricter control where required | Facility/patient/user state or new data type |
| FDA clinical decision-support/device law and guidance | Scope-dependent | v1 is intentionally non-clinical and non-device | Prohibited-use boundary and scope-change review | Diagnosis, treatment, triage, patient advice, opaque recommendation |
| ONC HTI-1/certified health IT requirements | Scope-dependent | Direct applicability depends on certified-health-IT role | Voluntarily adopt model/source transparency concepts | Integration into certified health IT or DSI |
| FTC Health Breach Notification Rule | Federal regulation for covered non-HIPAA health technologies | Generally outside internal covered-entity v1 assumption | Track for consumer-health or non-HIPAA extension | Patient/consumer app or PHR-related service |

## Voluntary frameworks and design guidance

| Resource | Role in Polaris | Canonical use |
|---|---|---|
| NIST AI RMF 1.0 | AI governance backbone; NIST notes it is being revised | Govern, Map, Measure, Manage outcomes and dated profile |
| NIST AI 600-1 GenAI Profile | Generative-AI risk actions | Risk/control/evaluation catalog |
| NIST CSF 2.0 | Enterprise cybersecurity lifecycle | Govern, Identify, Protect, Detect, Respond, Recover mappings |
| NIST Privacy Framework | Privacy-risk management | Privacy outcomes, data processing, individual impacts |
| NIST SSDF 1.1 and SP 800-218A | Secure software/AI development | Secure build, acquisition, provenance, vulnerability response |
| NIST SP 800-53 | Detailed control reference | Control mapping; no certification claim |
| HHS HPH Cybersecurity Performance Goals | Healthcare-specific cyber priorities | Essential/enhanced baseline and patient-safety resilience |
| ISO/IEC 42001:2023 | Optional AI management-system alignment | Governance, impact, controls, continual improvement |
| ISO/IEC 27001:2022 and 27701 | Optional information security/privacy alignment | ISMS/PIMS mapping; no certification claim |
| ISO/IEC 23894:2023 | AI risk guidance | AI risk process cross-check |
| OWASP GenAI LLM Top 10 2026 | LLM application threat baseline | Threat cases, requirements, tests, remediation |
| OWASP Top 10 for Agentic Applications 2026 | Agent/tool/autonomy threat baseline | Agent goal, tool, identity, memory, cascade, trust controls |
| MITRE ATLAS | Adversary behavior knowledge base | Threat techniques, red-team scenarios, detection mapping |
| CISA/NCSC secure AI development guidance | Secure-by-design lifecycle | Design, development, deployment, operation review |
| CHAI/Joint Commission guidance | Healthcare AI assurance | Healthcare governance, impact, evaluation, monitoring |
| HL7 FHIR security and SMART guidance | Clinical data exchange design | TLS, OAuth/OIDC, scopes, consent, labels, provenance, AuditEvent |
| MCP authorization/security guidance | Tool protocol design if MCP is used | Audience validation, no token passthrough, consent, confused-deputy defenses |

## Current primary-source register

| Source | Publisher | URL | Accessed | Status note |
|---|---|---|---|---|
| AI Risk Management Framework | NIST | https://www.nist.gov/itl/ai-risk-management-framework | 2026-08-11 | AI RMF 1.0 is being revised; maintain change watch |
| NIST AI RMF resources and GenAI Profile | NIST | https://www.nist.gov/itl/ai-risk-management-framework/ai-risk-management-framework-resources | 2026-08-11 | NIST AI 600-1 published 2024-07-26 |
| Cybersecurity Framework 2.0 | NIST | https://www.nist.gov/cyberframework | 2026-08-11 | Voluntary framework |
| SP 800-218A | NIST | https://csrc.nist.gov/pubs/sp/800/218/a/final | 2026-08-11 | Use with SSDF 1.1 |
| HIPAA Security Rule | HHS OCR | https://www.hhs.gov/hipaa/for-professionals/security/index.html | 2026-08-11 | HHS page lists 2025 update as proposed |
| Minimum Necessary Requirement | HHS OCR | https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/minimum-necessary-requirement/index.html | 2026-08-11 | Applicability depends on use/disclosure |
| Part 2 Final Rule fact sheet | HHS | https://www.hhs.gov/hipaa/for-professionals/regulatory-initiatives/fact-sheet-42-cfr-part-2-final-rule/index.html | 2026-08-11 | Compliance date 2026-02-16 |
| HPH Cybersecurity Performance Goals | HHS | https://hhscyber.hhs.gov/cybersecurity-performance-goals.html | 2026-08-11 | Voluntary healthcare priorities |
| HTI-1 Final Rule | ASTP/ONC | https://healthit.gov/regulations/hti-rules/hti-1-final-rule/ | 2026-08-11 | Certified-health-IT and DSI scope |
| Clinical Decision Support Software | FDA | https://www.fda.gov/regulatory-information/search-fda-guidance-documents/clinical-decision-support-software | 2026-08-11 | Final guidance issued 2026-01 |
| Health Breach Notification Rule | FTC | https://www.ftc.gov/legal-library/browse/rules/health-breach-notification-rule | 2026-08-11 | Non-HIPAA health technologies |
| LLM Top 10 2026 | OWASP GenAI Security Project | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ | 2026-08-11 | Released 2026-08-03 |
| MITRE ATLAS | MITRE | https://atlas.mitre.org/ | 2026-08-11 | Living knowledge base |
| FHIR Security | HL7 | https://www.hl7.org/fhir/security.html | 2026-08-11 | FHIR is not itself an access-control protocol |
| MCP Security Best Practices | Model Context Protocol | https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices | 2026-08-11 | Versioned living guidance |

## Required follow-up

- Create the canonical Northstar control library and crosswalk after requirements are baselined.
- Add a state-law register before any real-world scenario extends beyond the fictional design.
- Add model/cloud/provider contract criteria before selecting a hosted provider.
- Recheck all living and proposed sources at each simulated release gate.


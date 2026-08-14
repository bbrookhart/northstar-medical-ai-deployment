# NS-ENT-001 — Northstar Medical Enterprise Profile

**Artifact status:** Draft for simulated executive approval  
**Owner:** Chief Strategy and Digital Officer  
**Reviewers:** CIO, CISO, Chief Medical Information Officer, Privacy Officer  
**Last updated:** 2026-08-11

## Purpose

This document defines the fictional operating context used to make Project Polaris decisions realistic and internally consistent. Every organization, person, system, facility, and patient in this repository is fictional or synthetic.

## Organization

Northstar Medical is a nonprofit, multi-state U.S. integrated delivery network serving urban, suburban, and rural communities across the upper Midwest.

| Attribute | Simulation baseline |
|---|---|
| Acute-care hospitals | 8 |
| Outpatient and specialty sites | Approximately 60 |
| Workforce | Approximately 20,000 |
| Affiliated clinicians | Approximately 3,200 |
| Longitudinal patient records | Approximately 4 million |
| Annual patient encounters | Approximately 3.5 million |
| Operating model | Central enterprise functions with local facility operations |
| Technology model | Hybrid cloud with centralized identity, network, security, and data platforms |

These figures are scenario inputs, not claims about a real healthcare organization.

## Mission and strategic context

Northstar's fictional mission is to deliver safe, equitable, accessible care while maintaining the trust of patients, clinicians, and communities.

The organization is experiencing:

- Fragmented policy and procedure repositories
- Time spent by clinicians and care coordinators locating current administrative guidance
- Manual creation of routine follow-up work items
- Growing unsanctioned use of consumer generative-AI tools
- Pressure to demonstrate value from AI without increasing patient-safety or privacy risk
- Board and regulator attention to ransomware, third-party concentration, data governance, and AI oversight

## Technology environment

- Workforce identity is federated through a centralized OIDC-compatible identity provider with MFA.
- The production EHR is represented only conceptually; the simulation uses synthetic FHIR R4 resources.
- Security operations use a centralized SIEM, incident-management process, and on-call escalation model.
- Application delivery uses source control, CI/CD, infrastructure as code, centralized secrets, and vulnerability-management processes.
- Cloud, model, and SaaS services require procurement, security, privacy, legal, and business-owner review.

No real Northstar cloud tenant, EHR, network, vendor agreement, or workforce directory exists.

## Information classification

| Classification | Examples | Minimum handling intent |
|---|---|---|
| Public | Published policies, public training material | Integrity and provenance |
| Internal | General workforce procedures, internal architecture | Authenticated workforce access |
| Confidential | Security designs, vendor findings, non-public business data | Least privilege, encryption, monitored access |
| Northstar Restricted Health Data | Synthetic patient and encounter data used in the simulation | Treat operationally like regulated health data; strict purpose, access, audit, minimization |
| Restricted Security Data | Credentials, key material, exploit details, detection logic | Segregation, narrow access, never place in model context by default |

Real PHI, PII, secrets, and production data are prohibited from the repository.

## Threat environment

The simulation assumes credible threats from:

- External attackers seeking health data, credentials, extortion leverage, or operational disruption
- Malicious or compromised third-party dependencies and services
- Prompt-injection and data-poisoning attackers using documents, FHIR narrative, tool output, and user input
- Over-privileged agents, service identities, or confused-deputy flows
- Curious, negligent, or malicious insiders
- Well-intentioned users who over-trust fluent but incorrect AI output
- Provider outages, silent model changes, cost exhaustion, and operational failure

## Risk appetite

Northstar's simulated risk appetite permits a limited internal pilot when benefits are measurable and controls are independently evidenced.

Northstar has no appetite for:

- Autonomous diagnosis, prescribing, treatment, emergency triage, or clinical decision-making
- Unauthorized patient or workforce data disclosure
- An LLM making or bypassing an authorization decision
- Unreviewed patient communication or EHR modification
- Secrets or broad credentials available to the model
- Undocumented model, prompt, tool, corpus, or policy changes
- Critical or high security findings remaining open at release
- Claims of compliance, certification, or clinical fitness without qualified evidence

Northstar may accept time-limited moderate residual risk when the accountable owner, monitoring, compensating controls, expiry, and exit criteria are documented.

## Governance model

The Board Risk and Quality Committee oversees AI risk at the enterprise level. Management delegates use-case approval to an AI Review Board supported by security, privacy, compliance, legal, clinical safety, data governance, technology, vendor risk, and internal audit.

The three-lines model is:

1. Product, engineering, data, and operations own and manage risk.
2. AI security, privacy, compliance, legal, clinical safety, and vendor risk independently challenge and oversee.
3. Internal audit independently assesses design and operating evidence.

## Simulation assumptions requiring later validation

- Northstar is a HIPAA covered entity.
- A hosted model provider would be a business associate if it receives PHI in a real deployment.
- The v1 use case remains operational and administrative, not a medical-device function.
- The simulation will use U.S. requirements; international expansion is deferred.
- Facility, role, patient, purpose-of-use, consent, and sensitivity attributes are available to the authorization layer.
- All generated patient data is synthetic but is handled under restricted-data controls.


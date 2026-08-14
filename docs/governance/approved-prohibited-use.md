# NS-GOV-001 — Approved, Conditional, and Prohibited Use

**Artifact status:** Draft policy for simulated AI Review Board  
**Owner:** AI System Owner  
**Policy authority:** AI Review Board  
**Last updated:** 2026-08-11

## System purpose

Polaris supports authorized workforce members with operational information retrieval and non-clinical administrative workflow. It augments, but does not replace, professional judgment or established clinical systems.

## Approved uses

| ID | Use | Conditions |
|---|---|---|
| USE-001 | Retrieve current approved internal policies | Source must be approved, versioned, access-authorized, and cited |
| USE-002 | Summarize an approved policy | Summary must preserve citations and show uncertainty/conflicts |
| USE-003 | Retrieve minimal synthetic patient context | Authenticated role, facility, patient relationship, purpose of use, and sensitivity policy must allow access |
| USE-004 | Draft non-diagnostic administrative follow-up content | Must be labeled as a draft and reviewed by an authorized human |
| USE-005 | Propose a non-clinical follow-up task | Typed allowlisted action only; no execution at proposal time |
| USE-006 | Approve or reject an exact task | Authorized independent approver sees canonical action and expiry |
| USE-007 | Execute an approved task in the mock system | Reauthorize; verify approval hash, expiry, idempotency, and current policy |
| USE-008 | Review audit and assurance evidence | Access-controlled, minimized, and purpose-limited |

## Conditional uses requiring a new assessment

- Patient-facing content or direct communication
- Real PHI or a real clinical integration
- Internet, inbox, attachment, or external-content retrieval
- Voice, ambient recording, image, or other multimodal input
- Long-term memory or personalization
- Model fine-tuning or retrieval from user-generated content
- Additional tools, write capabilities, or multi-step autonomy
- Multi-agent or agent-to-agent communication
- Cross-organization or consumer access
- Clinical scoring, prediction, recommendation, or decision support
- Use outside the United States

Conditional use requires a revised charter, data flow, regulatory analysis, threat/privacy/safety assessment, controls, test plan, monitoring, training, and approval.

## Prohibited uses

- Diagnose a condition or interpret findings as a diagnosis
- Prescribe, select, change, or recommend medication or treatment
- Determine urgency, disposition, or emergency triage
- Replace a licensed clinician's review or patient-clinician communication
- Autonomously write to a real or simulated EHR clinical record
- Send an external or patient-visible message without explicit review and approved workflow
- Make coverage, employment, disciplinary, credentialing, or other consequential decisions
- Infer sensitive characteristics that are not necessary for the approved task
- Access a patient because the user states a relationship in chat
- Reveal system prompts, hidden configuration, credentials, private policies, or another user's data
- Obey instructions contained in retrieved content, FHIR narrative, tool metadata, tool output, or memory
- Invoke arbitrary network, shell, filesystem, database, code-execution, email, or browser functions
- Persist conversation content to cross-session memory
- Use output as the sole evidence for a legal, safety, security, or compliance decision
- Represent Polaris as a clinician, medical device, authoritative source, or compliant/certified system

## Required user experience

- Display that Polaris is an AI-assisted internal tool with a limited approved purpose.
- Identify the source and version of policy content.
- Mark drafts and unexecuted proposals clearly.
- Show the exact action, target, arguments, requester, approver requirement, and expiry before approval.
- Provide a visible way to reject, report, or escalate an unsafe or incorrect response.
- Use a fixed emergency message directing the user to established emergency procedures; do not attempt case-specific triage.
- State when evidence is missing, conflicting, unauthorized, or outside scope.

## Enforcement

Prompt instructions are guidance, not enforcement. The application, policy engine, data tier, tool broker, approval service, and execution layer enforce these rules independently of model output.

Violations generate a minimized security/safety event and follow the incident workflow. Repeated or high-severity events may trigger the kill switch and release rollback.


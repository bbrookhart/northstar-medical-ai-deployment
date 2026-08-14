# Curriculum

Twelve modules, each anchored to artifacts a learner can open, run, and break.

| Module | Topic | Anchor artifacts | Lab |
|---|---|---|---|
| 1 | Enterprise context and least-agency scoping | `docs/executive/`, approved-use boundary | Outlined |
| 2 | Governance, ownership, and honest applicability | `docs/governance/`, `docs/compliance/` | Outlined |
| 3 | Data flows, DPIA, STRIDE, LINDDUN, clinical hazards | `docs/risk/` | Outlined |
| 4 | Requirements, controls, traceability, and evidence | `governance/`, `make governance` | **Lab 1** |
| 5 | Identity, continuous access, consent, and FHIR security | `src/polaris/security/`, `ADR-007`, `ADR-008` | Outlined |
| 6 | Secure RAG: admission, partitioning, and grounding | `src/polaris/services/corpus.py`, `ADR-010` | **Lab 2** |
| 7 | Untrusted models, bounded loops, and typed tools | `src/polaris/agent/`, `ADR-011` | **Lab 3** |
| 8 | Exact approval, action integrity, and safe presentation | `src/polaris/presentation/`, `ADR-012` | Outlined |
| 9 | Secure SDLC, SBOM and AIBOM, signing, and provenance | `src/polaris/supplychain/`, `ADR-013` | Outlined |
| 10 | Evaluation, adversarial testing, and residual risk | `src/polaris/assurance/` | Outlined |
| 11 | Detection, incident response, and recovery | `src/polaris/operations/` | Outlined |
| 12 | Change control, audit, retirement, and honest claims | `src/polaris/lifecycle/`, `src/polaris/portfolio/` | Outlined |

Three labs are written end to end with solutions and assessments. The remaining nine are outlined
against real artifacts and are not claimed as complete — writing a lab guide is cheap, and writing
one whose exercise actually fails for the right reason is not.

## Product definition of done, per module

Measurable objectives, prerequisites, concept material, a decision exercise, a hands-on lab, a
solution, an assessment with a rubric, common failure modes, instructor notes, an accessibility
review, reset instructions, and links to the exact repository artifacts used.

Modules 4, 6, and 7 meet this. The others meet the first four items.

# Portfolio

Recruiter-facing material for Project Polaris. Every claim here resolves to an artifact in this
repository, and `make portfolio` fails the build if one does not.

## Read in this order

| | Time | What it covers |
|---|---|---|
| **[Case study](case-study.md)** | 5 min | The problem, the decision that shaped the architecture, what was built, and four bugs found by running rather than reading |
| **[Evidence tour](evidence-tour.md)** | 10 min | Three chains walked from risk to requirement to control to code to test |
| **[Demo script](demo-script.md)** | 7 min live | A walkthrough with real commands, for an interview or a recorded demo |

## The one-paragraph version

Project Polaris takes a single narrow AI capability — answer approved policy questions, draft
administrative follow-up tasks — through twelve milestones covering business intake, governance,
threat and privacy modelling, secure implementation, retrieval security, agent containment, approval
integrity, supply chain, assurance and red teaming, operations and incident response, audit, and
retirement. The system is deliberately constrained: the model is untrusted and can never authorize
anything, there is no tool that executes, and every write requires independent human approval bound
to the exact action displayed.

## Role-impact map

What a hiring manager is usually trying to establish, and where to look.

| Question | Where the answer lives |
|---|---|
| Can they design a secure AI architecture? | [ADR-011](../docs/architecture/decisions/ADR-011-bounded-agent-and-model-boundary.md), [`src/polaris/agent/`](../src/polaris/agent/) |
| Do they understand identity beyond "add OAuth"? | [ADR-007](../docs/architecture/decisions/ADR-007-durable-identity-signals.md), [`src/polaris/security/`](../src/polaris/security/) |
| Can they secure RAG, not just build it? | [ADR-010](../docs/architecture/decisions/ADR-010-secure-retrieval-boundary.md), [`src/polaris/services/corpus.py`](../src/polaris/services/corpus.py) |
| Can they threat model? | [`docs/risk/`](../docs/risk/) — STRIDE, LINDDUN, DPIA, abuse cases, clinical hazards |
| Can they red team their own work? | [`src/polaris/assurance/redteam.py`](../src/polaris/assurance/redteam.py) |
| Do they think about operations? | [Incident playbooks](../docs/operations/ai-incident-playbooks.md), [`src/polaris/operations/`](../src/polaris/operations/) |
| Can they run a governance program? | [`governance/`](../governance/) — 31 controls, machine-validated traceability |
| Do they know supply-chain security? | [ADR-013](../docs/architecture/decisions/ADR-013-supply-chain-and-release-policy.md), [`src/polaris/supplychain/`](../src/polaris/supplychain/) |
| Will they overstate what they built? | Every document here, and the checker that enforces it |

## Claims discipline

No artifact in this directory claims real healthcare deployment, real PHI processing, HIPAA
compliance, FDA status, clinical effectiveness, independent certification, or readiness for
production use. `src/polaris/portfolio/claims.py` enforces that mechanically: it resolves every
identifier against the catalogs, checks every link and documented command, and rejects overstated
language — while permitting the honest denial of a claim, which is the sentence that actually
belongs in this kind of material.

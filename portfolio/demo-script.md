# Seven-Minute Demo

**The demo shows what the system refuses.** A demo of successful answers would be indistinguishable
from any other assistant; the refusals are what took the engineering.

Every command below is real and runs from a clean checkout.

## 0:00 — Setup (30s)

```bash
uv sync --locked --all-groups
```

State the boundary out loud: synthetic data only, no hosted model connected, no pilot authorized.

## 0:30 — The whole gate (60s)

```bash
make verify
```

While it runs, explain what is being enforced: traceability, the retrieval golden set, the release
supply-chain policy, the adversarial campaign, five operational drills, the audit package and
retirement exercise, then lint, typing, tests, and coverage. Seven checks, each able to fail the
build.

## 1:30 — A compromised model cannot widen its reach (90s)

```bash
uv run pytest tests/test_agent_boundary.py -v
```

Point at three test names as they scroll: the model cannot reach an unapproved tool, cannot read an
unassigned patient, and cannot execute — only propose. Then say the part that matters: these script
hostile intents directly rather than asking a model to misbehave, so they test the boundary rather
than the model's compliance.

## 3:00 — The adversarial campaign (90s)

```bash
make red-team
```

Twenty-one attacks across fourteen classes, each naming the control expected to stop it — so a case
contained in the wrong place is visible in the report rather than hidden by a green result.

Then show the release evaluation beside it: it declares all eleven required dimensions and marks four
honestly unassessed, keeping blocking gaps separate from missing evidence. A single readiness boolean
would have collapsed that distinction.

## 4:30 — Containment and recovery (60s)

```bash
make game-day
```

Five drills. Call out `GD-05`: it backs up the database, corrupts it, confirms detection, restores,
and verifies the audit chain. Then mention `GD-01` failed on its first run because the drill asserted
the wrong half of the control.

## 5:30 — Traceability, both directions (60s)

```bash
make governance
```

Pick a risk from `governance/control-library.json` and follow it live: requirement, control,
implementation file, verification, evidence record. Then reverse it — open a source file and name the
risk it exists to treat.

Mention that the validator refuses verified evidence on a control still marked planned. That rule
caught a real inconsistency during development, rather than a hypothetical one.

## 6:30 — Close (30s)

The security work that mattered was rarely clever: choose the boundary that makes a class of mistake
impossible, then make it a type rather than a convention. And record every limitation next to the
control it affects — knowing which problems code cannot close is most of the job.

## Questions to expect

- *"Why isn't there a UI?"* Building one before the human-factors work means the findings audit a
  fixed design instead of informing it (`ADR-012`).
- *"Why no hosted model?"* `REQ-AI-002` criteria and `BLK-004` due diligence are open. The adapter
  implements the interface and refuses every call, so it cannot be misconfigured into working.
- *"Isn't a passing red team enough?"* `RT-F3`: the attacks were authored by the same process that
  wrote the controls, so they encode the same assumptions.

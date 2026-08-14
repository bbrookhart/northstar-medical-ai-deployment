# Seven-Minute Demo Script

The demo shows what the system refuses. A demo of successful answers would be indistinguishable from
any other assistant.

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

Twenty-one attacks, fourteen classes, all contained — and the release evaluation still reports **not
ready**, because accessibility, performance, cost, and recovery have no evidence. Show that
`release_ready` is false while `blocking_gaps` is empty. A single readiness boolean would have hidden
that.

## 4:30 — Containment and recovery (60s)

```bash
make game-day
```

Five drills. Call out `GD-05`: it backs up the database, corrupts it, confirms detection, restores,
and verifies the audit chain. Then mention `GD-01` failed on its first run because the drill asserted
the wrong half of the control.

## 5:30 — The refusal (60s)

Open `docs/assurance/M11-governance-board-decision.md`.

Read the two grounds: all seven pilot entry conditions unmet, and nobody with standing to authorize
anything. Say why the document exists — producing the authorization would have taken five minutes,
and a simulated signature on a pilot decision is a counterfeit, not a weaker approval.

## 6:30 — Close (30s)

Six gates did not pass. The remaining work needs clinicians, an operator, an independent red team,
and an accountable owner — not more code. Recognising which problems code cannot close is most of the
job.

## Questions to expect

- *"Why isn't there a UI?"* Building one before the human-factors work means the findings audit a
  fixed design instead of informing it (`ADR-012`).
- *"Why no hosted model?"* `REQ-AI-002` criteria and `BLK-004` due diligence are open. The adapter
  implements the interface and refuses every call, so it cannot be misconfigured into working.
- *"Isn't a passing red team enough?"* `RT-F3`: the attacks were authored by the same process that
  wrote the controls, so they encode the same assumptions.

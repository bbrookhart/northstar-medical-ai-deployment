from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from polaris.assurance.attacks import AttackClass
from polaris.assurance.redteam import run_campaign
from polaris.assurance.release_eval import build_release_evaluation

_CAMPAIGN_PATH = Path("evidence/reports/M09-red-team.json")
_EVALUATION_PATH = Path("evidence/reports/M09-release-evaluation.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Northstar adversarial campaign and build the release evaluation"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail on an uncontained blocking case, missing class coverage, or a stale report",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    campaign = run_campaign()
    evaluation = build_release_evaluation(campaign)

    for result in campaign.results:
        if not result.contained:
            print(
                f"UNCONTAINED {result.case_id} [{result.severity.value}] "
                f"{result.attack_class.value}: {result.detail}",
                file=sys.stderr,
            )

    if args.check:
        _require_current(root / _CAMPAIGN_PATH, campaign.to_json())
        _require_current(root / _EVALUATION_PATH, evaluation.to_json())
        if not campaign.passed:
            _fail(
                f"Adversarial campaign failed: {len(campaign.blocking_failures)} uncontained "
                f"blocking case(s); {len(campaign.covered_classes)} of "
                f"{len(set(AttackClass))} attack classes covered."
            )
        if evaluation.blocking_gaps:
            _fail(f"Release evaluation blocking gaps: {', '.join(evaluation.blocking_gaps)}")
        print(
            f"Adversarial campaign passed: {len(campaign.results)} cases, "
            f"{campaign.containment_rate:.0%} contained, no blocking gaps. "
            f"Unassessed dimensions: "
            f"{', '.join(dimension.name for dimension in evaluation.unassessed) or 'none'}."
        )
        return

    (root / _CAMPAIGN_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / _CAMPAIGN_PATH).write_text(campaign.to_json())
    (root / _EVALUATION_PATH).write_text(evaluation.to_json())
    print(
        f"Wrote {_CAMPAIGN_PATH} and {_EVALUATION_PATH}; "
        f"campaign passed: {campaign.passed}; release ready: {evaluation.release_ready}."
    )
    if not campaign.passed:
        raise SystemExit(1)


def _require_current(path: Path, generated: str) -> None:
    if not path.is_file():
        _fail(f"Missing generated report: {path.name}. Run 'make red-team'.")
    if _stable(path.read_text()) != _stable(generated):
        _fail(f"Generated report is stale: {path.name}. Run 'make red-team'.")


def _stable(document: str) -> str:
    payload = json.loads(document)
    payload.pop("executed_at", None)
    return json.dumps(payload, indent=2, sort_keys=True)


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

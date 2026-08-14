from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from polaris.operations.gameday import run_game_day

_GAME_DAY_PATH = Path("evidence/reports/M10-game-day.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Execute the Northstar operational game-day drills"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when a drill objective is unmet or the generated report is stale",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    with tempfile.TemporaryDirectory(prefix="polaris-gameday-") as workspace:
        report = run_game_day(Path(workspace))

    for result in report.results:
        if not result.met:
            print(f"UNMET {result.drill_id} {result.name}: {result.observed}", file=sys.stderr)

    if args.check:
        destination = root / _GAME_DAY_PATH
        if not destination.is_file():
            _fail(f"Missing generated report: {_GAME_DAY_PATH}. Run 'make game-day'.")
        if _stable(destination.read_text()) != _stable(report.to_json()):
            _fail(f"Generated report is stale: {_GAME_DAY_PATH}. Run 'make game-day'.")
        if not report.passed:
            _fail("One or more game-day objectives were not met.")
        print(
            f"Game day passed: {len(report.results)} drills, all objectives met. "
            "Production recovery exercises remain unexecuted (NS-EXC-004)."
        )
        return

    (root / _GAME_DAY_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / _GAME_DAY_PATH).write_text(report.to_json())
    print(f"Wrote {_GAME_DAY_PATH}; all objectives met: {report.passed}.")
    if not report.passed:
        raise SystemExit(1)


def _stable(document: str) -> str:
    payload = json.loads(document)
    payload.pop("executed_at", None)
    return json.dumps(payload, indent=2, sort_keys=True)


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

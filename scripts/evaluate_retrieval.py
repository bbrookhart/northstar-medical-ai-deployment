from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from polaris.services.retrieval_eval import (
    build_evaluation_index,
    run_evaluation,
)

_REPORT_PATH = Path("evidence/reports/M05-retrieval-evaluation.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Northstar retrieval evaluation set")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when thresholds are unmet or the generated report is stale",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    report = run_evaluation(build_evaluation_index())
    destination = root / _REPORT_PATH

    failures = [result for result in report.results if not result.passed]
    if failures:
        for failure in failures:
            print(
                f"FAIL {failure.case_id} [{failure.kind.value}] {failure.detail}",
                file=sys.stderr,
            )

    if args.check:
        if not destination.exists():
            _fail(f"Missing generated report: {_REPORT_PATH}")
        if _stable(destination.read_text()) != _stable(report.to_json()):
            _fail(f"Generated report is stale: {_REPORT_PATH}. Run 'make retrieval-eval'.")
        if not report.meets_thresholds:
            _fail(
                "Retrieval evaluation thresholds not met: "
                f"security={report.security_pass_rate:.4f} quality={report.quality_pass_rate:.4f}"
            )
        print(
            "Retrieval evaluation passed; "
            f"security={report.security_pass_rate:.4f} "
            f"quality={report.quality_pass_rate:.4f} and the report is current."
        )
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report.to_json())
    print(f"Wrote {_REPORT_PATH}; thresholds met: {report.meets_thresholds}.")
    if not report.meets_thresholds:
        raise SystemExit(1)


def _stable(document: str) -> str:
    """Compare everything except the run timestamp, which changes on every execution."""

    payload = json.loads(document)
    payload.pop("evaluated_at", None)
    return json.dumps(payload, indent=2, sort_keys=True)


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

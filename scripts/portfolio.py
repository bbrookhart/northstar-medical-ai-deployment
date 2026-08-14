from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from polaris.portfolio.claims import verify_claims

_REPORT_PATH = Path("evidence/reports/M12-portfolio-claims.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify that portfolio and training claims trace to repository artifacts"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail on an unresolved claim or a stale generated report",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    report = verify_claims(root)
    for finding in report.findings:
        print(f"{finding.kind.value} {finding.document}: {finding.detail}", file=sys.stderr)

    document = json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
    destination = root / _REPORT_PATH

    if args.check:
        if not destination.is_file():
            _fail(f"Missing generated report: {_REPORT_PATH}. Run 'make portfolio'.")
        if destination.read_text() != document:
            _fail(f"Generated report is stale: {_REPORT_PATH}. Run 'make portfolio'.")
        if not report.passed:
            _fail(f"Portfolio claims check failed with {len(report.findings)} finding(s).")
        print(
            f"Portfolio claims verified: {len(report.documents)} documents, "
            f"{report.references} identifiers resolved, no prohibited claims."
        )
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(document)
    print(f"Wrote {_REPORT_PATH}; claims verified: {report.passed}.")
    if not report.passed:
        raise SystemExit(1)


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

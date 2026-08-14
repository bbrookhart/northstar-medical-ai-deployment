from __future__ import annotations

import argparse
from pathlib import Path

from polaris.governance.traceability import (
    build_report,
    check_reports,
    validate_repository,
    write_reports,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Northstar governance traceability")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when generated reports are missing or stale instead of writing them",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    bundle = validate_repository(root, require_generated_evidence=args.check)
    report = build_report(root, bundle)
    if args.check:
        check_reports(root, report)
        print("Traceability validation passed; generated reports are current.")
    else:
        json_path, markdown_path = write_reports(root, report)
        print(f"Traceability validation passed; wrote {json_path} and {markdown_path}.")


if __name__ == "__main__":
    main()

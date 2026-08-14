from __future__ import annotations

import argparse
import sys
from pathlib import Path

from polaris.services.container import CORPUS_ID, CORPUS_VERSION
from polaris.supplychain.aibom import build_aibom
from polaris.supplychain.aibom import render as render_aibom
from polaris.supplychain.policy import Severity, evaluate_release_policy
from polaris.supplychain.sbom import build_sbom
from polaris.supplychain.sbom import render as render_sbom

_SBOM_PATH = Path("evidence/reports/M08-sbom.cdx.json")
_AIBOM_PATH = Path("evidence/reports/M08-aibom.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the Northstar SBOM and AIBOM and check the release supply-chain policy"
        )
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when a policy blocker exists or a generated document is stale",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    sbom = render_sbom(build_sbom(root))
    aibom = render_aibom(build_aibom(root, corpus_id=CORPUS_ID, corpus_version=CORPUS_VERSION))
    report = evaluate_release_policy(root)

    for finding in report.findings:
        stream = sys.stderr if finding.severity is Severity.BLOCKER else sys.stdout
        print(
            f"{finding.severity.value} {finding.check} {finding.location}: {finding.detail}",
            file=stream,
        )

    if args.check:
        _require_current(root / _SBOM_PATH, sbom)
        _require_current(root / _AIBOM_PATH, aibom)
        if not report.passed:
            _fail(f"Release supply-chain policy failed with {len(report.blockers)} blocker(s).")
        print(
            f"Supply-chain policy passed across {report.checked_files} pinned definition(s); "
            "SBOM and AIBOM are current."
        )
        return

    (root / _SBOM_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / _SBOM_PATH).write_text(sbom)
    (root / _AIBOM_PATH).write_text(aibom)
    print(f"Wrote {_SBOM_PATH} and {_AIBOM_PATH}; policy passed: {report.passed}.")
    if not report.passed:
        raise SystemExit(1)


def _require_current(path: Path, generated: str) -> None:
    if not path.is_file():
        _fail(f"Missing generated document: {path.name}. Run 'make supply-chain'.")
    if path.read_text() != generated:
        _fail(f"Generated document is stale: {path.name}. Run 'make supply-chain'.")


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

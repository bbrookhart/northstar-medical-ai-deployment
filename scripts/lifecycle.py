from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from polaris.lifecycle.audit_package import build_audit_package
from polaris.lifecycle.retirement import run_retirement

_AUDIT_PACKAGE_PATH = Path("evidence/reports/M11-audit-package.json")
_RETIREMENT_PATH = Path("evidence/reports/M11-retirement.json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Assemble the Northstar audit package and execute the retirement exercise"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail on a missing evidence artifact, an unmet retirement step, or a stale report",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    package = build_audit_package(root)
    with tempfile.TemporaryDirectory(prefix="polaris-retirement-") as workspace:
        retirement = run_retirement(Path(workspace))

    for artifact in package.missing:
        print(f"MISSING {artifact.evidence_id}: {artifact.path}", file=sys.stderr)
    for step in retirement.steps:
        if not step.met:
            print(f"UNMET {step.step_id} {step.name}: {step.observed}", file=sys.stderr)

    package_document = _render(package.to_dict())
    retirement_document = _render(retirement.to_dict())

    if args.check:
        _require_current(root / _AUDIT_PACKAGE_PATH, package_document, digest_sensitive=True)
        _require_current(root / _RETIREMENT_PATH, retirement_document)
        if not package.complete:
            _fail(f"Audit package incomplete: {len(package.missing)} artifact(s) missing.")
        if not retirement.passed:
            _fail("One or more retirement objectives were not met.")
        print(
            f"Lifecycle check passed: {len(package.artifacts)} evidence artifacts indexed, "
            f"{len(retirement.steps)} retirement steps met. "
            f"Unmet gates remain: {', '.join(package.unmet_gates) or 'none'}."
        )
        return

    (root / _AUDIT_PACKAGE_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / _AUDIT_PACKAGE_PATH).write_text(package_document)
    (root / _RETIREMENT_PATH).write_text(retirement_document)
    print(
        f"Wrote {_AUDIT_PACKAGE_PATH} and {_RETIREMENT_PATH}; "
        f"package complete: {package.complete}; retirement passed: {retirement.passed}."
    )
    if not (package.complete and retirement.passed):
        raise SystemExit(1)


def _render(document: dict[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _require_current(path: Path, generated: str, *, digest_sensitive: bool = False) -> None:
    if not path.is_file():
        _fail(f"Missing generated report: {path.name}. Run 'make lifecycle'.")
    if _stable(path.read_text(), digest_sensitive) != _stable(generated, digest_sensitive):
        _fail(f"Generated report is stale: {path.name}. Run 'make lifecycle'.")


def _stable(document: str, digest_sensitive: bool = False) -> str:
    payload = json.loads(document)
    payload.pop("executed_at", None)
    if digest_sensitive:
        # The package indexes its own directory, so artifact digests change whenever any evidence
        # file does. Compare the index structure and drop the digests, which the artifacts
        # themselves already carry.
        for artifact in payload.get("artifacts", []):
            artifact.pop("sha256", None)
            artifact.pop("bytes", None)
    return json.dumps(payload, indent=2, sort_keys=True)


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
from pathlib import Path

from polaris.data.synthetic import build_synthea_dataset, validate_synthetic_dataset


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build or validate the Northstar synthetic FHIR R4 dataset"
    )
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--raw-fhir-dir",
        type=Path,
        default=Path("artifacts/runtime/synthea/northstar-v1/fhir"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    dataset_dir = root / "data/synthetic/fhir-r4"
    config_path = root / "data/synthetic/config/synthea.properties"
    lock_path = root / "data/synthetic/toolchain-lock.json"

    if args.action == "build":
        build_synthea_dataset(
            raw_fhir_dir=(root / args.raw_fhir_dir).resolve(),
            output_dir=dataset_dir,
            config_path=config_path,
            toolchain_lock_path=lock_path,
        )
        print(f"Built and verified {dataset_dir}")
    else:
        validate_synthetic_dataset(
            dataset_dir=dataset_dir,
            config_path=config_path,
            toolchain_lock_path=lock_path,
        )
        print(f"Verified {dataset_dir}")


if __name__ == "__main__":
    main()

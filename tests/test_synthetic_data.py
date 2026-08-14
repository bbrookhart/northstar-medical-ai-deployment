from __future__ import annotations

import json
from pathlib import Path

import pytest

from polaris.data.synthetic import (
    SyntheticDataValidationError,
    build_synthea_dataset,
    validate_synthetic_dataset,
)

_ROOT = Path(__file__).resolve().parents[1]
_CONFIG = _ROOT / "data/synthetic/config/synthea.properties"
_LOCK = _ROOT / "data/synthetic/toolchain-lock.json"
_SOURCE_IDS = (
    "10000000-0000-0000-0000-000000000001",
    "20000000-0000-0000-0000-000000000002",
    "30000000-0000-0000-0000-000000000003",
)


def test_committed_synthetic_dataset_passes_integrity_and_safety_checks() -> None:
    manifest = validate_synthetic_dataset(
        dataset_dir=_ROOT / "data/synthetic/fhir-r4",
        config_path=_CONFIG,
        toolchain_lock_path=_LOCK,
    )

    assert manifest["dataset"]["synthetic_only"] is True
    assert manifest["validation"]["status"] == "passed"


def test_synthea_transformation_is_deterministic_and_removes_source_ids(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    for index, patient_id in enumerate(_SOURCE_IDS, start=1):
        source_bundle = {
            "resourceType": "Bundle",
            "type": "transaction",
            "entry": [{"resource": {"resourceType": "Patient", "id": patient_id}}],
        }
        (raw_dir / f"patient-{index}.json").write_text(
            json.dumps(source_bundle, sort_keys=True),
            encoding="utf-8",
        )

    first = tmp_path / "first"
    second = tmp_path / "second"
    build_synthea_dataset(
        raw_fhir_dir=raw_dir,
        output_dir=first,
        config_path=_CONFIG,
        toolchain_lock_path=_LOCK,
    )
    build_synthea_dataset(
        raw_fhir_dir=raw_dir,
        output_dir=second,
        config_path=_CONFIG,
        toolchain_lock_path=_LOCK,
    )

    assert (first / "bundle.json").read_bytes() == (second / "bundle.json").read_bytes()
    assert (first / "manifest.json").read_bytes() == (second / "manifest.json").read_bytes()
    serialized = (first / "bundle.json").read_text(encoding="utf-8")
    assert all(source_id not in serialized for source_id in _SOURCE_IDS)


def test_synthetic_dataset_tampering_is_detected(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir()
    for filename in ("bundle.json", "manifest.json"):
        (dataset_dir / filename).write_bytes(
            (_ROOT / "data/synthetic/fhir-r4" / filename).read_bytes()
        )
    bundle_path = dataset_dir / "bundle.json"
    bundle_path.write_bytes(bundle_path.read_bytes() + b" ")

    with pytest.raises(SyntheticDataValidationError, match="checksum"):
        validate_synthetic_dataset(
            dataset_dir=dataset_dir,
            config_path=_CONFIG,
            toolchain_lock_path=_LOCK,
        )

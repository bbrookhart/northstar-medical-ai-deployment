from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast
from urllib.request import Request, urlopen

_MAX_JAR_BYTES = 250_000_000
_CONTAINER_OUTPUT = "/work/artifacts/runtime/synthea/northstar-v1"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Acquire and run the pinned Northstar Synthea toolchain"
    )
    parser.add_argument("action", choices=("download", "generate", "reproduce"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/runtime/synthea/northstar-v1"),
    )
    args = parser.parse_args()
    root = args.root.resolve()
    lock = _json_object(root / "data/synthetic/toolchain-lock.json")
    jar_path = root / "artifacts/runtime/tools/synthea-v4.0.0-with-dependencies.jar"
    output_dir = (root / args.output_dir).resolve()

    if args.action == "download":
        _download_jar(lock, jar_path)
        print(f"Verified pinned Synthea JAR at {jar_path}")
        return
    _verify_jar(lock, jar_path)
    if args.action == "generate":
        _run_synthea(root, lock, jar_path, output_dir)
        print(f"Generated pinned Synthea FHIR at {output_dir / 'fhir'}")
        return
    _verify_reproducibility(root, lock, jar_path, output_dir)
    print("Verified two fresh Synthea runs against the canonical raw FHIR generation")


def _download_jar(lock: dict[str, Any], jar_path: Path) -> None:
    synthea = cast(dict[str, Any], lock["synthea"])
    expected_size = int(synthea["artifact_size_bytes"])
    if expected_size > _MAX_JAR_BYTES:
        raise ValueError("Pinned Synthea artifact exceeds the acquisition limit")
    if jar_path.exists():
        _verify_jar(lock, jar_path)
        return
    jar_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = jar_path.with_suffix(".download")
    request = Request(  # noqa: S310 - exact URL is integrity-checked against the lock digest.
        str(synthea["artifact_url"]),
        headers={"User-Agent": "northstar-polaris-toolchain/0.1"},
        method="GET",
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with (
            urlopen(request, timeout=30.0) as response,  # noqa: S310
            temporary_path.open("wb") as destination,
        ):
            while chunk := response.read(1_048_576):
                size += len(chunk)
                if size > _MAX_JAR_BYTES:
                    raise ValueError("Synthea download exceeded the acquisition limit")
                digest.update(chunk)
                destination.write(chunk)
        if size != expected_size or digest.hexdigest() != synthea["artifact_sha256"]:
            raise ValueError("Downloaded Synthea artifact failed size or SHA-256 verification")
        temporary_path.replace(jar_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _verify_jar(lock: dict[str, Any], jar_path: Path) -> None:
    synthea = cast(dict[str, Any], lock["synthea"])
    if not jar_path.is_file():
        raise FileNotFoundError("Pinned Synthea JAR is missing; run the download action first")
    raw = jar_path.read_bytes()
    if len(raw) != synthea["artifact_size_bytes"]:
        raise ValueError("Pinned Synthea JAR size is invalid")
    if hashlib.sha256(raw).hexdigest() != synthea["artifact_sha256"]:
        raise ValueError("Pinned Synthea JAR SHA-256 is invalid")


def _run_synthea(
    root: Path,
    lock: dict[str, Any],
    jar_path: Path,
    output_dir: Path,
) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"Refusing to overwrite a non-empty generation directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime = cast(dict[str, Any], lock["generator_runtime"])
    image = f"{runtime['image']}@{runtime['digest']}"
    command = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
    ]
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        command.append(f"--user={os.getuid()}:{os.getgid()}")
    config_path = (root / "data/synthetic/config/synthea.properties").resolve()
    command.extend(
        (
            f"--volume={jar_path.resolve()}:/tools/synthea.jar:ro",
            f"--volume={config_path}:/config/synthea.properties:ro",
            f"--volume={output_dir.resolve()}:{_CONTAINER_OUTPUT}:rw",
            image,
            "java",
            "-jar",
            "/tools/synthea.jar",
            "-c",
            "/config/synthea.properties",
            "-s",
            "20260811",
            "-cs",
            "11082026",
            "-p",
            "3",
            "-r",
            "20260811",
            "-e",
            "20260811",
            "Massachusetts",
        )
    )
    try:
        subprocess.run(  # noqa: S603 - fixed argv; no shell invocation.
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Pinned network-disabled Synthea generation failed") from exc
    hashes = _fhir_hashes(output_dir / "fhir")
    if len(hashes) != 3:
        raise ValueError(f"Expected 3 generated FHIR files, found {len(hashes)}")


def _verify_reproducibility(
    root: Path,
    lock: dict[str, Any],
    jar_path: Path,
    canonical_output: Path,
) -> None:
    canonical = _fhir_hashes(canonical_output / "fhir")
    if len(canonical) != 3:
        raise ValueError("Canonical raw generation must contain exactly 3 FHIR files")
    runtime_root = root / "artifacts/runtime/synthea"
    runtime_root.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(prefix="repro-a-", dir=runtime_root) as first_directory,
        tempfile.TemporaryDirectory(prefix="repro-b-", dir=runtime_root) as second_directory,
    ):
        first = Path(first_directory)
        second = Path(second_directory)
        _run_synthea(root, lock, jar_path, first)
        _run_synthea(root, lock, jar_path, second)
        if _fhir_hashes(first / "fhir") != canonical:
            raise ValueError("First reproduction differs from canonical raw FHIR")
        if _fhir_hashes(second / "fhir") != canonical:
            raise ValueError("Second reproduction differs from canonical raw FHIR")


def _fhir_hashes(fhir_dir: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(fhir_dir.glob("*.json"))
    }


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return cast(dict[str, Any], value)


if __name__ == "__main__":
    main()

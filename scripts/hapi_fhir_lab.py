from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from polaris.data.synthetic import validate_synthetic_dataset
from polaris.services.fhir_http import UrllibFhirHttpTransport, validated_fhir_base_url

_FHIR_JSON = "application/fhir+json"
_MAX_RESPONSE_BYTES = 1_048_576
_SYNTHETIC_SOURCE = "urn:northstar:synthetic:synthea-v4.0.0"
_ORIGIN_SYSTEM = "https://northstar.example.test/fhir/CodeSystem/data-origin"


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed or verify the disposable HAPI FHIR lab")
    parser.add_argument("action", choices=("seed", "verify"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--base-url", default="http://127.0.0.1:18080/fhir")
    args = parser.parse_args()

    root = args.root.resolve()
    resources = _validated_resources(root)
    base_url = validated_fhir_base_url(args.base_url, allow_insecure_localhost=True)
    if args.action == "seed":
        _seed(base_url, resources)
    _verify(base_url, resources)
    counts = Counter(str(resource["resourceType"]) for resource in resources)
    print(
        f"{args.action.capitalize()} verified {len(resources)} synthetic resources: "
        + ", ".join(f"{name}={counts[name]}" for name in sorted(counts))
    )


def _validated_resources(root: Path) -> list[dict[str, Any]]:
    dataset_dir = root / "data/synthetic/fhir-r4"
    validate_synthetic_dataset(
        dataset_dir=dataset_dir,
        config_path=root / "data/synthetic/config/synthea.properties",
        toolchain_lock_path=root / "data/synthetic/toolchain-lock.json",
    )
    bundle = json.loads((dataset_dir / "bundle.json").read_text(encoding="utf-8"))
    if not isinstance(bundle, dict) or not isinstance(bundle.get("entry"), list):
        raise ValueError("Validated FHIR dataset Bundle is malformed")
    resources: list[dict[str, Any]] = []
    for entry in bundle["entry"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("resource"), dict):
            raise ValueError("Validated FHIR dataset entry is malformed")
        resources.append(cast(dict[str, Any], entry["resource"]))
    return resources


def _seed(base_url: str, resources: list[dict[str, Any]]) -> None:
    for source_resource in resources:
        resource = cast(dict[str, Any], deepcopy(source_resource))
        resource_type, resource_id = _identity(resource)
        meta = resource.get("meta")
        if isinstance(meta, dict):
            meta.pop("versionId", None)
            meta.pop("lastUpdated", None)
        body = json.dumps(resource, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = Request(  # noqa: S310 - base URL was restricted by validated_fhir_base_url.
            f"{base_url}/{resource_type}/{quote(resource_id, safe='')}",
            data=body,
            headers={
                "Accept": _FHIR_JSON,
                "Content-Type": _FHIR_JSON,
                "User-Agent": "northstar-polaris-lab/0.1",
            },
            method="PUT",
        )
        try:
            with urlopen(request, timeout=10.0) as response:  # noqa: S310
                if response.status not in {200, 201}:
                    raise RuntimeError("HAPI FHIR seed returned an unexpected status")
                if len(response.read(_MAX_RESPONSE_BYTES + 1)) > _MAX_RESPONSE_BYTES:
                    raise RuntimeError("HAPI FHIR seed response exceeded 1 MiB")
        except (HTTPError, OSError, TimeoutError) as exc:
            raise RuntimeError(
                f"HAPI FHIR seed failed for synthetic {resource_type}/{resource_id}"
            ) from exc


def _verify(base_url: str, resources: list[dict[str, Any]]) -> None:
    transport = UrllibFhirHttpTransport(
        base_url,
        timeout_seconds=5.0,
        allow_insecure_localhost=True,
    )
    capability = transport.get_json("metadata", {"_summary": "true"})
    software = capability.get("software")
    if (
        capability.get("resourceType") != "CapabilityStatement"
        or capability.get("fhirVersion") != "4.0.1"
        or not isinstance(software, Mapping)
        or software.get("name") != "HAPI FHIR Server"
        or software.get("version") != "8.10.0"
    ):
        raise ValueError("HAPI FHIR R4 capability identity is not the pinned lab baseline")
    for expected in resources:
        resource_type, resource_id = _identity(expected)
        actual = transport.get_json(f"{resource_type}/{quote(resource_id, safe='')}")
        if actual.get("resourceType") != resource_type or actual.get("id") != resource_id:
            raise ValueError(f"HAPI FHIR identity mismatch for {resource_type}/{resource_id}")
        meta = actual.get("meta")
        if not isinstance(meta, Mapping) or meta.get("source") != _SYNTHETIC_SOURCE:
            raise ValueError(f"HAPI FHIR source label missing for {resource_type}/{resource_id}")
        security = meta.get("security")
        if not isinstance(security, list):
            raise ValueError(f"HAPI FHIR security labels missing for {resource_type}/{resource_id}")
        labels = {
            (coding.get("system"), coding.get("code"))
            for coding in security
            if isinstance(coding, Mapping)
        }
        if (_ORIGIN_SYSTEM, "SYNTHETIC") not in labels:
            raise ValueError(f"HAPI FHIR synthetic label missing for {resource_type}/{resource_id}")
    _verify_disabled_endpoints(base_url)


def _verify_disabled_endpoints(base_url: str) -> None:
    parsed = urlsplit(base_url)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    for endpoint in (
        "/mcp/messages",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/fhir/api-docs",
        "/fhir/swagger-ui/index.html",
    ):
        request = Request(  # noqa: S310 - origin was restricted by validated_fhir_base_url.
            f"{origin}{endpoint}",
            headers={"User-Agent": "northstar-polaris-lab/0.1"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=5.0):  # noqa: S310
                raise ValueError(f"Disabled HAPI endpoint remains exposed: {endpoint}")
        except HTTPError as exc:
            if exc.code != 404:
                raise ValueError(
                    f"Disabled HAPI endpoint returned unexpected status: {endpoint}"
                ) from exc
        except (OSError, TimeoutError) as exc:
            raise RuntimeError("HAPI hardening verification could not reach the lab") from exc


def _identity(resource: Mapping[str, Any]) -> tuple[str, str]:
    resource_type = resource.get("resourceType")
    resource_id = resource.get("id")
    if not isinstance(resource_type, str) or not resource_type.isalpha():
        raise ValueError("FHIR resource type is invalid")
    if not isinstance(resource_id, str) or not resource_id or len(resource_id) > 64:
        raise ValueError("FHIR resource ID is invalid")
    if any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."
        for character in resource_id
    ):
        raise ValueError("FHIR resource ID is invalid")
    return resource_type, resource_id


if __name__ == "__main__":
    main()

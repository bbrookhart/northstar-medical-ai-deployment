from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

SBOM_SPEC_VERSION = "1.6"
SBOM_FORMAT = "CycloneDX"


class SupplyChainError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Component:
    name: str
    version: str
    purl: str
    hashes: tuple[tuple[str, str], ...]
    source: str
    direct: bool

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": self.purl,
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "scope": "required",
            "properties": [
                {"name": "polaris:source", "value": self.source},
                {"name": "polaris:direct", "value": "true" if self.direct else "false"},
            ],
        }
        if self.hashes:
            entry["hashes"] = [
                {"alg": algorithm, "content": value} for algorithm, value in self.hashes
            ]
        return entry


def build_sbom(root: Path) -> dict[str, Any]:
    """Produce a CycloneDX document from the lockfile, not from the installed environment.

    The lockfile is the authority. Reading an installed environment would describe whichever
    machine ran the command, which is the opposite of what a bill of materials is for.
    """

    lock = _load(root / "uv.lock")
    project = _load(root / "pyproject.toml")
    direct = _direct_dependency_names(project)

    # The application itself is the subject of the document, recorded in metadata.component. It
    # is not one of its own dependencies and has no distributable artifact hash.
    project_name = str(project["project"]["name"]).lower()
    components = [
        _component(package, direct)
        for package in lock.get("package", [])
        if str(package["name"]).lower() != project_name
    ]
    components.sort(key=lambda component: (component.name, component.version))

    document = {
        "bomFormat": SBOM_FORMAT,
        "specVersion": SBOM_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": _project_purl(project),
                "name": project["project"]["name"],
                "version": project["project"]["version"],
                "purl": _project_purl(project),
            },
            "properties": [
                {"name": "polaris:requires-python", "value": lock.get("requires-python", "")},
                {"name": "polaris:lock-version", "value": str(lock.get("version", ""))},
                {"name": "polaris:lock-revision", "value": str(lock.get("revision", ""))},
                {"name": "polaris:lock-sha256", "value": file_digest(root / "uv.lock")},
            ],
        },
        "components": [component.to_dict() for component in components],
    }
    return document


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _component(package: dict[str, Any], direct: frozenset[str]) -> Component:
    name = str(package["name"])
    version = str(package["version"])
    source = package.get("source", {})
    registry = str(source.get("registry", source.get("editable", "local")))

    hashes: list[tuple[str, str]] = []
    sdist = package.get("sdist")
    if isinstance(sdist, dict) and isinstance(sdist.get("hash"), str):
        hashes.append(_hash(sdist["hash"]))
    for wheel in package.get("wheels", []) or []:
        if isinstance(wheel, dict) and isinstance(wheel.get("hash"), str):
            hashes.append(_hash(wheel["hash"]))

    return Component(
        name=name,
        version=version,
        purl=f"pkg:pypi/{quote(name)}@{quote(version)}",
        # Every artifact hash the lock pins, sorted so the document is byte-stable.
        hashes=tuple(sorted(set(hashes))),
        source=registry,
        direct=name.lower() in direct,
    )


def _hash(value: str) -> tuple[str, str]:
    algorithm, _, digest = value.partition(":")
    if algorithm != "sha256" or len(digest) != 64:
        raise SupplyChainError(f"Unsupported artifact hash: {value[:32]}")
    return ("SHA-256", digest)


def _direct_dependency_names(project: dict[str, Any]) -> frozenset[str]:
    names: set[str] = set()
    declared = list(project["project"].get("dependencies", []))
    for group in project.get("dependency-groups", {}).values():
        declared.extend(group)
    for requirement in declared:
        name = str(requirement).split(";")[0]
        for separator in ("[", ">", "<", "=", "!", "~", " "):
            name = name.split(separator)[0]
        if name:
            names.add(name.strip().lower())
    return frozenset(names)


def _project_purl(project: dict[str, Any]) -> str:
    return f"pkg:pypi/{project['project']['name']}@{project['project']['version']}"


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SupplyChainError(f"Missing required file: {path.name}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"

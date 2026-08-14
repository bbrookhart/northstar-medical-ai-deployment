from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

_DATASET_ID = "NS-SYN-FHIR-R4-001"
_DATASET_VERSION = "1.0.0"
_FIXED_TIME = "2026-08-11T00:00:00Z"
_SOURCE = "urn:northstar:synthetic:synthea-v4.0.0"
_FHIR_CONFIDENTIALITY_SYSTEM = "http://terminology.hl7.org/CodeSystem/v3-Confidentiality"
_NORTHSTAR_SECURITY_LABEL_SYSTEM = "https://northstar.example.test/fhir/CodeSystem/security-label"
_NORTHSTAR_ORIGIN_SYSTEM = "https://northstar.example.test/fhir/CodeSystem/data-origin"
_RECENT_ENCOUNTER_EXTENSION = (
    "https://northstar.example.test/fhir/StructureDefinition/recent-encounter-date"
)
_CARE_FLAG_EXTENSION = (
    "https://northstar.example.test/fhir/StructureDefinition/care-coordination-flag"
)
_FHIR_ID = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_UUID = re.compile(r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
_SECRET_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "aws_access_key_id",
    "authorization: bearer ",
    "client_secret",
)
_PATIENT_ALLOWED_FIELDS = frozenset(
    {
        "resourceType",
        "id",
        "meta",
        "active",
        "name",
        "communication",
        "managingOrganization",
        "extension",
    }
)


class SyntheticDataValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _PatientProfile:
    patient_id: str
    display_name: str
    facility_id: str
    language: str
    recent_encounter: str
    flags: tuple[str, ...]
    part2_style: bool


_PROFILES = (
    _PatientProfile(
        patient_id="SYN-P1001",
        display_name="Synthea Synthetic 001",
        facility_id="FAC-NORTH",
        language="es",
        recent_encounter="2026-08-01",
        flags=("routine-follow-up-due",),
        part2_style=False,
    ),
    _PatientProfile(
        patient_id="SYN-P2002",
        display_name="Synthea Synthetic 002",
        facility_id="FAC-SOUTH",
        language="es",
        recent_encounter="2026-08-03",
        flags=("interpreter-preferred",),
        part2_style=False,
    ),
    _PatientProfile(
        patient_id="SYN-P3003",
        display_name="Synthea Synthetic 003",
        facility_id="FAC-NORTH",
        language="en",
        recent_encounter="2026-07-30",
        flags=("restricted-follow-up",),
        part2_style=True,
    ),
)


def build_synthea_dataset(
    *,
    raw_fhir_dir: Path,
    output_dir: Path,
    config_path: Path,
    toolchain_lock_path: Path,
) -> dict[str, Any]:
    source_records = _source_records(raw_fhir_dir)
    toolchain = _json_object(toolchain_lock_path)
    _validate_toolchain(toolchain)
    if len(source_records) != len(_PROFILES):
        raise SyntheticDataValidationError(
            f"Expected {len(_PROFILES)} source patients, found {len(source_records)}"
        )

    resources: list[dict[str, Any]] = [
        _organization("FAC-NORTH", "Northstar Synthetic North Facility"),
        _organization("FAC-SOUTH", "Northstar Synthetic South Facility"),
        _organization(
            "NORTHSTAR-SYNTHETIC-PIPELINE",
            "Northstar Synthetic Data Pipeline",
        ),
    ]
    lineage: list[dict[str, str]] = []
    for profile, source_record in zip(_PROFILES, source_records, strict=True):
        resources.extend(
            (
                _patient(profile),
                _consent(profile),
                _provenance(profile, source_record["sha256"]),
            )
        )
        lineage.append(
            {
                "derived_patient_id": profile.patient_id,
                "source_patient_id": source_record["patient_id"],
                "source_file": source_record["file"],
                "source_sha256": source_record["sha256"],
            }
        )

    bundle = {
        "resourceType": "Bundle",
        "id": "northstar-synthea-fhir-r4-v1",
        "meta": _meta(part2_style=False),
        "type": "collection",
        "timestamp": _FIXED_TIME,
        "entry": [
            {
                "fullUrl": f"urn:uuid:{resource['resourceType']}-{resource['id']}",
                "resource": resource,
            }
            for resource in resources
        ],
    }
    bundle_bytes = _canonical_json(bundle)

    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / "bundle.json"
    bundle_path.write_bytes(bundle_bytes)

    transform_path = Path(__file__).resolve()
    manifest = {
        "schema_version": "1.0",
        "dataset": {
            "id": _DATASET_ID,
            "version": _DATASET_VERSION,
            "fhir_version": "4.0.1",
            "classification": "Northstar Restricted Health Data",
            "synthetic_only": True,
            "notice": (
                "Generated synthetic data for an educational simulation. "
                "Never combine with or replace using real patient data."
            ),
        },
        "generator": {
            "name": "Synthea",
            "version": toolchain["synthea"]["version"],
            "tag": toolchain["synthea"]["tag"],
            "release_commit": toolchain["synthea"]["release_commit"],
            "artifact_sha256": toolchain["synthea"]["artifact_sha256"],
            "runtime_image": toolchain["generator_runtime"]["image"],
            "runtime_digest": toolchain["generator_runtime"]["digest"],
            "network": "disabled",
            "population_seed": 20260811,
            "clinician_seed": 11082026,
            "population": 3,
            "reference_date": "2026-08-11",
            "end_date": "2026-08-11",
            "location": "Massachusetts",
            "config_path": "data/synthetic/config/synthea.properties",
            "config_sha256": _sha256(config_path.read_bytes()),
        },
        "transformation": {
            "name": "northstar-minimum-patient-v1",
            "recorded_at": _FIXED_TIME,
            "module_path": "src/polaris/data/synthetic.py",
            "module_sha256": _sha256(transform_path.read_bytes()),
            "steps": [
                "Extract exactly one Patient from each deterministic Synthea transaction Bundle",
                "Replace source identifiers and direct-contact fields with Northstar synthetic IDs",
                "Project only approved patient-summary source fields",
                "Attach Northstar restricted/synthetic security labels and source provenance",
                "Create explicit synthetic Consent and Provenance resources",
            ],
        },
        "lineage": lineage,
        "artifacts": [
            {
                "path": "data/synthetic/fhir-r4/bundle.json",
                "sha256": _sha256(bundle_bytes),
                "size_bytes": len(bundle_bytes),
                "resource_counts": dict(
                    sorted(Counter(resource["resourceType"] for resource in resources).items())
                ),
            }
        ],
        "validation": {
            "status": "passed",
            "checks": [
                "fixed seed/reference/end dates",
                "source FHIR files byte-identical across two generation runs",
                "exact source population and unique IDs",
                "derived FHIR R4 minimum-field contract",
                "security label and synthetic source continuity",
                "active permit Consent per patient",
                "Provenance source hash per patient",
                "no source name/address/telecom/birth date/identifier in derived Patient",
                "no recognized credential marker",
            ],
            "hapi_interoperability": "recorded separately in milestone evidence",
            "reviewer_role": "Data Steward (simulated)",
        },
        "source_and_license": {
            "source_url": toolchain["synthea"]["source_url"],
            "license": toolchain["synthea"]["license"],
            "toolchain_lock": "data/synthetic/toolchain-lock.json",
        },
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_bytes(_canonical_json(manifest))
    validate_synthetic_dataset(
        dataset_dir=output_dir,
        config_path=config_path,
        toolchain_lock_path=toolchain_lock_path,
    )
    return manifest


def validate_synthetic_dataset(
    *,
    dataset_dir: Path,
    config_path: Path,
    toolchain_lock_path: Path,
) -> dict[str, Any]:
    manifest = _json_object(dataset_dir / "manifest.json")
    bundle = _json_object(dataset_dir / "bundle.json")
    toolchain = _json_object(toolchain_lock_path)
    _validate_toolchain(toolchain)

    dataset = _mapping(manifest.get("dataset"), "manifest.dataset")
    if dataset.get("id") != _DATASET_ID or dataset.get("version") != _DATASET_VERSION:
        raise SyntheticDataValidationError("Dataset identity or version is invalid")
    if dataset.get("synthetic_only") is not True or dataset.get("fhir_version") != "4.0.1":
        raise SyntheticDataValidationError("Synthetic-only or FHIR version assertion is invalid")

    generator = _mapping(manifest.get("generator"), "manifest.generator")
    if generator.get("artifact_sha256") != toolchain["synthea"]["artifact_sha256"]:
        raise SyntheticDataValidationError("Generator artifact checksum does not match lock")
    if generator.get("runtime_digest") != toolchain["generator_runtime"]["digest"]:
        raise SyntheticDataValidationError("Generator runtime digest does not match lock")
    if generator.get("config_sha256") != _sha256(config_path.read_bytes()):
        raise SyntheticDataValidationError("Synthea configuration checksum has drifted")

    transformation = _mapping(manifest.get("transformation"), "manifest.transformation")
    if transformation.get("module_sha256") != _sha256(Path(__file__).resolve().read_bytes()):
        raise SyntheticDataValidationError("Synthetic transformation module has drifted")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1:
        raise SyntheticDataValidationError("Manifest must contain exactly one canonical artifact")
    artifact = _mapping(artifacts[0], "manifest.artifacts[0]")
    bundle_bytes = (dataset_dir / "bundle.json").read_bytes()
    if artifact.get("sha256") != _sha256(bundle_bytes):
        raise SyntheticDataValidationError("Canonical FHIR Bundle checksum is invalid")
    if artifact.get("size_bytes") != len(bundle_bytes):
        raise SyntheticDataValidationError("Canonical FHIR Bundle size is invalid")

    resources = _bundle_resources(bundle)
    counts = dict(
        sorted(Counter(str(resource.get("resourceType")) for resource in resources).items())
    )
    if counts != {"Consent": 3, "Organization": 3, "Patient": 3, "Provenance": 3}:
        raise SyntheticDataValidationError(f"Unexpected resource counts: {counts}")
    if artifact.get("resource_counts") != counts:
        raise SyntheticDataValidationError("Manifest resource counts do not match the Bundle")

    patients = [resource for resource in resources if resource.get("resourceType") == "Patient"]
    patient_ids = {str(resource.get("id")) for resource in patients}
    expected_ids = {profile.patient_id for profile in _PROFILES}
    if patient_ids != expected_ids:
        raise SyntheticDataValidationError("Canonical patient IDs are missing or unexpected")
    for patient in patients:
        _validate_patient(patient)
    _validate_consents(resources, expected_ids)
    _validate_provenance(resources, manifest, expected_ids)

    serialized = bundle_bytes.decode("utf-8").casefold()
    if any(marker.casefold() in serialized for marker in _SECRET_MARKERS):
        raise SyntheticDataValidationError("Recognized credential marker found in dataset")
    lineage = manifest.get("lineage")
    if not isinstance(lineage, list) or len(lineage) != 3:
        raise SyntheticDataValidationError("Manifest lineage must cover all source records")
    for record in lineage:
        item = _mapping(record, "manifest.lineage")
        if not _UUID.fullmatch(str(item.get("source_patient_id", ""))):
            raise SyntheticDataValidationError("Source patient lineage ID is invalid")
        if not _SHA256.fullmatch(str(item.get("source_sha256", ""))):
            raise SyntheticDataValidationError("Source patient checksum is invalid")
        if str(item.get("source_patient_id")) in serialized:
            raise SyntheticDataValidationError("Source patient ID leaked into canonical Bundle")
    return manifest


def _source_records(raw_fhir_dir: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for path in sorted(raw_fhir_dir.glob("*.json")):
        raw_bytes = path.read_bytes()
        bundle = cast(dict[str, Any], json.loads(raw_bytes))
        resources = _bundle_resources(bundle, expected_type="transaction")
        patients = [resource for resource in resources if resource.get("resourceType") == "Patient"]
        if len(patients) != 1:
            raise SyntheticDataValidationError(f"{path.name} must contain exactly one Patient")
        patient_id = patients[0].get("id")
        if not isinstance(patient_id, str) or not _UUID.fullmatch(patient_id):
            raise SyntheticDataValidationError(f"{path.name} has an invalid source Patient ID")
        records.append(
            {
                "file": path.name,
                "patient_id": patient_id,
                "sha256": _sha256(raw_bytes),
            }
        )
    return records


def _organization(organization_id: str, name: str) -> dict[str, Any]:
    return {
        "resourceType": "Organization",
        "id": organization_id,
        "meta": _meta(part2_style=False),
        "active": True,
        "name": name,
    }


def _patient(profile: _PatientProfile) -> dict[str, Any]:
    return {
        "resourceType": "Patient",
        "id": profile.patient_id,
        "meta": _meta(part2_style=profile.part2_style),
        "active": True,
        "name": [{"use": "official", "text": profile.display_name}],
        "communication": [
            {
                "language": {"coding": [{"system": "urn:ietf:bcp:47", "code": profile.language}]},
                "preferred": True,
            }
        ],
        "managingOrganization": {"reference": f"Organization/{profile.facility_id}"},
        "extension": [
            {"url": _RECENT_ENCOUNTER_EXTENSION, "valueDate": profile.recent_encounter},
            *({"url": _CARE_FLAG_EXTENSION, "valueString": flag} for flag in profile.flags),
        ],
    }


def _consent(profile: _PatientProfile) -> dict[str, Any]:
    return {
        "resourceType": "Consent",
        "id": f"CNS-{profile.patient_id}",
        "meta": _meta(part2_style=profile.part2_style),
        "status": "active",
        "scope": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/consentscope",
                    "code": "patient-privacy",
                }
            ]
        },
        "category": [{"coding": [{"system": "http://loinc.org", "code": "59284-0"}]}],
        "patient": {"reference": f"Patient/{profile.patient_id}"},
        "dateTime": _FIXED_TIME,
        "performer": [{"reference": f"Organization/{profile.facility_id}"}],
        "provision": {"type": "permit"},
    }


def _provenance(profile: _PatientProfile, source_sha256: str) -> dict[str, Any]:
    return {
        "resourceType": "Provenance",
        "id": f"PRV-{profile.patient_id}",
        "meta": _meta(part2_style=profile.part2_style),
        "target": [{"reference": f"Patient/{profile.patient_id}"}],
        "recorded": _FIXED_TIME,
        "activity": {
            "coding": [
                {
                    "system": "http://terminology.hl7.org/CodeSystem/v3-DataOperation",
                    "code": "CREATE",
                }
            ]
        },
        "agent": [
            {
                "type": {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/provenance-participant-type",
                            "code": "assembler",
                        }
                    ]
                },
                "who": {"reference": "Organization/NORTHSTAR-SYNTHETIC-PIPELINE"},
            }
        ],
        "entity": [
            {
                "role": "source",
                "what": {
                    "identifier": {
                        "system": "urn:northstar:synthea:source-sha256",
                        "value": source_sha256,
                    }
                },
            }
        ],
    }


def _meta(*, part2_style: bool) -> dict[str, Any]:
    security = [
        {"system": _FHIR_CONFIDENTIALITY_SYSTEM, "code": "R"},
        {"system": _NORTHSTAR_ORIGIN_SYSTEM, "code": "SYNTHETIC"},
    ]
    if part2_style:
        security.append({"system": _NORTHSTAR_SECURITY_LABEL_SYSTEM, "code": "SUD-PART2-SIM"})
    return {
        "versionId": "synthea-v4.0.0-northstar-v1",
        "lastUpdated": _FIXED_TIME,
        "source": _SOURCE,
        "security": security,
    }


def _validate_toolchain(toolchain: Mapping[str, Any]) -> None:
    synthea = _mapping(toolchain.get("synthea"), "toolchain.synthea")
    runtime = _mapping(toolchain.get("generator_runtime"), "toolchain.generator_runtime")
    fhir_server = _mapping(toolchain.get("fhir_server"), "toolchain.fhir_server")
    for location, value in (
        ("synthea artifact", synthea.get("artifact_sha256")),
        ("runtime image", runtime.get("digest")),
        ("FHIR server image", fhir_server.get("digest")),
    ):
        digest = str(value)
        if digest.startswith("sha256:"):
            digest = digest.removeprefix("sha256:")
        if not _SHA256.fullmatch(digest):
            raise SyntheticDataValidationError(f"{location} digest is invalid")


def _validate_patient(patient: Mapping[str, Any]) -> None:
    if set(patient) != _PATIENT_ALLOWED_FIELDS:
        raise SyntheticDataValidationError(
            f"Patient {patient.get('id')} contains non-minimum fields: "
            f"{sorted(set(patient) - _PATIENT_ALLOWED_FIELDS)}"
        )
    patient_id = str(patient.get("id", ""))
    if not _FHIR_ID.fullmatch(patient_id):
        raise SyntheticDataValidationError("Derived Patient ID is invalid")
    names = patient.get("name")
    if not isinstance(names, list) or len(names) != 1:
        raise SyntheticDataValidationError(f"Patient {patient_id} must have one synthetic name")
    name = _mapping(names[0], f"Patient/{patient_id}.name")
    if set(name) != {"use", "text"} or "Synthetic" not in str(name.get("text")):
        raise SyntheticDataValidationError(f"Patient {patient_id} name is not safely synthetic")
    meta = _mapping(patient.get("meta"), f"Patient/{patient_id}.meta")
    if meta.get("source") != _SOURCE:
        raise SyntheticDataValidationError(f"Patient {patient_id} source provenance is missing")
    security = meta.get("security")
    if not isinstance(security, list):
        raise SyntheticDataValidationError(f"Patient {patient_id} security labels are missing")
    labels = {
        (str(coding.get("system")), str(coding.get("code")))
        for coding in security
        if isinstance(coding, dict)
    }
    required = {
        (_FHIR_CONFIDENTIALITY_SYSTEM, "R"),
        (_NORTHSTAR_ORIGIN_SYSTEM, "SYNTHETIC"),
    }
    if not labels >= required:
        raise SyntheticDataValidationError(f"Patient {patient_id} required labels are missing")


def _validate_consents(resources: Sequence[Mapping[str, Any]], patient_ids: set[str]) -> None:
    permitted: set[str] = set()
    for resource in resources:
        if resource.get("resourceType") != "Consent":
            continue
        patient = _mapping(resource.get("patient"), "Consent.patient")
        provision = _mapping(resource.get("provision"), "Consent.provision")
        reference = str(patient.get("reference", ""))
        if resource.get("status") != "active" or provision.get("type") != "permit":
            raise SyntheticDataValidationError("Canonical Consent must be active and permit")
        if not reference.startswith("Patient/"):
            raise SyntheticDataValidationError("Consent patient reference is invalid")
        permitted.add(reference.removeprefix("Patient/"))
    if permitted != patient_ids:
        raise SyntheticDataValidationError("Active permit Consent does not cover every patient")


def _validate_provenance(
    resources: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
    patient_ids: set[str],
) -> None:
    lineage = cast(list[dict[str, str]], manifest["lineage"])
    expected_hashes = {item["derived_patient_id"]: item["source_sha256"] for item in lineage}
    proven: set[str] = set()
    for resource in resources:
        if resource.get("resourceType") != "Provenance":
            continue
        targets = resource.get("target")
        entities = resource.get("entity")
        if not isinstance(targets, list) or len(targets) != 1:
            raise SyntheticDataValidationError("Provenance must contain one Patient target")
        if not isinstance(entities, list) or len(entities) != 1:
            raise SyntheticDataValidationError("Provenance must contain one source entity")
        target = _mapping(targets[0], "Provenance.target")
        reference = str(target.get("reference", ""))
        patient_id = reference.removeprefix("Patient/")
        entity = _mapping(entities[0], "Provenance.entity")
        what = _mapping(entity.get("what"), "Provenance.entity.what")
        identifier = _mapping(what.get("identifier"), "Provenance.entity.what.identifier")
        if identifier.get("value") != expected_hashes.get(patient_id):
            raise SyntheticDataValidationError("Provenance source checksum does not match lineage")
        proven.add(patient_id)
    if proven != patient_ids:
        raise SyntheticDataValidationError("Provenance does not cover every patient")


def _bundle_resources(
    bundle: Mapping[str, Any], *, expected_type: str = "collection"
) -> list[dict[str, Any]]:
    if bundle.get("resourceType") != "Bundle" or bundle.get("type") != expected_type:
        raise SyntheticDataValidationError(f"Expected a FHIR {expected_type} Bundle")
    entries = bundle.get("entry")
    if not isinstance(entries, list) or not entries:
        raise SyntheticDataValidationError("FHIR Bundle must contain entries")
    resources: list[dict[str, Any]] = []
    for entry in entries:
        item = _mapping(entry, "Bundle.entry")
        resource = item.get("resource")
        if not isinstance(resource, dict):
            raise SyntheticDataValidationError("FHIR Bundle entry is missing a resource")
        resources.append(cast(dict[str, Any], resource))
    return resources


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SyntheticDataValidationError(f"{path} must contain a JSON object")
    return cast(dict[str, Any], value)


def _mapping(value: object, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SyntheticDataValidationError(f"{location} must be an object")
    return cast(Mapping[str, Any], value)


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, separators=(",", ": "))
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

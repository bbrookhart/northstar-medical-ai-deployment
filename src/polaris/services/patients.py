from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Annotated, Any, Literal, Protocol

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from polaris.domain import (
    ConsentDecision,
    DataSensitivity,
    PatientSummary,
    Principal,
    PurposeOfUse,
    SyntheticPatient,
)
from polaris.errors import DependencyUnavailableError, NotFoundError, UpstreamDataError
from polaris.security.policy import PolicyEngine
from polaris.services.audit import AuditLedger

_FHIR_CONFIDENTIALITY_SYSTEM = "http://terminology.hl7.org/CodeSystem/v3-Confidentiality"
_NORTHSTAR_SECURITY_LABEL_SYSTEM = "https://northstar.example.test/fhir/CodeSystem/security-label"
_NORTHSTAR_ORIGIN_SYSTEM = "https://northstar.example.test/fhir/CodeSystem/data-origin"
_RESTRICTED_LABEL = (_FHIR_CONFIDENTIALITY_SYSTEM, "R")
_PART2_SIMULATION_LABEL = (_NORTHSTAR_SECURITY_LABEL_SYSTEM, "SUD-PART2-SIM")
_SYNTHETIC_ORIGIN_LABEL = (_NORTHSTAR_ORIGIN_SYSTEM, "SYNTHETIC")
_KNOWN_LABELS = frozenset({_RESTRICTED_LABEL, _PART2_SIMULATION_LABEL, _SYNTHETIC_ORIGIN_LABEL})
_CONTRACT_SOURCE = "urn:northstar:synthetic:contract-fixture"
_RECENT_ENCOUNTER_EXTENSION = (
    "https://northstar.example.test/fhir/StructureDefinition/recent-encounter-date"
)
_CARE_FLAG_EXTENSION = (
    "https://northstar.example.test/fhir/StructureDefinition/care-coordination-flag"
)
_REQUIRED_PATIENT_OBLIGATIONS = frozenset({"patient.minimum_summary", "patient.no_raw_narrative"})
FhirText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


class _FhirModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=True)


class _Coding(_FhirModel):
    system: FhirText
    code: FhirText


class _Meta(_FhirModel):
    version_id: FhirText = Field(alias="versionId")
    last_updated: datetime = Field(alias="lastUpdated")
    source: Literal[
        "urn:northstar:synthetic:contract-fixture",
        "urn:northstar:synthetic:synthea-v4.0.0",
    ]
    security: tuple[_Coding, ...] = Field(min_length=1)


class _HumanName(_FhirModel):
    use: Literal["official"]
    text: FhirText


class _Reference(_FhirModel):
    reference: FhirText


class _Language(_FhirModel):
    coding: tuple[_Coding, ...] = Field(min_length=1)


class _Communication(_FhirModel):
    language: _Language
    preferred: bool = False


class _Extension(_FhirModel):
    url: FhirText
    value_date: date | None = Field(default=None, alias="valueDate")
    value_string: FhirText | None = Field(default=None, alias="valueString")

    @model_validator(mode="after")
    def one_supported_value(self) -> _Extension:
        if (self.value_date is None) == (self.value_string is None):
            raise ValueError("Extension must contain exactly one supported value")
        return self


class _PatientResource(_FhirModel):
    resource_type: Literal["Patient"] = Field(alias="resourceType")
    id: FhirText
    meta: _Meta
    name: tuple[_HumanName, ...] = Field(min_length=1)
    communication: tuple[_Communication, ...] = Field(min_length=1)
    managing_organization: _Reference = Field(alias="managingOrganization")
    extension: tuple[_Extension, ...]


class _PatientSecurityResource(_FhirModel):
    """FHIR fields permitted in the pre-authorization security-context lookup."""

    resource_type: Literal["Patient"] = Field(alias="resourceType")
    id: FhirText
    meta: _Meta
    managing_organization: _Reference = Field(alias="managingOrganization")


class PatientSecurityContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    patient_id: str
    facility_id: str
    sensitivities: frozenset[DataSensitivity]
    consent_decision: ConsentDecision
    source: str
    resource_version: str


class FhirPatientGateway(Protocol):
    def security_context(self, patient_id: str) -> PatientSecurityContext: ...

    def read_patient(self, patient_id: str) -> Mapping[str, Any]: ...


class FhirGatewayUnavailable(RuntimeError):
    pass


class InMemoryFhirPatientGateway:
    """Deterministic FHIR contract adapter; HAPI must pass the same broker tests later."""

    def __init__(
        self,
        resources: Iterable[Mapping[str, Any]],
        *,
        consent_decisions: Mapping[str, ConsentDecision],
    ) -> None:
        self._resources = {
            str(resource.get("id")): dict(resource) for resource in resources if resource.get("id")
        }
        self._consent_decisions = dict(consent_decisions)
        self.available = True
        self.full_read_count = 0

    def security_context(self, patient_id: str) -> PatientSecurityContext:
        return patient_security_context(
            self._resource(patient_id),
            expected_id=patient_id,
            consent_decision=self._consent_decisions.get(patient_id, ConsentDecision.UNKNOWN),
        )

    def read_patient(self, patient_id: str) -> Mapping[str, Any]:
        self.full_read_count += 1
        return dict(self._resource(patient_id))

    def _resource(self, patient_id: str) -> Mapping[str, Any]:
        if not self.available:
            raise FhirGatewayUnavailable
        resource = self._resources.get(patient_id)
        if resource is None:
            raise NotFoundError("PATIENT_NOT_AVAILABLE")
        return resource


def seed_fhir_patients() -> tuple[Mapping[str, Any], ...]:
    return (
        _fhir_patient(
            patient_id="SYN-P1001",
            name="Avery Synthetic",
            facility_id="FAC-NORTH",
            language="en",
            recent_encounter="2026-08-01",
            flags=("routine-follow-up-due",),
            part2=False,
        ),
        _fhir_patient(
            patient_id="SYN-P2002",
            name="Morgan Synthetic",
            facility_id="FAC-SOUTH",
            language="es",
            recent_encounter="2026-08-03",
            flags=("interpreter-preferred",),
            part2=False,
        ),
        _fhir_patient(
            patient_id="SYN-P3003",
            name="Riley Synthetic",
            facility_id="FAC-NORTH",
            language="en",
            recent_encounter="2026-07-30",
            flags=("restricted-follow-up",),
            part2=True,
        ),
    )


def seed_consent_decisions() -> Mapping[str, ConsentDecision]:
    return {
        "SYN-P1001": ConsentDecision.PERMIT,
        "SYN-P2002": ConsentDecision.PERMIT,
        "SYN-P3003": ConsentDecision.PERMIT,
    }


class PatientService:
    """Pre-authorized FHIR read broker that returns only the approved minimum view."""

    def __init__(
        self,
        gateway: FhirPatientGateway,
        policy: PolicyEngine,
        audit: AuditLedger,
    ) -> None:
        self._gateway = gateway
        self._policy = policy
        self._audit = audit

    def authorized_patient(
        self,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        patient_id: str,
        correlation_id: str,
    ) -> SyntheticPatient:
        context = self._get_security_context(
            principal=principal, patient_id=patient_id, correlation_id=correlation_id
        )
        decision = self._policy.patient_read(principal, purpose, context)
        obligations_satisfied = decision.obligations >= _REQUIRED_PATIENT_OBLIGATIONS
        outcome = (
            decision.code
            if not decision.allowed or obligations_satisfied
            else "PATIENT_POLICY_OBLIGATION_DENIED"
        )
        self._audit.append(
            actor=principal.subject,
            event_type="patient.read",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata={
                "patient_id": patient_id,
                "purpose": purpose.value,
                "consent_decision": context.consent_decision.value,
                "policy_version": decision.policy_version,
                "fhir_resource_version": context.resource_version,
            },
        )
        if not decision.allowed or not obligations_satisfied:
            raise NotFoundError("PATIENT_NOT_AVAILABLE")
        return self._read_and_validate_patient(
            context,
            principal=principal,
            correlation_id=correlation_id,
        )

    def authorized_summary(
        self,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        patient_id: str,
        correlation_id: str,
    ) -> PatientSummary:
        patient = self.authorized_patient(
            principal=principal,
            purpose=purpose,
            patient_id=patient_id,
            correlation_id=correlation_id,
        )
        return PatientSummary(
            patient_id=patient.patient_id,
            display_name=patient.display_name,
            facility_id=patient.facility_id,
            preferred_language=patient.preferred_language,
            recent_encounter_date=patient.recent_encounter_date,
            care_coordination_flags=patient.care_coordination_flags,
        )

    def _get_security_context(
        self, *, principal: Principal, patient_id: str, correlation_id: str
    ) -> PatientSecurityContext:
        try:
            return self._gateway.security_context(patient_id)
        except NotFoundError:
            self._audit.append(
                actor=principal.subject,
                event_type="patient.read",
                outcome="PATIENT_NOT_AVAILABLE",
                correlation_id=correlation_id,
                metadata={"patient_id": patient_id},
            )
            raise
        except FhirGatewayUnavailable as exc:
            self._audit.append(
                actor=principal.subject,
                event_type="patient.read",
                outcome="FHIR_DEPENDENCY_UNAVAILABLE",
                correlation_id=correlation_id,
                metadata={"patient_id": patient_id},
            )
            raise DependencyUnavailableError("FHIR_DEPENDENCY_UNAVAILABLE") from exc
        except (ValidationError, TypeError, ValueError) as exc:
            self._audit.append(
                actor=principal.subject,
                event_type="patient.read",
                outcome="FHIR_SECURITY_CONTEXT_INVALID",
                correlation_id=correlation_id,
                metadata={"patient_id": patient_id},
            )
            raise UpstreamDataError("FHIR_SECURITY_CONTEXT_INVALID") from exc

    def _read_and_validate_patient(
        self,
        context: PatientSecurityContext,
        *,
        principal: Principal,
        correlation_id: str,
    ) -> SyntheticPatient:
        try:
            raw = self._gateway.read_patient(context.patient_id)
            patient = _synthetic_patient(
                raw,
                expected_id=context.patient_id,
                consent_decision=context.consent_decision,
            )
            refreshed_context = self._gateway.security_context(context.patient_id)
        except NotFoundError as exc:
            self._audit_failure(
                principal=principal,
                context=context,
                correlation_id=correlation_id,
                outcome="FHIR_RESOURCE_CHANGED",
            )
            raise UpstreamDataError("FHIR_RESOURCE_CHANGED") from exc
        except FhirGatewayUnavailable as exc:
            self._audit_failure(
                principal=principal,
                context=context,
                correlation_id=correlation_id,
                outcome="FHIR_DEPENDENCY_UNAVAILABLE",
            )
            raise DependencyUnavailableError("FHIR_DEPENDENCY_UNAVAILABLE") from exc
        except (ValidationError, TypeError, ValueError) as exc:
            self._audit_failure(
                principal=principal,
                context=context,
                correlation_id=correlation_id,
                outcome="FHIR_RESPONSE_INVALID",
            )
            raise UpstreamDataError("FHIR_RESPONSE_INVALID") from exc
        if refreshed_context.consent_decision is not context.consent_decision:
            self._audit_failure(
                principal=principal,
                context=context,
                correlation_id=correlation_id,
                outcome="FHIR_CONSENT_CHANGED",
            )
            raise UpstreamDataError("FHIR_CONSENT_CHANGED")
        if (
            refreshed_context != context
            or patient.patient_id != context.patient_id
            or patient.facility_id != context.facility_id
            or patient.sensitivities != context.sensitivities
        ):
            self._audit_failure(
                principal=principal,
                context=context,
                correlation_id=correlation_id,
                outcome="FHIR_CONTEXT_MISMATCH",
            )
            raise UpstreamDataError("FHIR_CONTEXT_MISMATCH")
        return patient

    def _audit_failure(
        self,
        *,
        principal: Principal,
        context: PatientSecurityContext,
        correlation_id: str,
        outcome: str,
    ) -> None:
        self._audit.append(
            actor=principal.subject,
            event_type="patient.read",
            outcome=outcome,
            correlation_id=correlation_id,
            metadata={
                "patient_id": context.patient_id,
                "fhir_resource_version": context.resource_version,
            },
        )


def _fhir_patient(
    *,
    patient_id: str,
    name: str,
    facility_id: str,
    language: str,
    recent_encounter: str,
    flags: tuple[str, ...],
    part2: bool,
) -> Mapping[str, Any]:
    security = [
        {"system": _FHIR_CONFIDENTIALITY_SYSTEM, "code": "R"},
        {"system": _NORTHSTAR_ORIGIN_SYSTEM, "code": "SYNTHETIC"},
    ]
    if part2:
        security.append({"system": _NORTHSTAR_SECURITY_LABEL_SYSTEM, "code": "SUD-PART2-SIM"})
    return {
        "resourceType": "Patient",
        "id": patient_id,
        "meta": {
            "versionId": "fixture-v1",
            "lastUpdated": "2026-08-11T00:00:00Z",
            "source": _CONTRACT_SOURCE,
            "security": security,
        },
        "name": [{"use": "official", "text": name}],
        "communication": [
            {
                "language": {"coding": [{"system": "urn:ietf:bcp:47", "code": language}]},
                "preferred": True,
            }
        ],
        "managingOrganization": {"reference": f"Organization/{facility_id}"},
        "extension": [
            {"url": _RECENT_ENCOUNTER_EXTENSION, "valueDate": recent_encounter},
            *({"url": _CARE_FLAG_EXTENSION, "valueString": flag} for flag in flags),
        ],
    }


def _parse_resource(raw: Mapping[str, Any], *, expected_id: str) -> _PatientResource:
    resource = _PatientResource.model_validate(raw)
    if resource.id != expected_id:
        raise ValueError("FHIR resource ID does not match the requested patient")
    return resource


def patient_security_context(
    raw: Mapping[str, Any],
    *,
    expected_id: str,
    consent_decision: ConsentDecision,
) -> PatientSecurityContext:
    resource = _PatientSecurityResource.model_validate(raw)
    if resource.id != expected_id:
        raise ValueError("FHIR resource ID does not match the requested patient")
    facility = _facility(resource)
    sensitivities = _sensitivities(resource)
    return PatientSecurityContext(
        patient_id=resource.id,
        facility_id=facility,
        sensitivities=sensitivities,
        consent_decision=consent_decision,
        source=resource.meta.source,
        resource_version=resource.meta.version_id,
    )


def _synthetic_patient(
    raw: Mapping[str, Any],
    *,
    expected_id: str,
    consent_decision: ConsentDecision,
) -> SyntheticPatient:
    resource = _parse_resource(raw, expected_id=expected_id)
    security = patient_security_context(
        raw,
        expected_id=expected_id,
        consent_decision=consent_decision,
    )
    language = next(
        (
            coding.code
            for communication in resource.communication
            if communication.preferred
            for coding in communication.language.coding
            if coding.system == "urn:ietf:bcp:47"
        ),
        None,
    )
    encounter = next(
        (
            extension.value_date
            for extension in resource.extension
            if extension.url == _RECENT_ENCOUNTER_EXTENSION
        ),
        None,
    )
    if language is None or encounter is None:
        raise ValueError("Required minimum-view FHIR fields are missing")
    flags = tuple(
        extension.value_string
        for extension in resource.extension
        if extension.url == _CARE_FLAG_EXTENSION and extension.value_string is not None
    )
    return SyntheticPatient(
        patient_id=resource.id,
        display_name=resource.name[0].text,
        facility_id=security.facility_id,
        preferred_language=language,
        sensitivities=security.sensitivities,
        consent_decision=security.consent_decision,
        recent_encounter_date=encounter,
        care_coordination_flags=flags,
    )


def _facility(resource: _PatientResource | _PatientSecurityResource) -> str:
    prefix = "Organization/"
    reference = resource.managing_organization.reference
    if not reference.startswith(prefix) or len(reference) == len(prefix):
        raise ValueError("FHIR managing organization is invalid")
    return reference.removeprefix(prefix)


def _sensitivities(
    resource: _PatientResource | _PatientSecurityResource,
) -> frozenset[DataSensitivity]:
    labels = frozenset((coding.system, coding.code) for coding in resource.meta.security)
    if (
        _RESTRICTED_LABEL not in labels
        or _SYNTHETIC_ORIGIN_LABEL not in labels
        or labels - _KNOWN_LABELS
    ):
        raise ValueError("FHIR security labels are missing or unsupported")
    sensitivities = {DataSensitivity.GENERAL}
    if _PART2_SIMULATION_LABEL in labels:
        sensitivities.add(DataSensitivity.SUD_PART2)
    return frozenset(sensitivities)

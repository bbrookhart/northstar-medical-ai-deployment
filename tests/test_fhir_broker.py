from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, cast

import pytest

from polaris.domain import ConsentDecision, Decision, Principal, PurposeOfUse
from polaris.errors import DependencyUnavailableError, NotFoundError, UpstreamDataError
from polaris.security.policy import PolicyEngine
from polaris.services.audit import AuditLedger
from polaris.services.patients import (
    FhirPatientGateway,
    InMemoryFhirPatientGateway,
    PatientSecurityContext,
    PatientService,
    seed_consent_decisions,
    seed_fhir_patients,
)
from tests.fhir_gateway_contract import assert_patient_gateway_contract


def _principal(**updates: object) -> Principal:
    principal = Principal(
        subject="user-care-1",
        token_id="tok-test-1",
        client_id="polaris-web",
        scopes=frozenset({"polaris.patient.read"}),
        roles=frozenset({"care_coordinator"}),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset({"SYN-P1001"}),
    )
    return principal.model_copy(update=updates)


def _patient_resource(index: int = 0) -> dict[str, Any]:
    return cast(dict[str, Any], deepcopy(seed_fhir_patients()[index]))


def _gateway(
    resources: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
    consent_decisions: Mapping[str, ConsentDecision] | None = None,
) -> InMemoryFhirPatientGateway:
    return InMemoryFhirPatientGateway(
        seed_fhir_patients() if resources is None else resources,
        consent_decisions=(
            seed_consent_decisions() if consent_decisions is None else consent_decisions
        ),
    )


def _service(
    gateway: FhirPatientGateway,
) -> tuple[PatientService, AuditLedger]:
    audit = AuditLedger("test-audit-key-with-sufficient-entropy")
    return PatientService(gateway, PolicyEngine(), audit), audit


def test_in_memory_gateway_satisfies_shared_patient_gateway_contract() -> None:
    assert_patient_gateway_contract(
        _gateway(),
        expected_display_name="Avery Synthetic",
    )


def test_authorized_read_projects_only_minimum_synthetic_summary() -> None:
    gateway = _gateway()
    service, audit = _service(gateway)

    summary = service.authorized_summary(
        principal=_principal(),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        patient_id="SYN-P1001",
        correlation_id="req-fhir-allow",
    )

    assert gateway.full_read_count == 1
    assert summary.model_dump(mode="json") == {
        "patient_id": "SYN-P1001",
        "display_name": "Avery Synthetic",
        "facility_id": "FAC-NORTH",
        "preferred_language": "en",
        "recent_encounter_date": "2026-08-01",
        "care_coordination_flags": ["routine-follow-up-due"],
        "synthetic_data": True,
    }
    assert audit.snapshot()[-1].outcome == "PATIENT_READ_ALLOWED"


@pytest.mark.parametrize(
    ("principal_updates", "purpose"),
    [
        ({"scopes": frozenset()}, PurposeOfUse.HEALTHCARE_OPERATIONS),
        ({"roles": frozenset({"compliance_analyst"})}, PurposeOfUse.HEALTHCARE_OPERATIONS),
        ({"facilities": frozenset({"FAC-SOUTH"})}, PurposeOfUse.HEALTHCARE_OPERATIONS),
        ({"assigned_patients": frozenset()}, PurposeOfUse.HEALTHCARE_OPERATIONS),
        ({}, PurposeOfUse.TRAINING),
    ],
)
def test_authorization_denial_occurs_before_full_fhir_read(
    principal_updates: dict[str, object], purpose: PurposeOfUse
) -> None:
    gateway = _gateway()
    service, audit = _service(gateway)

    with pytest.raises(NotFoundError, match="Resource not found"):
        service.authorized_summary(
            principal=_principal(**principal_updates),
            purpose=purpose,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-deny",
        )

    assert gateway.full_read_count == 0
    assert audit.snapshot()[-1].outcome.endswith("_DENIED")


def test_part2_style_label_is_denied_before_full_read_without_specific_role() -> None:
    gateway = _gateway()
    service, audit = _service(gateway)

    with pytest.raises(NotFoundError):
        service.authorized_summary(
            principal=_principal(assigned_patients=frozenset({"SYN-P3003"})),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P3003",
            correlation_id="req-fhir-part2-deny",
        )

    assert gateway.full_read_count == 0
    assert audit.snapshot()[-1].outcome == "PATIENT_PART2_DENIED"


def test_unavailable_fhir_dependency_fails_closed_and_is_audited() -> None:
    gateway = _gateway()
    gateway.available = False
    service, audit = _service(gateway)

    with pytest.raises(DependencyUnavailableError) as caught:
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-unavailable",
        )

    assert caught.value.code == "FHIR_DEPENDENCY_UNAVAILABLE"
    assert gateway.full_read_count == 0
    assert audit.snapshot()[-1].outcome == "FHIR_DEPENDENCY_UNAVAILABLE"


def test_unknown_security_label_is_rejected_before_full_read() -> None:
    resource = _patient_resource()
    meta = cast(dict[str, Any], resource["meta"])
    security = cast(list[dict[str, str]], meta["security"])
    security.append({"system": "https://attacker.example.test/labels", "code": "DOWNGRADE"})
    gateway = _gateway([resource])
    service, audit = _service(gateway)

    with pytest.raises(UpstreamDataError) as caught:
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-label",
        )

    assert caught.value.code == "FHIR_SECURITY_CONTEXT_INVALID"
    assert gateway.full_read_count == 0
    assert audit.snapshot()[-1].outcome == "FHIR_SECURITY_CONTEXT_INVALID"


def test_invalid_full_resource_is_rejected_after_authorization() -> None:
    resource = _patient_resource()
    resource.pop("name")
    gateway = _gateway([resource])
    service, audit = _service(gateway)

    with pytest.raises(UpstreamDataError) as caught:
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-invalid",
        )

    assert caught.value.code == "FHIR_RESPONSE_INVALID"
    assert gateway.full_read_count == 1
    assert audit.snapshot()[-1].outcome == "FHIR_RESPONSE_INVALID"


class _MismatchedGateway:
    def __init__(self) -> None:
        self._delegate = _gateway()

    def security_context(self, patient_id: str) -> PatientSecurityContext:
        return self._delegate.security_context(patient_id)

    def read_patient(self, patient_id: str) -> Mapping[str, Any]:
        resource = cast(dict[str, Any], deepcopy(self._delegate.read_patient(patient_id)))
        organization = cast(dict[str, str], resource["managingOrganization"])
        organization["reference"] = "Organization/FAC-SOUTH"
        return resource


def test_post_authorization_context_change_is_blocked_and_audited() -> None:
    service, audit = _service(_MismatchedGateway())

    with pytest.raises(UpstreamDataError) as caught:
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-toctou",
        )

    assert caught.value.code == "FHIR_CONTEXT_MISMATCH"
    assert audit.snapshot()[-1].outcome == "FHIR_CONTEXT_MISMATCH"


class _ConsentChangedGateway:
    def __init__(self) -> None:
        self._delegate = _gateway()
        self._context_reads = 0

    def security_context(self, patient_id: str) -> PatientSecurityContext:
        self._context_reads += 1
        context = self._delegate.security_context(patient_id)
        if self._context_reads > 1:
            return context.model_copy(update={"consent_decision": ConsentDecision.DENY})
        return context

    def read_patient(self, patient_id: str) -> Mapping[str, Any]:
        return self._delegate.read_patient(patient_id)


def test_consent_change_after_authorization_is_blocked_and_audited() -> None:
    service, audit = _service(_ConsentChangedGateway())

    with pytest.raises(UpstreamDataError) as caught:
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-consent-toctou",
        )

    assert caught.value.code == "FHIR_CONSENT_CHANGED"
    assert audit.snapshot()[-1].outcome == "FHIR_CONSENT_CHANGED"


class _MissingObligationPolicy(PolicyEngine):
    def patient_read(
        self,
        principal: Principal,
        purpose: PurposeOfUse,
        patient: object,
    ) -> Decision:
        return Decision(
            allowed=True,
            code="PATIENT_READ_ALLOWED",
            policy_version=self.VERSION,
            obligations=frozenset(),
        )


def test_allowed_decision_without_minimization_obligations_fails_before_full_read() -> None:
    gateway = _gateway()
    audit = AuditLedger("test-audit-key-with-sufficient-entropy")
    service = PatientService(gateway, _MissingObligationPolicy(), audit)

    with pytest.raises(NotFoundError):
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-fhir-obligation",
        )

    assert gateway.full_read_count == 0
    assert audit.snapshot()[-1].outcome == "PATIENT_POLICY_OBLIGATION_DENIED"


@pytest.mark.parametrize(
    ("consent", "outcome"),
    [
        (ConsentDecision.DENY, "PATIENT_CONSENT_DENIED"),
        (ConsentDecision.UNKNOWN, "PATIENT_CONSENT_UNKNOWN_DENIED"),
    ],
)
def test_non_permit_consent_fails_closed_before_full_read(
    consent: ConsentDecision,
    outcome: str,
) -> None:
    gateway = _gateway(consent_decisions={"SYN-P1001": consent})
    service, audit = _service(gateway)

    with pytest.raises(NotFoundError):
        service.authorized_summary(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id=f"req-fhir-consent-{consent.value.lower()}",
        )

    assert gateway.full_read_count == 0
    assert audit.snapshot()[-1].outcome == outcome

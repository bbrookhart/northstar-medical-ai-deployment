from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from polaris.domain import ConsentDecision, DataSensitivity, Principal, PurposeOfUse
from polaris.errors import NotFoundError
from polaris.security.policy import PolicyEngine
from polaris.services.audit import AuditLedger
from polaris.services.patients import FhirPatientGateway, PatientSecurityContext, PatientService


class CountingGateway:
    def __init__(self, delegate: FhirPatientGateway) -> None:
        self._delegate = delegate
        self.full_read_count = 0

    def security_context(self, patient_id: str) -> PatientSecurityContext:
        return self._delegate.security_context(patient_id)

    def read_patient(self, patient_id: str) -> Mapping[str, Any]:
        self.full_read_count += 1
        return self._delegate.read_patient(patient_id)


def assert_patient_gateway_contract(
    gateway: FhirPatientGateway,
    *,
    expected_display_name: str,
) -> None:
    counting_gateway = CountingGateway(gateway)
    context = counting_gateway.security_context("SYN-P1001")
    assert context.patient_id == "SYN-P1001"
    assert context.facility_id == "FAC-NORTH"
    assert context.sensitivities == frozenset({DataSensitivity.GENERAL})
    assert context.consent_decision is ConsentDecision.PERMIT

    principal = Principal(
        subject="user-contract-1",
        token_id="tok-contract-1",
        client_id="polaris-web",
        scopes=frozenset({"polaris.patient.read"}),
        roles=frozenset({"care_coordinator"}),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset({"SYN-P1001"}),
    )
    audit = AuditLedger("contract-audit-key-with-sufficient-entropy")
    service = PatientService(counting_gateway, PolicyEngine(), audit)
    summary = service.authorized_summary(
        principal=principal,
        purpose=PurposeOfUse.TREATMENT,
        patient_id="SYN-P1001",
        correlation_id="req-gateway-contract-allow",
    )
    assert summary.display_name == expected_display_name
    assert summary.synthetic_data is True
    assert counting_gateway.full_read_count == 1

    denied_principal = principal.model_copy(update={"facilities": frozenset({"FAC-SOUTH"})})
    try:
        service.authorized_summary(
            principal=denied_principal,
            purpose=PurposeOfUse.TREATMENT,
            patient_id="SYN-P1001",
            correlation_id="req-gateway-contract-deny",
        )
    except NotFoundError:
        pass
    else:
        raise AssertionError("Gateway contract expected fail-closed facility denial")
    assert counting_gateway.full_read_count == 1
    assert audit.snapshot()[-1].outcome == "PATIENT_FACILITY_DENIED"

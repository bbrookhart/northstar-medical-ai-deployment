from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

import pytest

from polaris.domain import ConsentDecision
from polaris.errors import NotFoundError
from polaris.services.fhir_http import (
    FhirHttpNotFoundError,
    FhirHttpTransportError,
    HttpFhirPatientGateway,
    UrllibFhirHttpTransport,
)
from polaris.services.patients import FhirGatewayUnavailable, seed_fhir_patients


class _FakeTransport:
    def __init__(
        self,
        patient: Mapping[str, Any],
        consent_bundle: Mapping[str, Any],
    ) -> None:
        self.patient = patient
        self.consent_bundle = consent_bundle
        self.calls: list[tuple[str, Mapping[str, str] | None]] = []
        self.error: Exception | None = None
        self.error_path: str | None = None

    def get_json(
        self,
        resource_path: str,
        query: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        self.calls.append((resource_path, query))
        if self.error is not None and (self.error_path is None or resource_path == self.error_path):
            raise self.error
        if resource_path == "Consent":
            return self.consent_bundle
        return self.patient


def _patient() -> Mapping[str, Any]:
    return deepcopy(seed_fhir_patients()[0])


def _consent_bundle(
    *decisions: str,
    patient_id: str = "SYN-P1001",
) -> Mapping[str, Any]:
    return {
        "resourceType": "Bundle",
        "type": "searchset",
        "entry": [
            {
                "resource": {
                    "resourceType": "Consent",
                    "id": f"CNS-{index}",
                    "status": "active",
                    "patient": {"reference": f"Patient/{patient_id}"},
                    "provision": {"type": decision},
                }
            }
            for index, decision in enumerate(decisions, start=1)
        ],
    }


def test_http_gateway_uses_minimum_context_then_reads_full_patient() -> None:
    transport = _FakeTransport(_patient(), _consent_bundle("permit"))
    gateway = HttpFhirPatientGateway(transport)

    context = gateway.security_context("SYN-P1001")
    patient = gateway.read_patient("SYN-P1001")

    assert context.patient_id == "SYN-P1001"
    assert context.consent_decision is ConsentDecision.PERMIT
    assert patient["resourceType"] == "Patient"
    assert transport.calls == [
        ("Patient/SYN-P1001", {"_elements": "id,meta,managingOrganization"}),
        (
            "Consent",
            {"patient": "Patient/SYN-P1001", "status": "active", "_count": "2"},
        ),
        ("Patient/SYN-P1001", None),
    ]


@pytest.mark.parametrize(
    ("decisions", "expected"),
    [
        ((), ConsentDecision.UNKNOWN),
        (("deny",), ConsentDecision.DENY),
    ],
)
def test_http_gateway_maps_explicit_consent_state(
    decisions: tuple[str, ...], expected: ConsentDecision
) -> None:
    gateway = HttpFhirPatientGateway(_FakeTransport(_patient(), _consent_bundle(*decisions)))

    assert gateway.security_context("SYN-P1001").consent_decision is expected


@pytest.mark.parametrize(
    "bundle",
    [
        {"resourceType": "Patient"},
        {"resourceType": "Bundle", "entry": "invalid"},
        _consent_bundle("permit", "deny"),
        _consent_bundle("unsupported"),
        _consent_bundle("permit", patient_id="SYN-P9999"),
        {"resourceType": "Bundle", "entry": [{}]},
    ],
)
def test_http_gateway_rejects_invalid_or_ambiguous_consent(bundle: Mapping[str, Any]) -> None:
    gateway = HttpFhirPatientGateway(_FakeTransport(_patient(), bundle))

    with pytest.raises(ValueError):
        gateway.security_context("SYN-P1001")


def test_http_gateway_rejects_invalid_id_before_transport() -> None:
    transport = _FakeTransport(_patient(), _consent_bundle("permit"))
    gateway = HttpFhirPatientGateway(transport)

    with pytest.raises(ValueError, match="FHIR patient ID is invalid"):
        gateway.security_context("../metadata")

    assert transport.calls == []


def test_http_gateway_maps_patient_not_found_without_leaking_transport_details() -> None:
    transport = _FakeTransport(_patient(), _consent_bundle("permit"))
    transport.error = FhirHttpNotFoundError("upstream detail")
    gateway = HttpFhirPatientGateway(transport)

    with pytest.raises(NotFoundError) as caught:
        gateway.read_patient("SYN-P1001")

    assert caught.value.code == "PATIENT_NOT_AVAILABLE"
    assert "upstream" not in str(caught.value)


def test_http_gateway_maps_dependency_failure() -> None:
    transport = _FakeTransport(_patient(), _consent_bundle("permit"))
    transport.error = FhirHttpTransportError("upstream detail")
    gateway = HttpFhirPatientGateway(transport)

    with pytest.raises(FhirGatewayUnavailable):
        gateway.security_context("SYN-P1001")


def test_http_gateway_maps_missing_consent_search_endpoint_to_dependency_failure() -> None:
    transport = _FakeTransport(_patient(), _consent_bundle("permit"))
    transport.error = FhirHttpNotFoundError("consent endpoint missing")
    transport.error_path = "Consent"
    gateway = HttpFhirPatientGateway(transport)

    with pytest.raises(FhirGatewayUnavailable):
        gateway.security_context("SYN-P1001")


def test_transport_requires_https_except_explicit_loopback_lab_mode() -> None:
    UrllibFhirHttpTransport(
        "http://127.0.0.1:18080/fhir/",
        allow_insecure_localhost=True,
    )
    UrllibFhirHttpTransport("https://fhir.example.test/r4")

    with pytest.raises(ValueError, match="must use HTTPS"):
        UrllibFhirHttpTransport("http://fhir.example.test/r4")
    with pytest.raises(ValueError, match="invalid"):
        UrllibFhirHttpTransport("https://user:password@fhir.example.test/r4")
    with pytest.raises(ValueError, match="invalid"):
        UrllibFhirHttpTransport("https://fhir.example.test/r4?target=other")


@pytest.mark.parametrize(
    ("timeout", "limit"),
    [(0.0, 1024), (31.0, 1024), (1.0, 0), (1.0, 1_048_577)],
)
def test_transport_rejects_unsafe_bounds(timeout: float, limit: int) -> None:
    with pytest.raises(ValueError):
        UrllibFhirHttpTransport(
            "https://fhir.example.test/r4",
            timeout_seconds=timeout,
            max_response_bytes=limit,
        )

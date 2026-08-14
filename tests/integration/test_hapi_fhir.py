from __future__ import annotations

import os

import pytest
from tests.fhir_gateway_contract import assert_patient_gateway_contract

from polaris.services.fhir_http import HttpFhirPatientGateway, UrllibFhirHttpTransport

pytestmark = pytest.mark.integration

_BASE_URL = os.environ.get("POLARIS_HAPI_BASE_URL")


@pytest.mark.skipif(_BASE_URL is None, reason="POLARIS_HAPI_BASE_URL is not set")
def test_hapi_fhir_satisfies_shared_patient_gateway_contract() -> None:
    assert _BASE_URL is not None
    transport = UrllibFhirHttpTransport(
        _BASE_URL,
        timeout_seconds=5.0,
        allow_insecure_localhost=True,
    )
    assert_patient_gateway_contract(
        HttpFhirPatientGateway(transport),
        expected_display_name="Synthea Synthetic 001",
    )

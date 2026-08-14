from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient


def test_assigned_patient_summary_is_minimized_and_labeled_synthetic(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    response = client.get("/v1/patients/SYN-P1001/summary", headers=headers())

    assert response.status_code == 200
    body = response.json()
    assert body["patient_id"] == "SYN-P1001"
    assert body["synthetic_data"] is True
    assert "sensitivities" not in body
    assert "conditions" not in body


def test_cross_patient_and_cross_facility_access_are_concealed(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    cross_patient = client.get("/v1/patients/SYN-P3003/summary", headers=headers())
    cross_facility = client.get(
        "/v1/patients/SYN-P2002/summary",
        headers=headers(patients=["SYN-P2002"]),
    )

    assert cross_patient.status_code == 404
    assert cross_patient.json()["code"] == "PATIENT_NOT_AVAILABLE"
    assert cross_facility.status_code == 404
    assert cross_facility.json()["code"] == "PATIENT_NOT_AVAILABLE"


def test_wrong_purpose_is_denied_without_confirming_patient_existence(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    response = client.get(
        "/v1/patients/SYN-P1001/summary",
        headers=headers(purpose="TRAINING"),
    )

    assert response.status_code == 404
    assert response.json()["code"] == "PATIENT_NOT_AVAILABLE"


def test_part2_style_data_requires_specific_authorization(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    common = {"patients": ["SYN-P3003"]}
    denied = client.get("/v1/patients/SYN-P3003/summary", headers=headers(**common))
    allowed = client.get(
        "/v1/patients/SYN-P3003/summary",
        headers=headers(roles=["care_coordinator", "part2_authorized"], **common),
    )

    assert denied.status_code == 404
    assert allowed.status_code == 200
    assert allowed.json()["patient_id"] == "SYN-P3003"

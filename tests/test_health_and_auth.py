from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

from fastapi.testclient import TestClient


def test_health_endpoints_and_security_headers(client: TestClient) -> None:
    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.json() == {"status": "live"}
    assert ready.json() == {"status": "ready"}
    assert live.headers["x-content-type-options"] == "nosniff"
    assert live.headers["cache-control"] == "no-store"
    assert live.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_missing_bearer_token_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/policies/query",
        headers={"X-Purpose-Of-Use": "HEALTHCARE_OPERATIONS"},
        json={"question": "What is the policy?"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_BEARER_REQUIRED"
    assert response.headers["www-authenticate"] == "Bearer"


def test_expired_token_is_rejected(client: TestClient, token_factory: Callable[..., str]) -> None:
    token = token_factory(expires_delta=timedelta(seconds=-1))
    response = client.post(
        "/v1/policies/query",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Purpose-Of-Use": "HEALTHCARE_OPERATIONS",
        },
        json={"question": "What is the policy?"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "AUTH_INVALID_TOKEN"


def test_missing_or_invalid_purpose_is_rejected(
    client: TestClient, token_factory: Callable[..., str]
) -> None:
    token = token_factory()
    missing = client.post(
        "/v1/policies/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"question": "What is the policy?"},
    )
    invalid = client.post(
        "/v1/policies/query",
        headers={"Authorization": f"Bearer {token}", "X-Purpose-Of-Use": "ANY"},
        json={"question": "What is the policy?"},
    )

    assert missing.status_code == 403
    assert missing.json()["code"] == "PURPOSE_REQUIRED"
    assert invalid.status_code == 403
    assert invalid.json()["code"] == "PURPOSE_INVALID"

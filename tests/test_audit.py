from __future__ import annotations

from collections.abc import Callable
from typing import cast

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_audit_verification_is_access_controlled(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    denied = client.get("/v1/audit/verify", headers=headers(purpose="SECURITY"))
    allowed = client.get(
        "/v1/audit/verify",
        headers=headers(purpose="SECURITY", roles=["security_analyst"]),
    )

    assert denied.status_code == 403
    assert denied.json()["code"] == "AUDIT_ACCESS_DENIED"
    assert allowed.status_code == 200
    assert allowed.json()["valid"] is True


def test_tampered_audit_event_breaks_chain(
    client: TestClient, headers: Callable[..., dict[str, str]]
) -> None:
    client.post(
        "/v1/policies/query",
        headers=headers(),
        json={"question": "What is the Polaris policy?"},
    )
    app = cast(FastAPI, client.app)
    ledger = app.state.services.audit
    events = list(ledger.snapshot())
    assert events and ledger.verify(events)

    events[0] = events[0].model_copy(update={"outcome": "TAMPERED"})
    assert ledger.verify(events) is False

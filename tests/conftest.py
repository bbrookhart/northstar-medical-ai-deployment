from __future__ import annotations

from collections.abc import Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from polaris.config import Settings
from polaris.main import create_app


@pytest.fixture
def settings() -> Settings:
    return Settings.for_tests()


@pytest.fixture
def client(settings: Settings) -> Generator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def token_factory(settings: Settings) -> Callable[..., str]:
    def mint(
        *,
        subject: str = "user-care-1",
        roles: list[str] | None = None,
        facilities: list[str] | None = None,
        patients: list[str] | None = None,
        expires_delta: timedelta = timedelta(minutes=15),
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "sub": subject,
            "jti": f"tok-{uuid4().hex}",
            "client_id": "polaris-web",
            "scope": (
                "polaris.policy.read polaris.patient.read polaris.task.propose "
                "polaris.task.approve polaris.task.execute polaris.audit.read"
            ),
            "iat": now,
            "exp": now + expires_delta,
            "roles": roles or ["care_coordinator"],
            "facilities": facilities or ["FAC-NORTH"],
            "assigned_patients": patients or ["SYN-P1001"],
        }
        claims.update(extra or {})
        return jwt.encode(
            claims,
            settings.jwt_signing_key,
            algorithm="HS256",
            headers={"typ": "at+jwt"},
        )

    return mint


@pytest.fixture
def headers(token_factory: Callable[..., str]) -> Callable[..., dict[str, str]]:
    def build(*, purpose: str = "HEALTHCARE_OPERATIONS", **token_kwargs: Any) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token_factory(**token_kwargs)}",
            "X-Purpose-Of-Use": purpose,
            "X-Request-ID": f"req-{uuid4().hex}",
        }

    return build

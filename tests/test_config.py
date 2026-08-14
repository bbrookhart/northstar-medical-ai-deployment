from __future__ import annotations

from typing import Any, cast

import pytest

from polaris.config import ConfigurationError, Settings


def test_test_settings_are_valid() -> None:
    settings = Settings.for_tests()
    assert settings.environment == "test"
    assert len({settings.jwt_signing_key, settings.audit_hmac_key, settings.approval_hmac_key}) == 3


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("environment", "invalid", "POLARIS_ENVIRONMENT"),
        ("jwt_issuer", "http://insecure.example", "https"),
        ("jwt_audience", "", "AUDIENCE"),
        ("jwt_signing_key", "short", "SIGNING_KEY"),
        ("audit_hmac_key", "short", "HMAC_KEY"),
        ("approval_hmac_key", "short", "APPROVAL_HMAC_KEY"),
        ("action_ttl_seconds", 10, "TTL"),
    ],
)
def test_invalid_configuration_fails_closed(field: str, value: object, message: str) -> None:
    base: dict[str, object] = {
        "environment": "development",
        "jwt_issuer": "https://identity.example.test",
        "jwt_audience": "polaris-api",
        "jwt_signing_key": "a" * 32,
        "audit_hmac_key": "b" * 32,
        "approval_hmac_key": "c" * 32,
        "action_ttl_seconds": 300,
    }
    base[field] = value
    with pytest.raises(ConfigurationError, match=message):
        Settings(**cast(Any, base))


def test_reused_keys_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="all be different"):
        Settings(
            environment="test",
            jwt_issuer="https://identity.example.test",
            jwt_audience="polaris-api",
            jwt_signing_key="same-key-material-is-not-allowed-0001",
            audit_hmac_key="same-key-material-is-not-allowed-0001",
            approval_hmac_key="separate-approval-key-material-allowed-02",
        )

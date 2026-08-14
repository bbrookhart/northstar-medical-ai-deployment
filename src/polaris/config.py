from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigurationError(RuntimeError):
    """Raised when secure runtime configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    jwt_issuer: str
    jwt_audience: str
    jwt_signing_key: str
    audit_hmac_key: str
    approval_hmac_key: str
    action_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise ConfigurationError("POLARIS_ENVIRONMENT must be development, test, or production")
        if not self.jwt_issuer.startswith("https://") and self.environment != "test":
            raise ConfigurationError("POLARIS_JWT_ISSUER must use https outside tests")
        if not self.jwt_audience.strip():
            raise ConfigurationError("POLARIS_JWT_AUDIENCE is required")
        if len(self.jwt_signing_key) < 32:
            raise ConfigurationError("POLARIS_JWT_SIGNING_KEY must contain at least 32 characters")
        if len(self.audit_hmac_key) < 32:
            raise ConfigurationError("POLARIS_AUDIT_HMAC_KEY must contain at least 32 characters")
        if len(self.approval_hmac_key) < 32:
            raise ConfigurationError(
                "POLARIS_APPROVAL_HMAC_KEY must contain at least 32 characters"
            )
        if len({self.jwt_signing_key, self.audit_hmac_key, self.approval_hmac_key}) != 3:
            raise ConfigurationError("JWT, audit, and approval keys must all be different")
        if not 30 <= self.action_ttl_seconds <= 3600:
            raise ConfigurationError("POLARIS_ACTION_TTL_SECONDS must be between 30 and 3600")

    @classmethod
    def from_env(cls) -> Settings:
        required = {
            "environment": "POLARIS_ENVIRONMENT",
            "jwt_issuer": "POLARIS_JWT_ISSUER",
            "jwt_audience": "POLARIS_JWT_AUDIENCE",
            "jwt_signing_key": "POLARIS_JWT_SIGNING_KEY",
            "audit_hmac_key": "POLARIS_AUDIT_HMAC_KEY",
            "approval_hmac_key": "POLARIS_APPROVAL_HMAC_KEY",
        }
        values: dict[str, str] = {}
        missing: list[str] = []
        for field, variable in required.items():
            value = os.getenv(variable)
            if value is None or not value.strip():
                missing.append(variable)
            else:
                values[field] = value.strip()
        if missing:
            raise ConfigurationError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

        ttl_raw = os.getenv("POLARIS_ACTION_TTL_SECONDS", "300")
        try:
            ttl = int(ttl_raw)
        except ValueError as exc:
            raise ConfigurationError("POLARIS_ACTION_TTL_SECONDS must be an integer") from exc

        return cls(**values, action_ttl_seconds=ttl)

    @classmethod
    def for_tests(cls) -> Settings:
        return cls(
            environment="test",
            jwt_issuer="https://identity.northstar.example.test",
            jwt_audience="polaris-api",
            jwt_signing_key="test-jwt-signing-key-not-for-production-0001",
            audit_hmac_key="test-audit-hmac-key-not-for-production-0002",
            approval_hmac_key="test-approval-hmac-key-not-for-production-003",
            action_ttl_seconds=300,
        )

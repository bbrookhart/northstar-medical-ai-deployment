from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PolarisError(Exception):
    code: str
    message: str
    status_code: int = 400

    def __str__(self) -> str:
        return self.message


class AuthenticationError(PolarisError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code=code, message=message, status_code=401)


class AuthorizationError(PolarisError):
    def __init__(self, code: str, message: str = "Access denied") -> None:
        super().__init__(code=code, message=message, status_code=403)


class NotFoundError(PolarisError):
    def __init__(self, code: str, message: str = "Resource not found") -> None:
        super().__init__(code=code, message=message, status_code=404)


class ConflictError(PolarisError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code=code, message=message, status_code=409)


class DependencyUnavailableError(PolarisError):
    def __init__(self, code: str = "DEPENDENCY_UNAVAILABLE") -> None:
        super().__init__(code=code, message="Required service is unavailable", status_code=503)


class UpstreamDataError(PolarisError):
    def __init__(self, code: str = "UPSTREAM_RESPONSE_INVALID") -> None:
        super().__init__(
            code=code, message="Required service returned invalid data", status_code=502
        )

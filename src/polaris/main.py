from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated, Any
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, Request, Response, status
from fastapi.responses import JSONResponse

from polaris.config import Settings
from polaris.domain import (
    ActionApprovalRequest,
    ActionExecutionRequest,
    ActionExecutionResult,
    ActionProposalRequest,
    ActionProposalView,
    ApprovalReceipt,
    AuditVerification,
    PatientSummary,
    PolicyQueryRequest,
    PolicyQueryResponse,
    Principal,
    PurposeOfUse,
)
from polaris.errors import AuthenticationError, AuthorizationError, PolarisError
from polaris.presentation.views import ActionApprovalView
from polaris.security.auth import TokenAuthenticator
from polaris.security.signal_delivery import (
    JSON_MEDIA_TYPE,
    SharedSignalsPushService,
    SignalDeliveryError,
)
from polaris.services.audit import utc_now
from polaris.services.container import Services, build_services
from polaris.services.state import PolarisStateStore

_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")


def create_app(
    settings: Settings | None = None,
    *,
    clock: Callable[[], datetime] = utc_now,
    authenticator: TokenAuthenticator | None = None,
    state_store: PolarisStateStore | None = None,
    identity_signal_delivery: SharedSignalsPushService | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    app = FastAPI(
        title="Northstar Polaris API",
        version="0.1.0",
        description=(
            "Educational secure healthcare AI reference API using synthetic data only. "
            "Not a production or clinical system."
        ),
        docs_url="/docs" if resolved_settings.environment != "production" else None,
        redoc_url=None,
    )
    app.state.services = build_services(
        resolved_settings,
        clock=clock,
        authenticator=authenticator,
        state_store=state_store,
        identity_signal_delivery=identity_signal_delivery,
    )
    app.state.settings = resolved_settings

    @app.exception_handler(PolarisError)
    async def handle_polaris_error(request: Request, exc: PolarisError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        request_id = getattr(request.state, "request_id", "unavailable")
        return JSONResponse(
            status_code=exc.status_code,
            headers=headers,
            content={
                "type": f"urn:northstar:polaris:error:{exc.code}",
                "title": exc.message,
                "status": exc.status_code,
                "code": exc.code,
                "request_id": request_id,
            },
        )

    @app.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request.state.request_id = supplied if _REQUEST_ID.fullmatch(supplied) else uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/health/live", tags=["health"])
    def liveness() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready", tags=["health"])
    def readiness(request: Request) -> dict[str, str]:
        services = _services(request)
        delivery_ready = (
            services.identity_signal_delivery is None or services.identity_signal_delivery.ready()
        )
        healthy = (
            services.state.verify_integrity()
            and services.audit.verify()
            and services.auth.ready()
            and delivery_ready
        )
        return {"status": "ready" if healthy else "not-ready"}

    @app.post(
        "/v1/identity/streams/{stream_id}/events",
        status_code=status.HTTP_202_ACCEPTED,
        tags=["identity-signals"],
    )
    async def receive_identity_signal(
        stream_id: str,
        request: Request,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        content_type: Annotated[str | None, Header(alias="Content-Type")] = None,
        accept: Annotated[str | None, Header(alias="Accept")] = None,
    ) -> Response:
        delivery = _services(request).identity_signal_delivery
        if delivery is None:
            return Response(status_code=status.HTTP_404_NOT_FOUND)
        try:
            context = delivery.authenticate_request(
                stream_id=stream_id,
                authorization=authorization,
                content_type=content_type,
                accept=accept,
                correlation_id=request.state.request_id,
            )
        except SignalDeliveryError as exc:
            return _signal_delivery_error_response(exc)

        body = await _bounded_body(request, delivery.max_body_bytes)
        if body is None:
            delivery.audit_payload_too_large(
                context,
                correlation_id=request.state.request_id,
            )
            return Response(status_code=status.HTTP_413_CONTENT_TOO_LARGE)
        try:
            delivery.deliver(context, body, correlation_id=request.state.request_id)
        except SignalDeliveryError as exc:
            return _signal_delivery_error_response(exc)
        return Response(status_code=status.HTTP_202_ACCEPTED)

    @app.post(
        "/v1/policies/query",
        response_model=PolicyQueryResponse,
        tags=["policy"],
    )
    def query_policy(
        body: PolicyQueryRequest,
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> PolicyQueryResponse:
        return _services(request).retrieval.query(
            principal=principal,
            purpose=purpose,
            question=body.question,
            correlation_id=request.state.request_id,
        )

    @app.get(
        "/v1/patients/{patient_id}/summary",
        response_model=PatientSummary,
        tags=["patients"],
    )
    def patient_summary(
        patient_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> PatientSummary:
        return _services(request).patients.authorized_summary(
            principal=principal,
            purpose=purpose,
            patient_id=patient_id,
            correlation_id=request.state.request_id,
        )

    @app.post(
        "/v1/actions/proposals",
        response_model=ActionProposalView,
        status_code=status.HTTP_201_CREATED,
        tags=["actions"],
    )
    def propose_action(
        body: ActionProposalRequest,
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> ActionProposalView:
        proposal = _services(request).actions.propose(
            principal=principal,
            purpose=purpose,
            action=body.action,
            correlation_id=request.state.request_id,
        )
        return ActionProposalView(
            proposal_id=proposal.proposal_id,
            action=proposal.action,
            action_digest=proposal.action_digest,
            status=proposal.status,
            created_at=proposal.created_at,
            expires_at=proposal.expires_at,
        )

    @app.get(
        "/v1/actions/proposals/{proposal_id}/preview",
        response_model=ActionApprovalView,
        tags=["actions"],
    )
    def preview_action(
        proposal_id: str,
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> ActionApprovalView:
        """Render the trusted approval preview an approver must read before deciding."""

        return _services(request).actions.approval_preview(
            proposal_id=proposal_id,
            approver=principal,
            purpose=purpose,
            correlation_id=request.state.request_id,
        )

    @app.post(
        "/v1/actions/proposals/{proposal_id}/decision",
        response_model=ApprovalReceipt,
        tags=["actions"],
    )
    def decide_action(
        proposal_id: str,
        body: ActionApprovalRequest,
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> ApprovalReceipt:
        return _services(request).actions.decide(
            proposal_id=proposal_id,
            approver=principal,
            purpose=purpose,
            decision=body.decision,
            expected_action_digest=body.expected_action_digest,
            correlation_id=request.state.request_id,
        )

    @app.post(
        "/v1/actions/proposals/{proposal_id}/execute",
        response_model=ActionExecutionResult,
        tags=["actions"],
    )
    def execute_action(
        proposal_id: str,
        body: ActionExecutionRequest,
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> ActionExecutionResult:
        return _services(request).actions.execute(
            proposal_id=proposal_id,
            executor=principal,
            purpose=purpose,
            expected_action_digest=body.expected_action_digest,
            correlation_id=request.state.request_id,
        )

    @app.get(
        "/v1/audit/verify",
        response_model=AuditVerification,
        tags=["audit"],
    )
    def verify_audit(
        request: Request,
        principal: Annotated[Principal, Depends(_principal)],
        purpose: Annotated[PurposeOfUse, Depends(_purpose)],
    ) -> AuditVerification:
        services = _services(request)
        decision = services.policy.audit_read(principal, purpose)
        if not decision.allowed:
            raise AuthorizationError(decision.code)
        events = services.audit.snapshot()
        return AuditVerification(valid=services.audit.verify(events), event_count=len(events))

    return app


def _services(request: Request) -> Services:
    services: Services = request.app.state.services
    return services


def _principal(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> Principal:
    if authorization is None or not authorization.startswith("Bearer "):
        raise AuthenticationError("AUTH_BEARER_REQUIRED", "Bearer token is required")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise AuthenticationError("AUTH_BEARER_REQUIRED", "Bearer token is required")
    return _services(request).auth.authenticate(token)


def _purpose(
    purpose: Annotated[str | None, Header(alias="X-Purpose-Of-Use")] = None,
) -> PurposeOfUse:
    if purpose is None:
        raise AuthorizationError("PURPOSE_REQUIRED", "Purpose of use is required")
    try:
        return PurposeOfUse(purpose)
    except ValueError as exc:
        raise AuthorizationError("PURPOSE_INVALID", "Purpose of use is invalid") from exc


async def _bounded_body(request: Request, limit: int) -> bytes | None:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            return None
        body.extend(chunk)
    return bytes(body)


def _signal_delivery_error_response(exc: SignalDeliveryError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        headers={"Content-Language": "en-US"},
        media_type=JSON_MEDIA_TYPE,
        content={"err": exc.error_code, "description": exc.description},
    )


def app_state(app: FastAPI) -> dict[str, Any]:
    """Small test/diagnostic helper that does not expose secrets or runtime data."""
    return {
        "environment": app.state.settings.environment,
        "policy_version": app.state.services.policy.VERSION,
    }

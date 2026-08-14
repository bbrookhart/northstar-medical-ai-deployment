from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from polaris.config import Settings
from polaris.security.auth import JwtAuthenticator, TokenAuthenticator
from polaris.security.policy import PolicyEngine
from polaris.security.signal_delivery import SharedSignalsPushService
from polaris.services.actions import ActionService
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.patients import (
    InMemoryFhirPatientGateway,
    PatientService,
    seed_consent_decisions,
    seed_fhir_patients,
)
from polaris.services.retrieval import PolicyRetrievalService, seed_policy_documents
from polaris.services.state import InMemoryStateStore, PolarisStateStore


@dataclass(frozen=True, slots=True)
class Services:
    auth: TokenAuthenticator
    policy: PolicyEngine
    audit: AuditLedger
    patients: PatientService
    retrieval: PolicyRetrievalService
    actions: ActionService
    state: PolarisStateStore
    identity_signal_delivery: SharedSignalsPushService | None


def build_services(
    settings: Settings,
    *,
    clock: Callable[[], datetime] = utc_now,
    authenticator: TokenAuthenticator | None = None,
    state_store: PolarisStateStore | None = None,
    identity_signal_delivery: SharedSignalsPushService | None = None,
) -> Services:
    state = state_store or InMemoryStateStore()
    if identity_signal_delivery is not None and identity_signal_delivery.state_store is not state:
        raise ValueError("Identity signal delivery must share the application state store")
    audit = AuditLedger(settings.audit_hmac_key, clock=clock, state=state)
    policy = PolicyEngine()
    patients = PatientService(
        InMemoryFhirPatientGateway(
            seed_fhir_patients(),
            consent_decisions=seed_consent_decisions(),
        ),
        policy,
        audit,
    )
    retrieval = PolicyRetrievalService(seed_policy_documents(), policy, audit)
    actions = ActionService(
        policy=policy,
        patients=patients,
        audit=audit,
        signing_key=settings.approval_hmac_key,
        ttl_seconds=settings.action_ttl_seconds,
        clock=clock,
        state=state,
    )
    return Services(
        auth=authenticator or JwtAuthenticator(settings),
        policy=policy,
        audit=audit,
        patients=patients,
        retrieval=retrieval,
        actions=actions,
        state=state,
        identity_signal_delivery=identity_signal_delivery,
    )

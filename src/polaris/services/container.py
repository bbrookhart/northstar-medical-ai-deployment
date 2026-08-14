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
from polaris.services.corpus import CorpusIngestionService, seed_corpus_sources
from polaris.services.patients import (
    InMemoryFhirPatientGateway,
    PatientService,
    seed_consent_decisions,
    seed_fhir_patients,
)
from polaris.services.retrieval import PolicyRetrievalService
from polaris.services.secure_retrieval import CorpusRegistry
from polaris.services.state import InMemoryStateStore, PolarisStateStore

CORPUS_ID = "northstar-policy"
CORPUS_VERSION = "2026.08.14"


@dataclass(frozen=True, slots=True)
class Services:
    auth: TokenAuthenticator
    policy: PolicyEngine
    audit: AuditLedger
    patients: PatientService
    corpus: CorpusRegistry
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
    corpus = _build_corpus(state, audit, clock=clock)
    retrieval = PolicyRetrievalService(corpus, policy, audit)
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
        corpus=corpus,
        retrieval=retrieval,
        actions=actions,
        state=state,
        identity_signal_delivery=identity_signal_delivery,
    )


def _build_corpus(
    state: PolarisStateStore,
    audit: AuditLedger,
    *,
    clock: Callable[[], datetime],
) -> CorpusRegistry:
    """Promote the seed candidates and serve the resulting version.

    Ingestion runs at startup rather than being baked into a fixture so that the refused candidates
    are refused by the real control every time the application starts.
    """

    ingestion = CorpusIngestionService(clock=clock)
    manifest, chunks, _ = ingestion.build(
        seed_corpus_sources(),
        corpus_id=CORPUS_ID,
        version=CORPUS_VERSION,
    )
    registry = CorpusRegistry(corpus_id=CORPUS_ID, state=state, audit=audit, clock=clock)
    registry.register(manifest, chunks)
    with state.transaction() as transaction:
        active = transaction.latest_corpus_activation(CORPUS_ID)
    if active is None or active.version != CORPUS_VERSION:
        registry.activate(
            CORPUS_VERSION,
            activated_by="polaris-bootstrap",
            correlation_id="corpus-bootstrap",
        )
    return registry

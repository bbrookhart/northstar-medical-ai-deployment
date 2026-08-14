from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
from pydantic import SecretStr, ValidationError

from polaris.domain import (
    AuditEvent,
    IdentityGapIncidentStatus,
    IdentityGapRecoveredEvent,
    IdentityGapRecoveryState,
    IdentitySignalRecord,
    IdentitySignalTarget,
    IdentitySignalType,
    IdentityStreamStatusValue,
    IdentityStreamVerification,
    IdentityStreamVerificationStatus,
    IdentitySubjectState,
)
from polaris.security.okta_gap_recovery import (
    GapRecoveryExitCriterion,
    GapRecoveryPageOutcome,
    OktaGapRecoveryController,
)
from polaris.security.okta_recovery import OktaRecoveryError, OktaSystemLogRecoveryClient
from polaris.security.ssf_operations import SsfHttpResponse
from polaris.services.audit import AuditLedger
from polaris.services.state import (
    InMemoryStateStore,
    PolarisStateStore,
    SqliteStateStore,
    StateIntegrityError,
)

ORIGIN = "https://northstar.okta.example.test"
STREAM = "stream-northstar-identity"
ISSUER = "https://identity.northstar.example.test"
NOW = datetime(2026, 8, 11, 12, tzinfo=UTC)


class MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


class ScriptedTransport:
    def __init__(self) -> None:
        self.responses: list[SsfHttpResponse | Exception] = []
        self.requests: list[str] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> SsfHttpResponse:
        self.requests.append(url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FailingAuditLedger(AuditLedger):
    """Audit ledger that fails once, to prove the page rolls back with it."""

    def __init__(self, key: str, *, state: PolarisStateStore, fail_on_outcome: str) -> None:
        super().__init__(key, state=state)
        self._fail_on_outcome = fail_on_outcome

    def append(
        self,
        *,
        actor: str,
        event_type: str,
        outcome: str,
        correlation_id: str,
        metadata: Mapping[str, str] | None = None,
    ) -> AuditEvent:
        if outcome == self._fail_on_outcome:
            raise StateIntegrityError
        return super().append(
            actor=actor,
            event_type=event_type,
            outcome=outcome,
            correlation_id=correlation_id,
            metadata=metadata,
        )


def test_pages_apply_exactly_once_and_only_invalidate() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    controller, client, state, audit = _controller(clock, transport)
    controller.open_incident(incident_id="INC-001", correlation_id="corr-open")

    first_cursor = _cursor(client, "cursor-1")
    second_cursor = _cursor(client, "cursor-2")
    transport.responses.append(
        _response(
            client,
            first_cursor,
            [
                _event(
                    event_id="11111111-1111-4111-8111-111111111111",
                    event_type="user.session.end",
                    published=NOW - timedelta(minutes=2),
                    subject="00uNorthstarUser01",
                ),
                _event(
                    event_id="22222222-2222-4222-8222-222222222222",
                    event_type="user.account.reset_password",
                    published=NOW - timedelta(minutes=1),
                    subject="00uNorthstarUser02",
                ),
                _event(
                    event_id="33333333-3333-4333-8333-333333333333",
                    event_type="user.mfa.factor.activate",
                    published=NOW - timedelta(minutes=1),
                    subject="00uNorthstarUser03",
                    result="FAILURE",
                ),
            ],
        )
    )
    transport.responses.append(_response(client, second_cursor, []))

    first = controller.apply_next_page(incident_id="INC-001", correlation_id="corr-1")
    second = controller.apply_next_page(incident_id="INC-001", correlation_id="corr-2")

    assert first.outcome is GapRecoveryPageOutcome.APPLIED
    assert (first.scanned, first.applied, first.ignored, first.duplicates) == (3, 2, 1, 0)
    assert second.outcome is GapRecoveryPageOutcome.CAUGHT_UP
    assert second.cursor_sequence == 2

    with state.transaction() as transaction:
        incident = transaction.get_identity_gap_recovery_state("INC-001")
        first_subject = transaction.get_identity_subject_state("00uNorthstarUser01")
        second_subject = transaction.get_identity_subject_state("00uNorthstarUser02")
        failed_subject = transaction.get_identity_subject_state("00uNorthstarUser03")
        checkpoint = transaction.get_identity_stream_checkpoint(STREAM)
    assert incident is not None
    assert incident.status is IdentityGapIncidentStatus.RECOVERING
    assert incident.next_cursor_url == second_cursor
    assert (incident.pages_applied, incident.events_applied, incident.events_ignored) == (2, 2, 1)
    assert incident.caught_up_at == NOW
    assert first_subject is not None
    assert first_subject.invalid_before == NOW - timedelta(minutes=2)
    assert first_subject.recovered_event_id == "11111111-1111-4111-8111-111111111111"
    assert first_subject.signal_id is None
    assert second_subject is not None
    # A failed provider operation is counted but never enforced.
    assert failed_subject is None
    # A compensating read must not manufacture SSF delivery freshness.
    assert checkpoint is None
    assert audit.verify()
    outcomes = [event.outcome for event in audit.snapshot()]
    assert outcomes == [
        "GAP_INCIDENT_OPENED",
        "GAP_RECOVERY_PAGE_APPLIED",
        "GAP_RECOVERY_PAGE_APPLIED",
    ]
    assert all("cursor-" not in json.dumps(event.metadata) for event in audit.snapshot())


def test_duplicate_provider_event_is_counted_and_never_reapplied() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    controller, client, state, _ = _controller(clock, transport)
    controller.open_incident(incident_id="INC-002", correlation_id="corr-open")
    duplicate_id = "44444444-4444-4444-8444-444444444444"
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-1"),
            [
                _event(
                    event_id=duplicate_id,
                    published=NOW - timedelta(minutes=5),
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-2"),
            [
                _event(
                    event_id=duplicate_id,
                    published=NOW - timedelta(minutes=1),
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )

    controller.apply_next_page(incident_id="INC-002", correlation_id="corr-1")
    replay = controller.apply_next_page(incident_id="INC-002", correlation_id="corr-2")

    assert (replay.applied, replay.duplicates) == (0, 1)
    with state.transaction() as transaction:
        subject = transaction.get_identity_subject_state("00uNorthstarUser01")
        incident = transaction.get_identity_gap_recovery_state("INC-002")
    assert subject is not None
    # The replayed copy carries a later timestamp; reapplying it would move the watermark forward.
    assert subject.invalid_before == NOW - timedelta(minutes=5)
    assert incident is not None
    assert (incident.events_applied, incident.events_duplicate) == (1, 1)


def test_stale_worker_page_is_discarded_on_cursor_conflict() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    controller, client, state, _ = _controller(clock, transport)
    audit = AuditLedger("audit-key-for-gap-recovery-tests", state=state)
    controller.open_incident(incident_id="INC-003", correlation_id="corr-open")

    # Both workers read sequence 0. The second worker's page is already in flight when the first
    # commits, which is exactly the race the cursor sequence exists to lose safely.
    winner = OktaGapRecoveryController(
        client=_client(clock, transport),
        stream_id=STREAM,
        audit=audit,
        clock=clock,
    )
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-1"),
            [
                _event(
                    event_id="55555555-5555-4555-8555-555555555555",
                    published=NOW - timedelta(minutes=3),
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-1"),
            [
                _event(
                    event_id="66666666-6666-4666-8666-666666666666",
                    published=NOW - timedelta(minutes=2),
                    subject="00uNorthstarUser09",
                )
            ],
        )
    )
    racing = _RacingClient(
        client,
        on_fetch=lambda: winner.apply_next_page(
            incident_id="INC-003",
            correlation_id="corr-winner",
        ),
    )
    stale = OktaGapRecoveryController(
        client=racing,  # type: ignore[arg-type]
        stream_id=STREAM,
        audit=audit,
        clock=clock,
    )

    result = stale.apply_next_page(incident_id="INC-003", correlation_id="corr-stale")

    assert result.outcome is GapRecoveryPageOutcome.CURSOR_CONFLICT
    assert result.applied == 0
    with state.transaction() as transaction:
        incident = transaction.get_identity_gap_recovery_state("INC-003")
        loser_subject = transaction.get_identity_subject_state("00uNorthstarUser09")
        loser_event = transaction.get_identity_gap_recovered_event(
            "66666666-6666-4666-8666-666666666666"
        )
    assert incident is not None
    assert incident.cursor_sequence == 1
    assert incident.events_applied == 1
    assert loser_subject is None
    assert loser_event is None


def test_audit_failure_rolls_back_the_whole_page(tmp_path: Path) -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    state = SqliteStateStore(tmp_path / "gap-recovery.db")
    audit = FailingAuditLedger(
        "audit-key-for-gap-recovery-tests",
        state=state,
        fail_on_outcome="GAP_RECOVERY_PAGE_APPLIED",
    )
    client = _client(clock, transport)
    controller = OktaGapRecoveryController(
        client=client,
        stream_id=STREAM,
        audit=audit,
        clock=clock,
    )
    controller.open_incident(incident_id="INC-004", correlation_id="corr-open")
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-1"),
            [
                _event(
                    event_id="77777777-7777-4777-8777-777777777777",
                    published=NOW - timedelta(minutes=1),
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )

    with pytest.raises(StateIntegrityError):
        controller.apply_next_page(incident_id="INC-004", correlation_id="corr-1")

    reopened = SqliteStateStore(tmp_path / "gap-recovery.db")
    with reopened.transaction() as transaction:
        incident = transaction.get_identity_gap_recovery_state("INC-004")
        recovered = transaction.get_identity_gap_recovered_event(
            "77777777-7777-4777-8777-777777777777"
        )
        subject = transaction.get_identity_subject_state("00uNorthstarUser01")
    assert incident is not None
    assert incident.cursor_sequence == 0
    assert incident.status is IdentityGapIncidentStatus.OPEN
    assert recovered is None
    assert subject is None
    assert reopened.verify_integrity()


def test_applied_cursor_and_events_survive_restart(tmp_path: Path) -> None:
    database = tmp_path / "gap-restart.db"
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    state = SqliteStateStore(database)
    audit = AuditLedger("audit-key-for-gap-recovery-tests", state=state)
    client = _client(clock, transport)
    controller = OktaGapRecoveryController(
        client=client, stream_id=STREAM, audit=audit, clock=clock
    )
    controller.open_incident(incident_id="INC-005", correlation_id="corr-open")
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-1"),
            [
                _event(
                    event_id="88888888-8888-4888-8888-888888888888",
                    published=NOW - timedelta(minutes=4),
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )
    controller.apply_next_page(incident_id="INC-005", correlation_id="corr-1")

    restarted_state = SqliteStateStore(database)
    restarted_audit = AuditLedger("audit-key-for-gap-recovery-tests", state=restarted_state)
    restarted = OktaGapRecoveryController(
        client=_client(clock, transport),
        stream_id=STREAM,
        audit=restarted_audit,
        clock=clock,
    )
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-2"),
            [
                _event(
                    event_id="88888888-8888-4888-8888-888888888888",
                    published=NOW,
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )
    replay = restarted.apply_next_page(incident_id="INC-005", correlation_id="corr-2")

    assert (replay.applied, replay.duplicates) == (0, 1)
    assert restarted_state.verify_integrity()
    assert restarted_audit.verify()
    with restarted_state.transaction() as transaction:
        subject = transaction.get_identity_subject_state("00uNorthstarUser01")
    assert subject is not None
    assert subject.invalid_before == NOW - timedelta(minutes=4)


def test_exit_requires_every_recovery_signal() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    controller, client, state, _ = _controller(clock, transport)
    controller.open_incident(incident_id="INC-006", correlation_id="corr-open")
    transport.responses.append(_response(client, _cursor(client, "cursor-1"), []))
    controller.apply_next_page(incident_id="INC-006", correlation_id="corr-1")

    caught_up_only = controller.evaluate_exit(incident_id="INC-006", correlation_id="corr-exit-1")

    assert caught_up_only.recovered is False
    assert set(caught_up_only.unmet) == {
        GapRecoveryExitCriterion.STREAM_STATUS_ENABLED,
        GapRecoveryExitCriterion.FRESH_CORRELATED_VERIFICATION,
    }

    _seed_enabled_status(state, observed_at=NOW)
    status_only = controller.evaluate_exit(incident_id="INC-006", correlation_id="corr-exit-2")
    assert status_only.unmet == (GapRecoveryExitCriterion.FRESH_CORRELATED_VERIFICATION,)

    # A receipt that predates the incident cannot close it.
    _seed_verification(state, completed_at=NOW - timedelta(hours=2), suffix="old")
    stale = controller.evaluate_exit(incident_id="INC-006", correlation_id="corr-exit-3")
    assert stale.unmet == (GapRecoveryExitCriterion.FRESH_CORRELATED_VERIFICATION,)

    _seed_verification(state, completed_at=NOW, suffix="fresh")
    recovered = controller.evaluate_exit(incident_id="INC-006", correlation_id="corr-exit-4")

    assert recovered.recovered is True
    assert recovered.unmet == ()
    with state.transaction() as transaction:
        incident = transaction.get_identity_gap_recovery_state("INC-006")
    assert incident is not None
    assert incident.status is IdentityGapIncidentStatus.RECOVERED
    assert incident.closed_at == NOW
    with pytest.raises(StateIntegrityError):
        controller.apply_next_page(incident_id="INC-006", correlation_id="corr-closed")


def test_empty_first_page_alone_never_recovers() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    controller, _client_unused, state, _ = _controller(clock, transport)
    controller.open_incident(incident_id="INC-007", correlation_id="corr-open")

    unstarted = controller.evaluate_exit(incident_id="INC-007", correlation_id="corr-exit")

    assert unstarted.recovered is False
    assert GapRecoveryExitCriterion.PAGES_APPLIED in unstarted.unmet
    assert GapRecoveryExitCriterion.CAUGHT_UP_CURSOR_COMMITTED in unstarted.unmet

    transport.responses.append(OktaRecoveryError(retryable=True))
    with pytest.raises(OktaRecoveryError):
        controller.apply_next_page(incident_id="INC-007", correlation_id="corr-fail")
    with state.transaction() as transaction:
        incident = transaction.get_identity_gap_recovery_state("INC-007")
    assert incident is not None
    assert incident.cursor_sequence == 0


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_cursor_sequencing_rejects_skips_rewinds_and_rebinding(
    store_kind: str,
    tmp_path: Path,
) -> None:
    state = _state_store(store_kind, tmp_path / "cas.db")
    opened = _incident(sequence=0, status=IdentityGapIncidentStatus.OPEN)
    with state.transaction() as transaction:
        transaction.save_identity_gap_recovery_state(opened)

    for rejected in (
        # A first save must start at sequence 0 in the OPEN state.
        opened.model_copy(update={"incident_id": "INC-CAS-2", "cursor_sequence": 1}),
        # Sequence may only advance by one.
        _incident(sequence=2, status=IdentityGapIncidentStatus.RECOVERING),
        # The incident cannot be rebound to another stream.
        _incident(sequence=1, status=IdentityGapIncidentStatus.RECOVERING).model_copy(
            update={"stream_id": "stream-other"}
        ),
    ):
        with state.transaction() as transaction, pytest.raises(StateIntegrityError):
            transaction.save_identity_gap_recovery_state(rejected)

    advanced = _incident(sequence=1, status=IdentityGapIncidentStatus.RECOVERING)
    with state.transaction() as transaction:
        transaction.save_identity_gap_recovery_state(advanced)
        assert transaction.active_identity_gap_recovery_state(STREAM) == advanced
    # The same sequence cannot be committed twice, and counters cannot regress.
    with state.transaction() as transaction, pytest.raises(StateIntegrityError):
        transaction.save_identity_gap_recovery_state(advanced)
    with state.transaction() as transaction, pytest.raises(StateIntegrityError):
        transaction.save_identity_gap_recovery_state(
            _incident(sequence=2, status=IdentityGapIncidentStatus.RECOVERING).model_copy(
                update={"events_applied": 0, "pages_applied": 2}
            )
        )


def test_tampered_incident_counters_fail_integrity(tmp_path: Path) -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    database = tmp_path / "gap-tamper.db"
    state = SqliteStateStore(database)
    audit = AuditLedger("audit-key-for-gap-recovery-tests", state=state)
    client = _client(clock, transport)
    controller = OktaGapRecoveryController(
        client=client, stream_id=STREAM, audit=audit, clock=clock
    )
    controller.open_incident(incident_id="INC-011", correlation_id="corr-open")
    transport.responses.append(
        _response(
            client,
            _cursor(client, "cursor-1"),
            [
                _event(
                    event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    published=NOW - timedelta(minutes=2),
                    subject="00uNorthstarUser01",
                )
            ],
        )
    )
    controller.apply_next_page(incident_id="INC-011", correlation_id="corr-1")
    assert state.verify_integrity()

    with state.transaction() as transaction:
        incident = transaction.get_identity_gap_recovery_state("INC-011")
    assert incident is not None
    forged = incident.model_copy(update={"events_applied": 5})
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "UPDATE identity_gap_recovery_states SET document_json = ? WHERE incident_id = ?",
            (forged.model_dump_json(), "INC-011"),
        )

    assert SqliteStateStore(database).verify_integrity() is False


def test_controller_rejects_unsafe_configuration() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    state = InMemoryStateStore()
    audit = AuditLedger("audit-key-for-gap-recovery-tests", state=state)
    client = _client(clock, transport)
    for kwargs in (
        {"stream_id": ""},
        {"max_observation_age": timedelta(0)},
        {"max_verification_age": timedelta(days=2)},
    ):
        with pytest.raises(ValueError):
            OktaGapRecoveryController(
                client=client,
                stream_id=str(kwargs.get("stream_id", STREAM)),
                audit=audit,
                clock=clock,
                **{
                    key: value
                    for key, value in kwargs.items()
                    if key != "stream_id"  # type: ignore[arg-type]
                },
            )


def test_recovered_events_and_incidents_reject_unsafe_shapes() -> None:
    with pytest.raises(ValidationError):
        IdentityGapRecoveredEvent(
            provider_event_id="99999999-9999-4999-8999-999999999999",
            incident_id="INC-008",
            stream_id=STREAM,
            provider_event_type="user.account.update_profile",
            # Only session revocation and credential change may be recovered from the log feed.
            signal_type=IdentitySignalType.TOKEN_CLAIMS_CHANGE,
            subject="00uNorthstarUser01",
            effective_at=NOW,
            applied_at=NOW,
            cursor_sequence=1,
        )
    with pytest.raises(ValidationError):
        IdentitySubjectState(subject="00uNorthstarUser01", invalid_before=NOW)
    with pytest.raises(ValidationError):
        IdentitySubjectState(
            subject="00uNorthstarUser01",
            invalid_before=NOW,
            signal_id="set-1",
            recovered_event_id="99999999-9999-4999-8999-999999999999",
        )


def test_one_open_incident_per_stream() -> None:
    clock = MutableClock(NOW)
    transport = ScriptedTransport()
    controller, _, _, _ = _controller(clock, transport)
    controller.open_incident(incident_id="INC-009", correlation_id="corr-open")

    with pytest.raises(StateIntegrityError):
        controller.open_incident(incident_id="INC-010", correlation_id="corr-open-2")


def _incident(*, sequence: int, status: IdentityGapIncidentStatus) -> IdentityGapRecoveryState:
    return IdentityGapRecoveryState(
        incident_id="INC-CAS-1",
        stream_id=STREAM,
        status=status,
        cursor_sequence=sequence,
        next_cursor_url=f"{ORIGIN}/api/v1/logs?after=cursor-{sequence}",
        opened_at=NOW,
        updated_at=NOW + timedelta(seconds=sequence),
        pages_applied=sequence,
        events_applied=sequence,
        events_ignored=0,
        events_duplicate=0,
        last_page_at=NOW + timedelta(seconds=sequence) if sequence else None,
    )


def _state_store(store_kind: str, database: Path) -> PolarisStateStore:
    return InMemoryStateStore() if store_kind == "memory" else SqliteStateStore(database)


def _controller(
    clock: MutableClock,
    transport: ScriptedTransport,
) -> tuple[OktaGapRecoveryController, OktaSystemLogRecoveryClient, PolarisStateStore, AuditLedger]:
    state = InMemoryStateStore()
    audit = AuditLedger("audit-key-for-gap-recovery-tests", state=state)
    client = _client(clock, transport)
    controller = OktaGapRecoveryController(
        client=client,
        stream_id=STREAM,
        audit=audit,
        clock=clock,
    )
    return controller, client, state, audit


class _RacingClient:
    """Lets another worker commit the same cursor while this page is in flight."""

    def __init__(
        self,
        inner: OktaSystemLogRecoveryClient,
        *,
        on_fetch: Callable[[], object],
    ) -> None:
        self._inner = inner
        self._on_fetch = on_fetch

    @property
    def initial_cursor_url(self) -> str:
        return self._inner.initial_cursor_url

    def fetch_page(self, *, cursor_url: str | None = None) -> object:
        self._on_fetch()
        return self._inner.fetch_page(cursor_url=cursor_url)


def _client(clock: MutableClock, transport: ScriptedTransport) -> OktaSystemLogRecoveryClient:
    return OktaSystemLogRecoveryClient(
        okta_origin=ORIGIN,
        transport=transport,
        authorization_provider=lambda: SecretStr("system-log-oauth-token"),
        initial_since=clock.current - timedelta(minutes=30),
        clock=clock,
    )


def _cursor(client: OktaSystemLogRecoveryClient, after: str) -> str:
    parsed = urlsplit(client.initial_cursor_url)
    query = [*parse_qsl(parsed.query, keep_blank_values=True), ("after", after)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _response(
    client: OktaSystemLogRecoveryClient,
    cursor: str,
    payload: object,
) -> SsfHttpResponse:
    link = f'<{client.initial_cursor_url}>; rel="self", <{cursor}>; rel="next"'
    return SsfHttpResponse(
        200,
        {"content-type": "application/json; charset=utf-8", "link": link},
        json.dumps(payload).encode(),
    )


def _event(
    *,
    event_id: str,
    event_type: str = "user.session.end",
    published: datetime,
    subject: str,
    result: str = "SUCCESS",
) -> dict[str, object]:
    return {
        "uuid": event_id,
        "published": published.isoformat().replace("+00:00", "Z"),
        "eventType": event_type,
        "outcome": {"result": result},
        "target": [{"type": "User", "id": subject}],
    }


def _seed_enabled_status(state: PolarisStateStore, *, observed_at: datetime) -> None:
    signal = IdentitySignalRecord(
        event_id="set-stream-updated-enabled",
        stream_id=STREAM,
        transmitter_id="okta-transmitter",
        issuer=ISSUER,
        audience="polaris-identity-signals",
        event_type=IdentitySignalType.STREAM_UPDATED,
        target=IdentitySignalTarget.STREAM,
        stream_status=IdentityStreamStatusValue.ENABLED,
        event_time=observed_at,
        received_at=observed_at,
        payload_hash=hashlib.sha256(b"stream-updated").hexdigest(),
    )
    from polaris.domain import IdentityStreamObservedState

    with state.transaction() as transaction:
        transaction.save_identity_signal(signal)
        transaction.save_identity_stream_observed_state(
            IdentityStreamObservedState(
                stream_id=STREAM,
                status=IdentityStreamStatusValue.ENABLED,
                observed_at=observed_at,
                signal_id=signal.event_id,
            )
        )


def _seed_verification(state: PolarisStateStore, *, completed_at: datetime, suffix: str) -> None:
    signal = IdentitySignalRecord(
        event_id=f"set-verification-{suffix}",
        stream_id=STREAM,
        transmitter_id="okta-transmitter",
        issuer=ISSUER,
        audience="polaris-identity-signals",
        event_type=IdentitySignalType.STREAM_VERIFICATION,
        target=IdentitySignalTarget.STREAM,
        verification_state_hash=hashlib.sha256(suffix.encode()).hexdigest(),
        event_time=completed_at,
        received_at=completed_at,
        payload_hash=hashlib.sha256(f"verification-{suffix}".encode()).hexdigest(),
    )
    requested_at = completed_at - timedelta(seconds=30)
    with state.transaction() as transaction:
        transaction.save_identity_signal(signal)
        transaction.save_identity_stream_verification(
            IdentityStreamVerification(
                verification_id=f"ver-{suffix}",
                stream_id=STREAM,
                state_hash=hashlib.sha256(suffix.encode()).hexdigest(),
                status=IdentityStreamVerificationStatus.VERIFIED,
                requested_at=requested_at,
                deadline_at=requested_at + timedelta(minutes=5),
                accepted_at=requested_at,
                completed_at=completed_at,
                signal_id=signal.event_id,
            )
        )

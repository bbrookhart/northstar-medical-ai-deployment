from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from polaris.config import Settings
from polaris.domain import (
    ActionProposal,
    FollowUpAction,
    Principal,
    ProposalStatus,
    PurposeOfUse,
)
from polaris.main import create_app
from polaris.services.actions import action_digest
from polaris.services.audit import AuditLedger
from polaris.services.state import (
    InMemoryStateStore,
    PolarisStateStore,
    SqliteStateStore,
    StateIntegrityError,
    StateStoreUnavailable,
)


def test_sqlite_workflow_and_audit_survive_restart_with_idempotency(
    tmp_path: Path,
    settings: Settings,
    headers: Callable[..., dict[str, str]],
) -> None:
    database_path = tmp_path / "polaris-state.db"
    first_store = SqliteStateStore(database_path)
    with TestClient(create_app(settings, state_store=first_store)) as first_client:
        proposal = _propose(first_client, headers)
        proposal_id = str(proposal["proposal_id"])
        digest = str(proposal["action_digest"])
        approval = first_client.post(
            f"/v1/actions/proposals/{proposal_id}/decision",
            headers=headers(subject="approver-1", roles=["task_approver"]),
            json={"decision": "APPROVE", "expected_action_digest": digest, "comment": ""},
        )
        assert approval.status_code == 200
        first_event_count = len(cast(FastAPI, first_client.app).state.services.audit.snapshot())

    second_store = SqliteStateStore(database_path)
    with TestClient(create_app(settings, state_store=second_store)) as second_client:
        services = cast(FastAPI, second_client.app).state.services
        assert services.actions.get_proposal(proposal_id).status is ProposalStatus.APPROVED
        executed = second_client.post(
            f"/v1/actions/proposals/{proposal_id}/execute",
            headers=headers(subject="executor-1", roles=["task_executor"]),
            json={"expected_action_digest": digest},
        )
        assert executed.status_code == 200
        assert executed.json()["idempotent_replay"] is False
        task_id = executed.json()["task_id"]
        assert len(services.audit.snapshot()) > first_event_count
        assert services.audit.verify()

    third_store = SqliteStateStore(database_path)
    with TestClient(create_app(settings, state_store=third_store)) as third_client:
        replay = third_client.post(
            f"/v1/actions/proposals/{proposal_id}/execute",
            headers=headers(subject="executor-1", roles=["task_executor"]),
            json={"expected_action_digest": digest},
        )
        services = cast(FastAPI, third_client.app).state.services

        assert replay.status_code == 200
        assert replay.json()["task_id"] == task_id
        assert replay.json()["idempotent_replay"] is True
        assert services.actions.get_proposal(proposal_id).status is ProposalStatus.EXECUTED
        assert services.state.verify_integrity()
        assert services.audit.verify()

    with third_store.transaction() as transaction:
        receipt = transaction.get_approval(proposal_id)
        execution = transaction.get_execution(proposal_id)
    assert receipt is not None
    assert execution is not None

    substituted_receipt = receipt.model_copy(update={"approval_id": "APR-substituted"})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE approval_receipts SET document_json = ? WHERE proposal_id = ?",
            (substituted_receipt.model_dump_json(), proposal_id),
        )
    assert third_store.verify_integrity() is False
    with third_store.transaction() as transaction, pytest.raises(StateIntegrityError):
        transaction.get_approval(proposal_id)
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE approval_receipts SET document_json = ? WHERE proposal_id = ?",
            (receipt.model_dump_json(), proposal_id),
        )

    substituted_execution = execution.model_copy(update={"task_id": "TASK-substituted"})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE action_executions SET document_json = ? WHERE proposal_id = ?",
            (substituted_execution.model_dump_json(), proposal_id),
        )
    assert third_store.verify_integrity() is False
    with third_store.transaction() as transaction, pytest.raises(StateIntegrityError):
        transaction.get_execution(proposal_id)
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE action_executions SET document_json = ? WHERE proposal_id = ?",
            (execution.model_dump_json(), proposal_id),
        )

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("DELETE FROM action_proposals WHERE proposal_id = ?", (proposal_id,))
    assert third_store.verify_integrity() is False


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_nested_transaction_failure_rolls_back_state_and_audit_together(
    store_kind: str,
    tmp_path: Path,
) -> None:
    state = _state_store(store_kind, tmp_path)
    audit = AuditLedger("synthetic-audit-key-with-sufficient-entropy", state=state)
    proposal = _proposal_fixture("PRP-rollback-test")

    with pytest.raises(StateStoreUnavailable), state.transaction():
        try:
            with state.transaction() as nested:
                nested.save_proposal(proposal)
                audit.append(
                    actor="user-care-1",
                    event_type="action.propose",
                    outcome="ACTION_PROPOSAL_ALLOWED",
                    correlation_id="req-rollback-1",
                )
                raise RuntimeError("simulated mid-transaction failure")
        except RuntimeError:
            pass

    with state.transaction() as transaction:
        assert transaction.get_proposal(proposal.proposal_id) is None
        assert transaction.audit_events() == ()


def test_concurrent_sqlite_execution_creates_one_task_and_one_replay(
    tmp_path: Path,
    settings: Settings,
    headers: Callable[..., dict[str, str]],
) -> None:
    state = SqliteStateStore(tmp_path / "concurrent-state.db")
    with TestClient(create_app(settings, state_store=state)) as client:
        proposal = _propose(client, headers)
        proposal_id = str(proposal["proposal_id"])
        digest = str(proposal["action_digest"])
        approval = client.post(
            f"/v1/actions/proposals/{proposal_id}/decision",
            headers=headers(subject="approver-1", roles=["task_approver"]),
            json={"decision": "APPROVE", "expected_action_digest": digest, "comment": ""},
        )
        assert approval.status_code == 200
        services = cast(FastAPI, client.app).state.services
        barrier = Barrier(2)

        def execute(index: int) -> tuple[str, bool]:
            barrier.wait()
            result = services.actions.execute(
                proposal_id=proposal_id,
                executor=_executor(index),
                purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
                expected_action_digest=digest,
                correlation_id=f"req-concurrent-{index}",
            )
            return result.task_id, result.idempotent_replay

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(execute, (1, 2)))

        assert len({task_id for task_id, _ in results}) == 1
        assert sorted(replayed for _, replayed in results) == [False, True]
        outcomes = [
            event.outcome
            for event in services.audit.snapshot()
            if event.event_type == "action.execute"
        ]
        assert outcomes.count("ACTION_EXECUTED") == 1
        assert outcomes.count("ACTION_IDEMPOTENT_REPLAY") == 1
        assert services.audit.verify()


def test_sqlite_audit_tamper_and_invalid_state_make_readiness_fail_closed(
    tmp_path: Path,
    settings: Settings,
) -> None:
    database_path = tmp_path / "tamper-state.db"
    state = SqliteStateStore(database_path)
    audit = AuditLedger(settings.audit_hmac_key, state=state)
    audit.append(
        actor="security-analyst-1",
        event_type="audit.verify",
        outcome="AUDIT_READ_ALLOWED",
        correlation_id="req-tamper-1",
    )
    event = audit.snapshot()[0]
    tampered = event.model_copy(update={"outcome": "TAMPERED"})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE audit_events SET document_json = ? WHERE sequence = 1",
            (tampered.model_dump_json(),),
        )

    assert audit.verify() is False
    with TestClient(create_app(settings, state_store=state)) as client:
        response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "not-ready"}

    proposal = _proposal_fixture("PRP-key-binding")
    with state.transaction() as transaction:
        transaction.save_proposal(proposal)
    substituted = proposal.model_copy(update={"proposal_id": "PRP-substituted"})
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE action_proposals SET document_json = ? WHERE proposal_id = ?",
            (substituted.model_dump_json(), proposal.proposal_id),
        )
    assert state.verify_integrity() is False
    with state.transaction() as transaction, pytest.raises(StateIntegrityError):
        transaction.get_proposal(proposal.proposal_id)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "UPDATE action_proposals SET document_json = ? WHERE proposal_id = ?",
            (proposal.model_dump_json(), proposal.proposal_id),
        )
    assert state.verify_integrity()

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            "INSERT INTO action_proposals (proposal_id, document_json) VALUES (?, ?)",
            ("PRP-corrupt-record", "not-json"),
        )
    assert state.verify_integrity() is False
    with state.transaction() as transaction, pytest.raises(StateIntegrityError):
        transaction.get_proposal("PRP-corrupt-record")


def test_sqlite_schema_version_and_path_validation_fail_closed(tmp_path: Path) -> None:
    database_path = tmp_path / "schema-state.db"
    state = SqliteStateStore(database_path)
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '1' WHERE key = 'schema_version'")
    migrated = SqliteStateStore(database_path)
    assert migrated.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '2' WHERE key = 'schema_version'")
    migrated_v2 = SqliteStateStore(database_path)
    assert migrated_v2.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '3' WHERE key = 'schema_version'")
    migrated_v3 = SqliteStateStore(database_path)
    assert migrated_v3.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '4' WHERE key = 'schema_version'")
    migrated_v4 = SqliteStateStore(database_path)
    assert migrated_v4.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '5' WHERE key = 'schema_version'")
    migrated_v5 = SqliteStateStore(database_path)
    assert migrated_v5.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '6' WHERE key = 'schema_version'")
    migrated_v6 = SqliteStateStore(database_path)
    assert migrated_v6.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("DROP TABLE identity_stream_recovery_schedules")
        connection.execute("UPDATE schema_metadata SET value = '7' WHERE key = 'schema_version'")
    migrated_v7 = SqliteStateStore(database_path)
    assert migrated_v7.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("DROP TABLE identity_gap_recovered_events")
        connection.execute("DROP TABLE identity_gap_recovery_states")
        connection.execute("UPDATE schema_metadata SET value = '8' WHERE key = 'schema_version'")
    migrated_v8 = SqliteStateStore(database_path)
    assert migrated_v8.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        subject_columns = {
            column[1] for column in connection.execute("PRAGMA table_info(identity_subject_states)")
        }
    assert version == ("10",)
    assert "recovered_event_id" in subject_columns

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("DROP TABLE corpus_activations")
        connection.execute("UPDATE schema_metadata SET value = '9' WHERE key = 'schema_version'")
    migrated_v9 = SqliteStateStore(database_path)
    assert migrated_v9.verify_integrity()
    with closing(sqlite3.connect(database_path)) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
    assert version == ("10",)

    legacy_path = tmp_path / "legacy-v2-state.db"
    SqliteStateStore(legacy_path)
    legacy_signal = {
        "event_id": "set-legacy-without-transport-context",
        "issuer": "https://identity.northstar.example.test",
        "audience": "polaris-identity-signals",
        "event_type": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "target": "SUBJECT",
        "subject": "user-care-1",
        "token_id": None,
        "event_time": "2026-08-11T12:00:00Z",
        "received_at": "2026-08-11T12:00:01Z",
        "payload_hash": "a" * 64,
    }
    with closing(sqlite3.connect(legacy_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '2' WHERE key = 'schema_version'")
        connection.execute(
            "INSERT INTO identity_signals (event_id, payload_hash, document_json) VALUES (?, ?, ?)",
            (
                legacy_signal["event_id"],
                legacy_signal["payload_hash"],
                json.dumps(legacy_signal),
            ),
        )
    with pytest.raises(StateIntegrityError):
        SqliteStateStore(legacy_path)

    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute("UPDATE schema_metadata SET value = '999' WHERE key = 'schema_version'")

    assert state.verify_integrity() is False
    with pytest.raises(StateIntegrityError):
        SqliteStateStore(database_path)
    with pytest.raises(ValueError):
        SqliteStateStore("relative-state.db")
    with pytest.raises(ValueError):
        SqliteStateStore(tmp_path)
    with pytest.raises(ValueError):
        SqliteStateStore(tmp_path / "missing" / "state.db")


def _propose(
    client: TestClient,
    headers: Callable[..., dict[str, str]],
) -> dict[str, object]:
    response = client.post(
        "/v1/actions/proposals",
        headers=headers(),
        json={"action": _action_payload()},
    )
    assert response.status_code == 201
    return cast(dict[str, object], response.json())


def _action_payload() -> dict[str, object]:
    return {
        "action_type": "administrative_follow_up",
        "patient_id": "SYN-P1001",
        "facility_id": "FAC-NORTH",
        "queue": "care_coordination",
        "due_date": "2026-08-20",
        "summary": "Confirm availability for routine follow-up",
    }


def _proposal_fixture(proposal_id: str) -> ActionProposal:
    now = datetime(2026, 8, 11, 12, tzinfo=UTC)
    action = FollowUpAction(
        patient_id="SYN-P1001",
        facility_id="FAC-NORTH",
        due_date=date(2026, 8, 20),
        summary="Confirm availability for routine follow-up",
    )
    return ActionProposal(
        proposal_id=proposal_id,
        action=action,
        action_digest=action_digest(action),
        requester=Principal(
            subject="user-care-1",
            token_id="tok-state-1",
            client_id="polaris-web",
            scopes=frozenset({"polaris.task.propose"}),
            roles=frozenset({"care_coordinator"}),
            facilities=frozenset({"FAC-NORTH"}),
            assigned_patients=frozenset({"SYN-P1001"}),
        ),
        purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
        status=ProposalStatus.PENDING,
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _executor(index: int) -> Principal:
    return Principal(
        subject=f"executor-{index}",
        token_id=f"tok-executor-{index}",
        client_id="polaris-web",
        scopes=frozenset({"polaris.task.execute"}),
        roles=frozenset({"task_executor"}),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset(),
    )


def _state_store(store_kind: str, tmp_path: Path) -> PolarisStateStore:
    if store_kind == "memory":
        return InMemoryStateStore()
    return SqliteStateStore(tmp_path / "rollback-state.db")

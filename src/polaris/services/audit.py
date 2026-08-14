from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime

from polaris.domain import AuditEvent
from polaris.services.state import InMemoryStateStore, PolarisStateStore


def utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLedger:
    """HMAC hash chain persisted through the injected transactional state boundary."""

    def __init__(
        self,
        key: str,
        clock: Callable[[], datetime] = utc_now,
        *,
        state: PolarisStateStore | None = None,
    ) -> None:
        self._key = key.encode()
        self._clock = clock
        self._state = state or InMemoryStateStore()

    @property
    def state_store(self) -> PolarisStateStore:
        return self._state

    def append(
        self,
        *,
        actor: str,
        event_type: str,
        outcome: str,
        correlation_id: str,
        metadata: Mapping[str, str] | None = None,
    ) -> AuditEvent:
        with self._state.transaction() as transaction:
            previous = transaction.last_audit_event()
            previous_hash = previous.event_hash if previous is not None else "GENESIS"
            sequence = previous.sequence + 1 if previous is not None else 1
            occurred_at = self._clock()
            metadata_values = dict(sorted((metadata or {}).items()))
            payload: dict[str, object] = {
                "sequence": sequence,
                "occurred_at": occurred_at.isoformat(),
                "actor": actor,
                "event_type": event_type,
                "outcome": outcome,
                "correlation_id": correlation_id,
                "metadata": metadata_values,
                "previous_hash": previous_hash,
            }
            event_hash = self._sign(payload)
            event = AuditEvent(
                sequence=sequence,
                occurred_at=occurred_at,
                actor=actor,
                event_type=event_type,
                outcome=outcome,
                correlation_id=correlation_id,
                metadata=metadata_values,
                previous_hash=previous_hash,
                event_hash=event_hash,
            )
            transaction.append_audit_event(event)
            return event.model_copy(deep=True)

    def snapshot(self) -> tuple[AuditEvent, ...]:
        with self._state.transaction() as transaction:
            return transaction.audit_events()

    def verify(self, events: Iterable[AuditEvent] | None = None) -> bool:
        candidate = list(events) if events is not None else list(self.snapshot())
        previous_hash = "GENESIS"
        for expected_sequence, event in enumerate(candidate, start=1):
            if event.sequence != expected_sequence or event.previous_hash != previous_hash:
                return False
            payload = {
                "sequence": event.sequence,
                "occurred_at": event.occurred_at.isoformat(),
                "actor": event.actor,
                "event_type": event.event_type,
                "outcome": event.outcome,
                "correlation_id": event.correlation_id,
                "metadata": dict(sorted(event.metadata.items())),
                "previous_hash": event.previous_hash,
            }
            if not hmac.compare_digest(event.event_hash, self._sign(payload)):
                return False
            previous_hash = event.event_hash
        return True

    def _sign(self, payload: Mapping[str, object]) -> str:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        return hmac.new(self._key, canonical, hashlib.sha256).hexdigest()

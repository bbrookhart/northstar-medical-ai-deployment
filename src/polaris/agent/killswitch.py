from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from polaris.domain import AgentCapability, AgentCapabilityState
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.state import PolarisStateStore


class CapabilityDisabled(RuntimeError):
    """A capability was switched off. The run stops; it does not fall back to another path."""

    def __init__(self, capability: AgentCapability) -> None:
        super().__init__("Agent capability is disabled")
        self.capability = capability


class AgentKillSwitch:
    """Independent, durable on/off state for each agent capability.

    Independence is the point: disabling writes must not disable reads, and disabling the model must
    not disable the deterministic retrieval path clinicians still depend on. State is persisted and
    monotonically sequenced, so a restart cannot silently re-enable a capability an operator killed
    and a stale writer cannot roll one back on.

    Capabilities default to enabled when no record exists, which is the correct default for a local
    simulation with no operator. A deployment would invert that and require explicit enablement.
    """

    def __init__(
        self,
        *,
        state: PolarisStateStore,
        audit: AuditLedger,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if audit.state_store is not state:
            raise ValueError("Kill switch and audit must share one transactional state store")
        self._state = state
        self._audit = audit
        self._clock = clock

    def is_enabled(self, capability: AgentCapability) -> bool:
        with self._state.transaction() as transaction:
            record = transaction.get_agent_capability_state(capability)
        return True if record is None else record.enabled

    def assert_enabled(self, capability: AgentCapability) -> None:
        if not self.is_enabled(capability):
            raise CapabilityDisabled(capability)

    def set_enabled(
        self,
        capability: AgentCapability,
        *,
        enabled: bool,
        changed_by: str,
        reason: str,
        correlation_id: str,
    ) -> AgentCapabilityState:
        with self._state.transaction() as transaction:
            current = transaction.get_agent_capability_state(capability)
            if current is not None and current.enabled == enabled:
                raise ValueError("Capability is already in the requested state")
            record = AgentCapabilityState(
                capability=capability,
                enabled=enabled,
                sequence=1 if current is None else current.sequence + 1,
                changed_at=self._clock(),
                changed_by=changed_by,
                reason=reason,
            )
            transaction.save_agent_capability_state(record)
            self._audit.append(
                actor=changed_by,
                event_type="agent.capability",
                outcome="AGENT_CAPABILITY_ENABLED" if enabled else "AGENT_CAPABILITY_DISABLED",
                correlation_id=correlation_id,
                metadata={
                    "capability": capability.value,
                    "sequence": str(record.sequence),
                    "reason": reason,
                },
            )
        return record

    def snapshot(self) -> dict[AgentCapability, bool]:
        with self._state.transaction() as transaction:
            records = {
                capability: transaction.get_agent_capability_state(capability)
                for capability in AgentCapability
            }
        return {
            capability: True if record is None else record.enabled
            for capability, record in records.items()
        }

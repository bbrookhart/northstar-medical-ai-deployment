from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from pathlib import Path
from threading import RLock, local
from typing import Protocol

from pydantic import BaseModel, ValidationError

from polaris.domain import (
    ActionExecutionResult,
    ActionProposal,
    ApprovalReceipt,
    AuditEvent,
    CorpusActivation,
    IdentityGapIncidentStatus,
    IdentityGapRecoveredEvent,
    IdentityGapRecoveryState,
    IdentitySignalRecord,
    IdentitySignalType,
    IdentityStreamCheckpoint,
    IdentityStreamObservedState,
    IdentityStreamRecoverySchedule,
    IdentityStreamStatusOperation,
    IdentityStreamStatusOperationStatus,
    IdentityStreamStatusReconciliation,
    IdentityStreamStatusReconciliationStatus,
    IdentityStreamUnsolicitedVerificationState,
    IdentityStreamVerification,
    IdentityStreamVerificationStatus,
    IdentitySubjectState,
    IdentityTokenRevocation,
)
from polaris.errors import DependencyUnavailableError

_SCHEMA_VERSION = "10"

# Schema 9 gives every subject invalidation an attributable source, so a signed SET and a
# compensating provider-log record can never be mistaken for each other. Databases written before
# 9 carry signal-attributed rows only and are rebuilt in place.
_SUBJECT_STATE_REBUILD_SQL = """
    BEGIN IMMEDIATE;
    ALTER TABLE identity_subject_states RENAME TO identity_subject_states_pre9;
    CREATE TABLE identity_subject_states (
        subject TEXT PRIMARY KEY,
        signal_id TEXT REFERENCES identity_signals(event_id),
        recovered_event_id TEXT
            REFERENCES identity_gap_recovered_events(provider_event_id),
        document_json TEXT NOT NULL,
        CHECK (
            (signal_id IS NOT NULL AND recovered_event_id IS NULL)
            OR (signal_id IS NULL AND recovered_event_id IS NOT NULL)
        )
    ) STRICT;
    INSERT INTO identity_subject_states (
        subject, signal_id, recovered_event_id, document_json
    )
    SELECT subject, signal_id, NULL, document_json FROM identity_subject_states_pre9;
    DROP TABLE identity_subject_states_pre9;
    COMMIT;
"""


class StateStoreUnavailable(DependencyUnavailableError):
    def __init__(self) -> None:
        super().__init__("STATE_STORE_UNAVAILABLE")


class StateIntegrityError(DependencyUnavailableError):
    def __init__(self) -> None:
        super().__init__("STATE_INTEGRITY_FAILURE")


class StateTransaction(Protocol):
    def get_proposal(self, proposal_id: str) -> ActionProposal | None: ...

    def save_proposal(self, proposal: ActionProposal) -> None: ...

    def get_approval(self, proposal_id: str) -> ApprovalReceipt | None: ...

    def save_approval(self, receipt: ApprovalReceipt) -> None: ...

    def get_execution(self, proposal_id: str) -> ActionExecutionResult | None: ...

    def save_execution(self, result: ActionExecutionResult) -> None: ...

    def last_audit_event(self) -> AuditEvent | None: ...

    def audit_events(self) -> tuple[AuditEvent, ...]: ...

    def append_audit_event(self, event: AuditEvent) -> None: ...

    def get_identity_signal(self, event_id: str) -> IdentitySignalRecord | None: ...

    def save_identity_signal(self, signal: IdentitySignalRecord) -> None: ...

    def get_identity_subject_state(self, subject: str) -> IdentitySubjectState | None: ...

    def save_identity_subject_state(self, state: IdentitySubjectState) -> None: ...

    def get_identity_token_revocation(self, token_id: str) -> IdentityTokenRevocation | None: ...

    def save_identity_token_revocation(self, revocation: IdentityTokenRevocation) -> None: ...

    def get_identity_stream_checkpoint(self, stream_id: str) -> IdentityStreamCheckpoint | None: ...

    def save_identity_stream_checkpoint(self, checkpoint: IdentityStreamCheckpoint) -> None: ...

    def get_identity_stream_unsolicited_verification_state(
        self,
        stream_id: str,
    ) -> IdentityStreamUnsolicitedVerificationState | None: ...

    def save_identity_stream_unsolicited_verification_state(
        self,
        state: IdentityStreamUnsolicitedVerificationState,
    ) -> None: ...

    def get_identity_stream_verification(
        self,
        verification_id: str,
    ) -> IdentityStreamVerification | None: ...

    def get_identity_stream_verification_by_state(
        self,
        stream_id: str,
        state_hash: str,
    ) -> IdentityStreamVerification | None: ...

    def latest_identity_stream_verification(
        self,
        stream_id: str,
    ) -> IdentityStreamVerification | None: ...

    def latest_verified_identity_stream_verification(
        self,
        stream_id: str,
    ) -> IdentityStreamVerification | None: ...

    def save_identity_stream_verification(
        self,
        verification: IdentityStreamVerification,
    ) -> None: ...

    def get_identity_stream_status_operation(
        self,
        operation_id: str,
    ) -> IdentityStreamStatusOperation | None: ...

    def latest_identity_stream_status_operation(
        self,
        stream_id: str,
    ) -> IdentityStreamStatusOperation | None: ...

    def save_identity_stream_status_operation(
        self,
        operation: IdentityStreamStatusOperation,
    ) -> None: ...

    def get_identity_stream_status_reconciliation(
        self,
        reconciliation_id: str,
    ) -> IdentityStreamStatusReconciliation | None: ...

    def save_identity_stream_status_reconciliation(
        self,
        reconciliation: IdentityStreamStatusReconciliation,
    ) -> None: ...

    def get_identity_stream_recovery_schedule(
        self,
        stream_id: str,
    ) -> IdentityStreamRecoverySchedule | None: ...

    def save_identity_stream_recovery_schedule(
        self,
        schedule: IdentityStreamRecoverySchedule,
    ) -> None: ...

    def get_identity_stream_observed_state(
        self,
        stream_id: str,
    ) -> IdentityStreamObservedState | None: ...

    def save_identity_stream_observed_state(
        self,
        state: IdentityStreamObservedState,
    ) -> None: ...

    def get_identity_gap_recovery_state(
        self,
        incident_id: str,
    ) -> IdentityGapRecoveryState | None: ...

    def active_identity_gap_recovery_state(
        self,
        stream_id: str,
    ) -> IdentityGapRecoveryState | None: ...

    def save_identity_gap_recovery_state(
        self,
        state: IdentityGapRecoveryState,
    ) -> None: ...

    def get_identity_gap_recovered_event(
        self,
        provider_event_id: str,
    ) -> IdentityGapRecoveredEvent | None: ...

    def save_identity_gap_recovered_event(
        self,
        event: IdentityGapRecoveredEvent,
    ) -> None: ...

    def latest_corpus_activation(self, corpus_id: str) -> CorpusActivation | None: ...

    def save_corpus_activation(self, activation: CorpusActivation) -> None: ...


class PolarisStateStore(Protocol):
    def transaction(self) -> AbstractContextManager[StateTransaction]: ...

    def verify_integrity(self) -> bool: ...


class _MemoryTransaction:
    def __init__(
        self,
        *,
        proposals: dict[str, ActionProposal],
        approvals: dict[str, ApprovalReceipt],
        executions: dict[str, ActionExecutionResult],
        events: list[AuditEvent],
        identity_signals: dict[str, IdentitySignalRecord],
        identity_subject_states: dict[str, IdentitySubjectState],
        identity_token_revocations: dict[str, IdentityTokenRevocation],
        identity_stream_checkpoints: dict[str, IdentityStreamCheckpoint],
        identity_stream_unsolicited_verification_states: dict[
            str, IdentityStreamUnsolicitedVerificationState
        ],
        identity_stream_verifications: dict[str, IdentityStreamVerification],
        identity_stream_status_operations: dict[str, IdentityStreamStatusOperation],
        identity_stream_status_reconciliations: dict[str, IdentityStreamStatusReconciliation],
        identity_stream_recovery_schedules: dict[str, IdentityStreamRecoverySchedule],
        identity_stream_observed_states: dict[str, IdentityStreamObservedState],
        identity_gap_recovery_states: dict[str, IdentityGapRecoveryState],
        identity_gap_recovered_events: dict[str, IdentityGapRecoveredEvent],
        corpus_activations: list[CorpusActivation],
    ) -> None:
        self.proposals = proposals
        self.approvals = approvals
        self.executions = executions
        self.events = events
        self.identity_signals = identity_signals
        self.identity_subject_states = identity_subject_states
        self.identity_token_revocations = identity_token_revocations
        self.identity_stream_checkpoints = identity_stream_checkpoints
        self.identity_stream_unsolicited_verification_states = (
            identity_stream_unsolicited_verification_states
        )
        self.identity_stream_verifications = identity_stream_verifications
        self.identity_stream_status_operations = identity_stream_status_operations
        self.identity_stream_status_reconciliations = identity_stream_status_reconciliations
        self.identity_stream_recovery_schedules = identity_stream_recovery_schedules
        self.identity_stream_observed_states = identity_stream_observed_states
        self.identity_gap_recovery_states = identity_gap_recovery_states
        self.identity_gap_recovered_events = identity_gap_recovered_events
        self.corpus_activations = corpus_activations
        self.rollback_only = False

    def get_proposal(self, proposal_id: str) -> ActionProposal | None:
        value = self.proposals.get(proposal_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_proposal(self, proposal: ActionProposal) -> None:
        self.proposals[proposal.proposal_id] = proposal.model_copy(deep=True)

    def get_approval(self, proposal_id: str) -> ApprovalReceipt | None:
        value = self.approvals.get(proposal_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_approval(self, receipt: ApprovalReceipt) -> None:
        if receipt.proposal_id not in self.proposals:
            raise StateIntegrityError
        if any(
            candidate.approval_id == receipt.approval_id
            and candidate.proposal_id != receipt.proposal_id
            for candidate in self.approvals.values()
        ):
            raise StateIntegrityError
        self.approvals[receipt.proposal_id] = receipt.model_copy(deep=True)

    def get_execution(self, proposal_id: str) -> ActionExecutionResult | None:
        value = self.executions.get(proposal_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_execution(self, result: ActionExecutionResult) -> None:
        if result.proposal_id not in self.proposals or result.proposal_id in self.executions:
            raise StateIntegrityError
        if any(
            candidate.execution_id == result.execution_id or candidate.task_id == result.task_id
            for candidate in self.executions.values()
        ):
            raise StateIntegrityError
        self.executions[result.proposal_id] = result.model_copy(deep=True)

    def last_audit_event(self) -> AuditEvent | None:
        return self.events[-1].model_copy(deep=True) if self.events else None

    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(event.model_copy(deep=True) for event in self.events)

    def append_audit_event(self, event: AuditEvent) -> None:
        previous = self.events[-1] if self.events else None
        expected_sequence = previous.sequence + 1 if previous is not None else 1
        expected_hash = previous.event_hash if previous is not None else "GENESIS"
        if event.sequence != expected_sequence or event.previous_hash != expected_hash:
            raise StateIntegrityError
        if any(candidate.event_hash == event.event_hash for candidate in self.events):
            raise StateIntegrityError
        self.events.append(event.model_copy(deep=True))

    def get_identity_signal(self, event_id: str) -> IdentitySignalRecord | None:
        value = self.identity_signals.get(event_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_signal(self, signal: IdentitySignalRecord) -> None:
        existing = self.identity_signals.get(signal.event_id)
        if existing is not None and existing != signal:
            raise StateIntegrityError
        if any(
            candidate.payload_hash == signal.payload_hash and candidate.event_id != signal.event_id
            for candidate in self.identity_signals.values()
        ):
            raise StateIntegrityError
        self.identity_signals[signal.event_id] = signal.model_copy(deep=True)

    def get_identity_subject_state(self, subject: str) -> IdentitySubjectState | None:
        value = self.identity_subject_states.get(subject)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_subject_state(self, state: IdentitySubjectState) -> None:
        source_known = (
            state.signal_id in self.identity_signals
            if state.signal_id is not None
            else state.recovered_event_id in self.identity_gap_recovered_events
        )
        if not source_known:
            raise StateIntegrityError
        self.identity_subject_states[state.subject] = state.model_copy(deep=True)

    def get_identity_token_revocation(self, token_id: str) -> IdentityTokenRevocation | None:
        value = self.identity_token_revocations.get(token_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_token_revocation(self, revocation: IdentityTokenRevocation) -> None:
        if revocation.signal_id not in self.identity_signals:
            raise StateIntegrityError
        self.identity_token_revocations[revocation.token_id] = revocation.model_copy(deep=True)

    def get_identity_stream_checkpoint(self, stream_id: str) -> IdentityStreamCheckpoint | None:
        value = self.identity_stream_checkpoints.get(stream_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_stream_checkpoint(self, checkpoint: IdentityStreamCheckpoint) -> None:
        self.identity_stream_checkpoints[checkpoint.stream_id] = checkpoint.model_copy(deep=True)

    def get_identity_stream_unsolicited_verification_state(
        self,
        stream_id: str,
    ) -> IdentityStreamUnsolicitedVerificationState | None:
        value = self.identity_stream_unsolicited_verification_states.get(stream_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_stream_unsolicited_verification_state(
        self,
        state: IdentityStreamUnsolicitedVerificationState,
    ) -> None:
        existing = self.identity_stream_unsolicited_verification_states.get(state.stream_id)
        _validate_unsolicited_verification_transition(existing, state)
        self._validate_unsolicited_verification_signal(state)
        self.identity_stream_unsolicited_verification_states[state.stream_id] = state.model_copy(
            deep=True
        )

    def _validate_unsolicited_verification_signal(
        self,
        state: IdentityStreamUnsolicitedVerificationState,
    ) -> None:
        signal = self.identity_signals.get(state.last_signal_id)
        if (
            signal is None
            or signal.stream_id != state.stream_id
            or signal.event_type is not IdentitySignalType.STREAM_VERIFICATION
            or signal.verification_state_hash is not None
            or signal.received_at != state.last_received_at
        ):
            raise StateIntegrityError

    def get_identity_stream_verification(
        self,
        verification_id: str,
    ) -> IdentityStreamVerification | None:
        value = self.identity_stream_verifications.get(verification_id)
        return value.model_copy(deep=True) if value is not None else None

    def get_identity_stream_verification_by_state(
        self,
        stream_id: str,
        state_hash: str,
    ) -> IdentityStreamVerification | None:
        for verification in self.identity_stream_verifications.values():
            if verification.stream_id == stream_id and verification.state_hash == state_hash:
                return verification.model_copy(deep=True)
        return None

    def latest_identity_stream_verification(
        self,
        stream_id: str,
    ) -> IdentityStreamVerification | None:
        matches = [
            verification
            for verification in self.identity_stream_verifications.values()
            if verification.stream_id == stream_id
        ]
        if not matches:
            return None
        latest = matches[-1]
        return latest.model_copy(deep=True)

    def latest_verified_identity_stream_verification(
        self,
        stream_id: str,
    ) -> IdentityStreamVerification | None:
        matches = [
            verification
            for verification in self.identity_stream_verifications.values()
            if verification.stream_id == stream_id
            and verification.status is IdentityStreamVerificationStatus.VERIFIED
        ]
        if not matches:
            return None
        latest = max(
            reversed(matches),
            key=lambda value: value.completed_at or value.requested_at,
        )
        return latest.model_copy(deep=True)

    def save_identity_stream_verification(
        self,
        verification: IdentityStreamVerification,
    ) -> None:
        existing = self.identity_stream_verifications.get(verification.verification_id)
        if existing is not None and (
            existing.stream_id != verification.stream_id
            or existing.state_hash != verification.state_hash
            or existing.requested_at != verification.requested_at
        ):
            raise StateIntegrityError
        if any(
            candidate.state_hash == verification.state_hash
            and candidate.verification_id != verification.verification_id
            for candidate in self.identity_stream_verifications.values()
        ):
            raise StateIntegrityError
        if (
            verification.signal_id is not None
            and verification.signal_id not in self.identity_signals
        ):
            raise StateIntegrityError
        self.identity_stream_verifications[verification.verification_id] = verification.model_copy(
            deep=True
        )

    def get_identity_stream_status_operation(
        self,
        operation_id: str,
    ) -> IdentityStreamStatusOperation | None:
        value = self.identity_stream_status_operations.get(operation_id)
        return value.model_copy(deep=True) if value is not None else None

    def latest_identity_stream_status_operation(
        self,
        stream_id: str,
    ) -> IdentityStreamStatusOperation | None:
        matches = [
            operation
            for operation in self.identity_stream_status_operations.values()
            if operation.stream_id == stream_id
        ]
        return matches[-1].model_copy(deep=True) if matches else None

    def save_identity_stream_status_operation(
        self,
        operation: IdentityStreamStatusOperation,
    ) -> None:
        existing = self.identity_stream_status_operations.get(operation.operation_id)
        _validate_status_operation_transition(existing, operation)
        self.identity_stream_status_operations[operation.operation_id] = operation.model_copy(
            deep=True
        )

    def get_identity_stream_status_reconciliation(
        self,
        reconciliation_id: str,
    ) -> IdentityStreamStatusReconciliation | None:
        value = self.identity_stream_status_reconciliations.get(reconciliation_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_stream_status_reconciliation(
        self,
        reconciliation: IdentityStreamStatusReconciliation,
    ) -> None:
        operation = self.identity_stream_status_operations.get(reconciliation.operation_id)
        if operation is None or operation.stream_id != reconciliation.stream_id:
            raise StateIntegrityError
        existing = self.identity_stream_status_reconciliations.get(reconciliation.reconciliation_id)
        _validate_status_reconciliation_transition(existing, reconciliation)
        self.identity_stream_status_reconciliations[reconciliation.reconciliation_id] = (
            reconciliation.model_copy(deep=True)
        )

    def get_identity_stream_recovery_schedule(
        self,
        stream_id: str,
    ) -> IdentityStreamRecoverySchedule | None:
        value = self.identity_stream_recovery_schedules.get(stream_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_stream_recovery_schedule(
        self,
        schedule: IdentityStreamRecoverySchedule,
    ) -> None:
        existing = self.identity_stream_recovery_schedules.get(schedule.stream_id)
        _validate_recovery_schedule_transition(existing, schedule)
        self._validate_recovery_schedule_reconciliation(schedule)
        self.identity_stream_recovery_schedules[schedule.stream_id] = schedule.model_copy(deep=True)

    def _validate_recovery_schedule_reconciliation(
        self,
        schedule: IdentityStreamRecoverySchedule,
    ) -> None:
        if schedule.last_reconciliation_id is None:
            return
        reconciliation = self.identity_stream_status_reconciliations.get(
            schedule.last_reconciliation_id
        )
        if (
            reconciliation is None
            or reconciliation.stream_id != schedule.stream_id
            or reconciliation.status is IdentityStreamStatusReconciliationStatus.REQUESTING
        ):
            raise StateIntegrityError

    def get_identity_stream_observed_state(
        self,
        stream_id: str,
    ) -> IdentityStreamObservedState | None:
        value = self.identity_stream_observed_states.get(stream_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_stream_observed_state(
        self,
        state: IdentityStreamObservedState,
    ) -> None:
        self._validate_observed_source(state)
        self.identity_stream_observed_states[state.stream_id] = state.model_copy(deep=True)

    def get_identity_gap_recovery_state(
        self,
        incident_id: str,
    ) -> IdentityGapRecoveryState | None:
        value = self.identity_gap_recovery_states.get(incident_id)
        return value.model_copy(deep=True) if value is not None else None

    def active_identity_gap_recovery_state(
        self,
        stream_id: str,
    ) -> IdentityGapRecoveryState | None:
        candidates = [
            state
            for state in self.identity_gap_recovery_states.values()
            if state.stream_id == stream_id and state.closed_at is None
        ]
        if not candidates:
            return None
        if len(candidates) > 1:
            raise StateIntegrityError
        return candidates[0].model_copy(deep=True)

    def save_identity_gap_recovery_state(self, state: IdentityGapRecoveryState) -> None:
        existing = self.identity_gap_recovery_states.get(state.incident_id)
        _validate_gap_recovery_transition(existing, state)
        if existing is None and any(
            other.stream_id == state.stream_id and other.closed_at is None
            for other in self.identity_gap_recovery_states.values()
        ):
            raise StateIntegrityError
        self.identity_gap_recovery_states[state.incident_id] = state.model_copy(deep=True)

    def get_identity_gap_recovered_event(
        self,
        provider_event_id: str,
    ) -> IdentityGapRecoveredEvent | None:
        value = self.identity_gap_recovered_events.get(provider_event_id)
        return value.model_copy(deep=True) if value is not None else None

    def save_identity_gap_recovered_event(self, event: IdentityGapRecoveredEvent) -> None:
        if event.provider_event_id in self.identity_gap_recovered_events:
            raise StateIntegrityError
        self._validate_gap_recovered_event(event)
        self.identity_gap_recovered_events[event.provider_event_id] = event.model_copy(deep=True)

    def _validate_gap_recovered_event(self, event: IdentityGapRecoveredEvent) -> None:
        incident = self.identity_gap_recovery_states.get(event.incident_id)
        if incident is None or incident.stream_id != event.stream_id:
            raise StateIntegrityError

    def latest_corpus_activation(self, corpus_id: str) -> CorpusActivation | None:
        matches = [
            activation
            for activation in self.corpus_activations
            if activation.corpus_id == corpus_id
        ]
        return matches[-1].model_copy(deep=True) if matches else None

    def save_corpus_activation(self, activation: CorpusActivation) -> None:
        existing = self.latest_corpus_activation(activation.corpus_id)
        _validate_corpus_activation_transition(existing, activation)
        self.corpus_activations.append(activation.model_copy(deep=True))

    def _validate_observed_source(self, state: IdentityStreamObservedState) -> None:
        if state.signal_id is not None:
            signal = self.identity_signals.get(state.signal_id)
            if (
                signal is None
                or signal.stream_id != state.stream_id
                or signal.stream_status is not state.status
                or signal.stream_status_reason_hash != state.reason_hash
            ):
                raise StateIntegrityError
            return
        if state.reconciliation_id is not None:
            reconciliation = self.identity_stream_status_reconciliations.get(
                state.reconciliation_id
            )
            if (
                reconciliation is None
                or reconciliation.stream_id != state.stream_id
                or reconciliation.status is not IdentityStreamStatusReconciliationStatus.OBSERVED
                or reconciliation.observed_status is not state.status
                or reconciliation.observed_reason_hash != state.reason_hash
            ):
                raise StateIntegrityError
            return
        operation = self.identity_stream_status_operations.get(state.operation_id or "")
        if (
            operation is None
            or operation.stream_id != state.stream_id
            or operation.desired_status is not state.status
            or operation.reason_hash != state.reason_hash
            or operation.status is not IdentityStreamStatusOperationStatus.CONFIRMED
        ):
            raise StateIntegrityError

    def verify_integrity(self) -> bool:
        for proposal_id, proposal in self.proposals.items():
            ActionProposal.model_validate(proposal.model_dump())
            if proposal.proposal_id != proposal_id:
                return False
        for proposal_id, receipt in self.approvals.items():
            ApprovalReceipt.model_validate(receipt.model_dump())
            if receipt.proposal_id != proposal_id or proposal_id not in self.proposals:
                return False
        for proposal_id, result in self.executions.items():
            ActionExecutionResult.model_validate(result.model_dump())
            if result.proposal_id != proposal_id or proposal_id not in self.proposals:
                return False
        previous_hash = "GENESIS"
        for sequence, event in enumerate(self.events, start=1):
            AuditEvent.model_validate(event.model_dump())
            if event.sequence != sequence or event.previous_hash != previous_hash:
                return False
            previous_hash = event.event_hash
        for event_id, signal in self.identity_signals.items():
            IdentitySignalRecord.model_validate(signal.model_dump())
            if signal.event_id != event_id:
                return False
        for subject, state in self.identity_subject_states.items():
            IdentitySubjectState.model_validate(state.model_dump())
            source_known = (
                state.signal_id in self.identity_signals
                if state.signal_id is not None
                else state.recovered_event_id in self.identity_gap_recovered_events
            )
            if state.subject != subject or not source_known:
                return False
        for token_id, revocation in self.identity_token_revocations.items():
            IdentityTokenRevocation.model_validate(revocation.model_dump())
            if revocation.token_id != token_id or revocation.signal_id not in self.identity_signals:
                return False
        for stream_id, checkpoint in self.identity_stream_checkpoints.items():
            IdentityStreamCheckpoint.model_validate(checkpoint.model_dump())
            if checkpoint.stream_id != stream_id:
                return False
        for (
            stream_id,
            unsolicited,
        ) in self.identity_stream_unsolicited_verification_states.items():
            IdentityStreamUnsolicitedVerificationState.model_validate(unsolicited.model_dump())
            if unsolicited.stream_id != stream_id:
                return False
            try:
                self._validate_unsolicited_verification_signal(unsolicited)
            except StateIntegrityError:
                return False
        for verification_id, verification in self.identity_stream_verifications.items():
            IdentityStreamVerification.model_validate(verification.model_dump())
            if verification.verification_id != verification_id or (
                verification.signal_id is not None
                and verification.signal_id not in self.identity_signals
            ):
                return False
        for operation_id, operation in self.identity_stream_status_operations.items():
            IdentityStreamStatusOperation.model_validate(operation.model_dump())
            if operation.operation_id != operation_id:
                return False
        for (
            reconciliation_id,
            reconciliation,
        ) in self.identity_stream_status_reconciliations.items():
            IdentityStreamStatusReconciliation.model_validate(reconciliation.model_dump())
            linked_operation = self.identity_stream_status_operations.get(
                reconciliation.operation_id
            )
            if (
                reconciliation.reconciliation_id != reconciliation_id
                or linked_operation is None
                or linked_operation.stream_id != reconciliation.stream_id
            ):
                return False
        for stream_id, schedule in self.identity_stream_recovery_schedules.items():
            IdentityStreamRecoverySchedule.model_validate(schedule.model_dump())
            if schedule.stream_id != stream_id:
                return False
            try:
                self._validate_recovery_schedule_reconciliation(schedule)
            except StateIntegrityError:
                return False
        for stream_id, observed in self.identity_stream_observed_states.items():
            IdentityStreamObservedState.model_validate(observed.model_dump())
            if observed.stream_id != stream_id:
                return False
            try:
                self._validate_observed_source(observed)
            except StateIntegrityError:
                return False
        open_incidents: set[str] = set()
        for incident_id, incident in self.identity_gap_recovery_states.items():
            IdentityGapRecoveryState.model_validate(incident.model_dump())
            if incident.incident_id != incident_id:
                return False
            if incident.closed_at is None:
                if incident.stream_id in open_incidents:
                    return False
                open_incidents.add(incident.stream_id)
        applied_by_incident: dict[str, int] = {}
        for provider_event_id, recovered in self.identity_gap_recovered_events.items():
            IdentityGapRecoveredEvent.model_validate(recovered.model_dump())
            if recovered.provider_event_id != provider_event_id:
                return False
            source = self.identity_gap_recovery_states.get(recovered.incident_id)
            if (
                source is None
                or source.stream_id != recovered.stream_id
                or recovered.cursor_sequence > source.cursor_sequence
            ):
                return False
            applied_by_incident[recovered.incident_id] = (
                applied_by_incident.get(recovered.incident_id, 0) + 1
            )
        for incident_id, incident in self.identity_gap_recovery_states.items():
            if applied_by_incident.get(incident_id, 0) != incident.events_applied:
                return False
        previous: dict[str, CorpusActivation] = {}
        for activation in self.corpus_activations:
            CorpusActivation.model_validate(activation.model_dump())
            try:
                _validate_corpus_activation_transition(
                    previous.get(activation.corpus_id), activation
                )
            except StateIntegrityError:
                return False
            previous[activation.corpus_id] = activation
        return True


class InMemoryStateStore:
    """Copy-on-write transaction store retained as the deterministic test oracle."""

    def __init__(self) -> None:
        self._proposals: dict[str, ActionProposal] = {}
        self._approvals: dict[str, ApprovalReceipt] = {}
        self._executions: dict[str, ActionExecutionResult] = {}
        self._events: list[AuditEvent] = []
        self._identity_signals: dict[str, IdentitySignalRecord] = {}
        self._identity_subject_states: dict[str, IdentitySubjectState] = {}
        self._identity_token_revocations: dict[str, IdentityTokenRevocation] = {}
        self._identity_stream_checkpoints: dict[str, IdentityStreamCheckpoint] = {}
        self._identity_stream_unsolicited_verification_states: dict[
            str, IdentityStreamUnsolicitedVerificationState
        ] = {}
        self._identity_stream_verifications: dict[str, IdentityStreamVerification] = {}
        self._identity_stream_status_operations: dict[str, IdentityStreamStatusOperation] = {}
        self._identity_stream_status_reconciliations: dict[
            str, IdentityStreamStatusReconciliation
        ] = {}
        self._identity_stream_recovery_schedules: dict[str, IdentityStreamRecoverySchedule] = {}
        self._identity_stream_observed_states: dict[str, IdentityStreamObservedState] = {}
        self._identity_gap_recovery_states: dict[str, IdentityGapRecoveryState] = {}
        self._identity_gap_recovered_events: dict[str, IdentityGapRecoveredEvent] = {}
        self._corpus_activations: list[CorpusActivation] = []
        self._lock = RLock()
        self._local = local()

    @contextmanager
    def transaction(self) -> Iterator[StateTransaction]:
        current = getattr(self._local, "transaction", None)
        if isinstance(current, _MemoryTransaction):
            try:
                yield current
            except BaseException:
                current.rollback_only = True
                raise
            return

        with self._lock:
            transaction = _MemoryTransaction(
                proposals=_copy_models(self._proposals),
                approvals=_copy_models(self._approvals),
                executions=_copy_models(self._executions),
                events=[event.model_copy(deep=True) for event in self._events],
                identity_signals=_copy_models(self._identity_signals),
                identity_subject_states=_copy_models(self._identity_subject_states),
                identity_token_revocations=_copy_models(self._identity_token_revocations),
                identity_stream_checkpoints=_copy_models(self._identity_stream_checkpoints),
                identity_stream_unsolicited_verification_states=_copy_models(
                    self._identity_stream_unsolicited_verification_states
                ),
                identity_stream_verifications=_copy_models(self._identity_stream_verifications),
                identity_stream_status_operations=_copy_models(
                    self._identity_stream_status_operations
                ),
                identity_stream_status_reconciliations=_copy_models(
                    self._identity_stream_status_reconciliations
                ),
                identity_stream_recovery_schedules=_copy_models(
                    self._identity_stream_recovery_schedules
                ),
                identity_stream_observed_states=_copy_models(self._identity_stream_observed_states),
                identity_gap_recovery_states=_copy_models(self._identity_gap_recovery_states),
                identity_gap_recovered_events=_copy_models(self._identity_gap_recovered_events),
                corpus_activations=[
                    activation.model_copy(deep=True) for activation in self._corpus_activations
                ],
            )
            self._local.transaction = transaction
            try:
                yield transaction
                if transaction.rollback_only:
                    raise StateStoreUnavailable
                self._proposals = _copy_models(transaction.proposals)
                self._approvals = _copy_models(transaction.approvals)
                self._executions = _copy_models(transaction.executions)
                self._events = [event.model_copy(deep=True) for event in transaction.events]
                self._identity_signals = _copy_models(transaction.identity_signals)
                self._identity_subject_states = _copy_models(transaction.identity_subject_states)
                self._identity_token_revocations = _copy_models(
                    transaction.identity_token_revocations
                )
                self._identity_stream_checkpoints = _copy_models(
                    transaction.identity_stream_checkpoints
                )
                self._identity_stream_unsolicited_verification_states = _copy_models(
                    transaction.identity_stream_unsolicited_verification_states
                )
                self._identity_stream_verifications = _copy_models(
                    transaction.identity_stream_verifications
                )
                self._identity_stream_status_operations = _copy_models(
                    transaction.identity_stream_status_operations
                )
                self._identity_stream_status_reconciliations = _copy_models(
                    transaction.identity_stream_status_reconciliations
                )
                self._identity_stream_recovery_schedules = _copy_models(
                    transaction.identity_stream_recovery_schedules
                )
                self._identity_stream_observed_states = _copy_models(
                    transaction.identity_stream_observed_states
                )
                self._identity_gap_recovery_states = _copy_models(
                    transaction.identity_gap_recovery_states
                )
                self._identity_gap_recovered_events = _copy_models(
                    transaction.identity_gap_recovered_events
                )
                self._corpus_activations = [
                    activation.model_copy(deep=True)
                    for activation in transaction.corpus_activations
                ]
            finally:
                delattr(self._local, "transaction")

    def verify_integrity(self) -> bool:
        with self.transaction() as transaction:
            if not isinstance(transaction, _MemoryTransaction):
                return False
            return transaction.verify_integrity()


class _SqliteTransaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self.rollback_only = False

    def get_proposal(self, proposal_id: str) -> ActionProposal | None:
        row = self._connection.execute(
            "SELECT proposal_id, document_json FROM action_proposals WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()
        return _parse_proposal_row(row) if row is not None else None

    def save_proposal(self, proposal: ActionProposal) -> None:
        self._connection.execute(
            """
            INSERT INTO action_proposals (proposal_id, document_json)
            VALUES (?, ?)
            ON CONFLICT(proposal_id) DO UPDATE SET document_json = excluded.document_json
            """,
            (proposal.proposal_id, proposal.model_dump_json()),
        )

    def get_approval(self, proposal_id: str) -> ApprovalReceipt | None:
        row = self._connection.execute(
            """
            SELECT proposal_id, approval_id, document_json
            FROM approval_receipts WHERE proposal_id = ?
            """,
            (proposal_id,),
        ).fetchone()
        return _parse_approval_row(row) if row is not None else None

    def save_approval(self, receipt: ApprovalReceipt) -> None:
        self._connection.execute(
            """
            INSERT INTO approval_receipts (proposal_id, approval_id, document_json)
            VALUES (?, ?, ?)
            ON CONFLICT(proposal_id) DO UPDATE SET
                approval_id = excluded.approval_id,
                document_json = excluded.document_json
            """,
            (receipt.proposal_id, receipt.approval_id, receipt.model_dump_json()),
        )

    def get_execution(self, proposal_id: str) -> ActionExecutionResult | None:
        row = self._connection.execute(
            """
            SELECT proposal_id, execution_id, task_id, document_json
            FROM action_executions WHERE proposal_id = ?
            """,
            (proposal_id,),
        ).fetchone()
        return _parse_execution_row(row) if row is not None else None

    def save_execution(self, result: ActionExecutionResult) -> None:
        try:
            self._connection.execute(
                """
                INSERT INTO action_executions (proposal_id, execution_id, task_id, document_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    result.proposal_id,
                    result.execution_id,
                    result.task_id,
                    result.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_stream_status_reconciliation(
        self,
        reconciliation_id: str,
    ) -> IdentityStreamStatusReconciliation | None:
        row = self._connection.execute(
            """
            SELECT reconciliation_id, stream_id, operation_id, status, requested_at,
                   completed_at, attempts, observed_status, observed_reason_hash,
                   failure, document_json
            FROM identity_stream_status_reconciliations WHERE reconciliation_id = ?
            """,
            (reconciliation_id,),
        ).fetchone()
        return _parse_identity_stream_status_reconciliation_row(row) if row is not None else None

    def save_identity_stream_status_reconciliation(
        self,
        reconciliation: IdentityStreamStatusReconciliation,
    ) -> None:
        operation = self.get_identity_stream_status_operation(reconciliation.operation_id)
        if operation is None or operation.stream_id != reconciliation.stream_id:
            raise StateIntegrityError
        existing = self.get_identity_stream_status_reconciliation(reconciliation.reconciliation_id)
        _validate_status_reconciliation_transition(existing, reconciliation)
        try:
            cursor = self._connection.execute(
                """
                INSERT INTO identity_stream_status_reconciliations (
                    reconciliation_id, stream_id, operation_id, status, requested_at,
                    completed_at, attempts, observed_status, observed_reason_hash,
                    failure, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(reconciliation_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    attempts = excluded.attempts,
                    observed_status = excluded.observed_status,
                    observed_reason_hash = excluded.observed_reason_hash,
                    failure = excluded.failure,
                    document_json = excluded.document_json
                WHERE identity_stream_status_reconciliations.stream_id = excluded.stream_id
                  AND identity_stream_status_reconciliations.operation_id = excluded.operation_id
                  AND identity_stream_status_reconciliations.requested_at = excluded.requested_at
                """,
                (
                    reconciliation.reconciliation_id,
                    reconciliation.stream_id,
                    reconciliation.operation_id,
                    reconciliation.status.value,
                    reconciliation.requested_at.isoformat(),
                    (
                        reconciliation.completed_at.isoformat()
                        if reconciliation.completed_at is not None
                        else None
                    ),
                    reconciliation.attempts,
                    (
                        reconciliation.observed_status.value
                        if reconciliation.observed_status is not None
                        else None
                    ),
                    reconciliation.observed_reason_hash,
                    reconciliation.failure.value if reconciliation.failure is not None else None,
                    reconciliation.model_dump_json(),
                ),
            )
            if cursor.rowcount != 1:
                raise StateIntegrityError
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_stream_recovery_schedule(
        self,
        stream_id: str,
    ) -> IdentityStreamRecoverySchedule | None:
        row = self._connection.execute(
            """
            SELECT stream_id, sequence, active_run_id, active_started_at,
                   lease_expires_at, last_run_id, last_completed_at, next_due_at,
                   consecutive_failures, last_outcome, last_reconciliation_id,
                   alert_level, document_json
            FROM identity_stream_recovery_schedules WHERE stream_id = ?
            """,
            (stream_id,),
        ).fetchone()
        return _parse_identity_stream_recovery_schedule_row(row) if row is not None else None

    def save_identity_stream_recovery_schedule(
        self,
        schedule: IdentityStreamRecoverySchedule,
    ) -> None:
        existing = self.get_identity_stream_recovery_schedule(schedule.stream_id)
        _validate_recovery_schedule_transition(existing, schedule)
        self._validate_recovery_schedule_reconciliation(schedule)
        try:
            cursor = self._connection.execute(
                """
                INSERT INTO identity_stream_recovery_schedules (
                    stream_id, sequence, active_run_id, active_started_at,
                    lease_expires_at, last_run_id, last_completed_at, next_due_at,
                    consecutive_failures, last_outcome, last_reconciliation_id,
                    alert_level, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stream_id) DO UPDATE SET
                    sequence = excluded.sequence,
                    active_run_id = excluded.active_run_id,
                    active_started_at = excluded.active_started_at,
                    lease_expires_at = excluded.lease_expires_at,
                    last_run_id = excluded.last_run_id,
                    last_completed_at = excluded.last_completed_at,
                    next_due_at = excluded.next_due_at,
                    consecutive_failures = excluded.consecutive_failures,
                    last_outcome = excluded.last_outcome,
                    last_reconciliation_id = excluded.last_reconciliation_id,
                    alert_level = excluded.alert_level,
                    document_json = excluded.document_json
                WHERE identity_stream_recovery_schedules.sequence = excluded.sequence - 1
                """,
                (
                    schedule.stream_id,
                    schedule.sequence,
                    schedule.active_run_id,
                    (
                        schedule.active_started_at.isoformat()
                        if schedule.active_started_at is not None
                        else None
                    ),
                    (
                        schedule.lease_expires_at.isoformat()
                        if schedule.lease_expires_at is not None
                        else None
                    ),
                    schedule.last_run_id,
                    (
                        schedule.last_completed_at.isoformat()
                        if schedule.last_completed_at is not None
                        else None
                    ),
                    schedule.next_due_at.isoformat(),
                    schedule.consecutive_failures,
                    schedule.last_outcome.value if schedule.last_outcome is not None else None,
                    schedule.last_reconciliation_id,
                    schedule.alert_level.value,
                    schedule.model_dump_json(),
                ),
            )
            if cursor.rowcount != 1:
                raise StateIntegrityError
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def _validate_recovery_schedule_reconciliation(
        self,
        schedule: IdentityStreamRecoverySchedule,
    ) -> None:
        if schedule.last_reconciliation_id is None:
            return
        reconciliation = self.get_identity_stream_status_reconciliation(
            schedule.last_reconciliation_id
        )
        if (
            reconciliation is None
            or reconciliation.stream_id != schedule.stream_id
            or reconciliation.status is IdentityStreamStatusReconciliationStatus.REQUESTING
        ):
            raise StateIntegrityError

    def get_identity_stream_status_operation(
        self,
        operation_id: str,
    ) -> IdentityStreamStatusOperation | None:
        row = self._connection.execute(
            """
            SELECT operation_id, stream_id, desired_status, status, reason_hash,
                   requested_at, completed_at, document_json
            FROM identity_stream_status_operations WHERE operation_id = ?
            """,
            (operation_id,),
        ).fetchone()
        return _parse_identity_stream_status_operation_row(row) if row is not None else None

    def latest_identity_stream_status_operation(
        self,
        stream_id: str,
    ) -> IdentityStreamStatusOperation | None:
        row = self._connection.execute(
            """
            SELECT operation_id, stream_id, desired_status, status, reason_hash,
                   requested_at, completed_at, document_json
            FROM identity_stream_status_operations
            WHERE stream_id = ? ORDER BY rowid DESC LIMIT 1
            """,
            (stream_id,),
        ).fetchone()
        return _parse_identity_stream_status_operation_row(row) if row is not None else None

    def save_identity_stream_status_operation(
        self,
        operation: IdentityStreamStatusOperation,
    ) -> None:
        existing = self.get_identity_stream_status_operation(operation.operation_id)
        _validate_status_operation_transition(existing, operation)
        try:
            cursor = self._connection.execute(
                """
                INSERT INTO identity_stream_status_operations (
                    operation_id, stream_id, desired_status, status, reason_hash,
                    requested_at, completed_at, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    document_json = excluded.document_json
                WHERE identity_stream_status_operations.stream_id = excluded.stream_id
                  AND identity_stream_status_operations.desired_status = excluded.desired_status
                  AND identity_stream_status_operations.reason_hash IS excluded.reason_hash
                  AND identity_stream_status_operations.requested_at = excluded.requested_at
                """,
                (
                    operation.operation_id,
                    operation.stream_id,
                    operation.desired_status.value,
                    operation.status.value,
                    operation.reason_hash,
                    operation.requested_at.isoformat(),
                    (
                        operation.completed_at.isoformat()
                        if operation.completed_at is not None
                        else None
                    ),
                    operation.model_dump_json(),
                ),
            )
            if cursor.rowcount != 1:
                raise StateIntegrityError
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_stream_observed_state(
        self,
        stream_id: str,
    ) -> IdentityStreamObservedState | None:
        row = self._connection.execute(
            """
            SELECT stream_id, status, observed_at, signal_id, operation_id,
                   reconciliation_id, document_json
            FROM identity_stream_observed_states WHERE stream_id = ?
            """,
            (stream_id,),
        ).fetchone()
        return _parse_identity_stream_observed_state_row(row) if row is not None else None

    def save_identity_stream_observed_state(
        self,
        state: IdentityStreamObservedState,
    ) -> None:
        self._validate_observed_source(state)
        try:
            self._connection.execute(
                """
                INSERT INTO identity_stream_observed_states (
                    stream_id, status, observed_at, signal_id, operation_id,
                    reconciliation_id, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(stream_id) DO UPDATE SET
                    status = excluded.status,
                    observed_at = excluded.observed_at,
                    signal_id = excluded.signal_id,
                    operation_id = excluded.operation_id,
                    reconciliation_id = excluded.reconciliation_id,
                    document_json = excluded.document_json
                """,
                (
                    state.stream_id,
                    state.status.value,
                    state.observed_at.isoformat(),
                    state.signal_id,
                    state.operation_id,
                    state.reconciliation_id,
                    state.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_gap_recovery_state(
        self,
        incident_id: str,
    ) -> IdentityGapRecoveryState | None:
        row = self._connection.execute(
            """
            SELECT incident_id, stream_id, status, cursor_sequence, closed_at, document_json
            FROM identity_gap_recovery_states WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()
        return _parse_gap_recovery_state_row(row) if row is not None else None

    def active_identity_gap_recovery_state(
        self,
        stream_id: str,
    ) -> IdentityGapRecoveryState | None:
        rows = self._connection.execute(
            """
            SELECT incident_id, stream_id, status, cursor_sequence, closed_at, document_json
            FROM identity_gap_recovery_states
            WHERE stream_id = ? AND closed_at IS NULL
            """,
            (stream_id,),
        ).fetchall()
        if not rows:
            return None
        if len(rows) > 1:
            raise StateIntegrityError
        return _parse_gap_recovery_state_row(rows[0])

    def save_identity_gap_recovery_state(self, state: IdentityGapRecoveryState) -> None:
        existing = self.get_identity_gap_recovery_state(state.incident_id)
        _validate_gap_recovery_transition(existing, state)
        try:
            self._connection.execute(
                """
                INSERT INTO identity_gap_recovery_states (
                    incident_id, stream_id, status, cursor_sequence, closed_at, document_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    status = excluded.status,
                    cursor_sequence = excluded.cursor_sequence,
                    closed_at = excluded.closed_at,
                    document_json = excluded.document_json
                """,
                (
                    state.incident_id,
                    state.stream_id,
                    state.status.value,
                    state.cursor_sequence,
                    state.closed_at.isoformat() if state.closed_at is not None else None,
                    state.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_gap_recovered_event(
        self,
        provider_event_id: str,
    ) -> IdentityGapRecoveredEvent | None:
        row = self._connection.execute(
            """
            SELECT provider_event_id, incident_id, stream_id, subject, cursor_sequence,
                   document_json
            FROM identity_gap_recovered_events WHERE provider_event_id = ?
            """,
            (provider_event_id,),
        ).fetchone()
        return _parse_gap_recovered_event_row(row) if row is not None else None

    def save_identity_gap_recovered_event(self, event: IdentityGapRecoveredEvent) -> None:
        try:
            self._connection.execute(
                """
                INSERT INTO identity_gap_recovered_events (
                    provider_event_id, incident_id, stream_id, subject, cursor_sequence,
                    document_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.provider_event_id,
                    event.incident_id,
                    event.stream_id,
                    event.subject,
                    event.cursor_sequence,
                    event.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def latest_corpus_activation(self, corpus_id: str) -> CorpusActivation | None:
        row = self._connection.execute(
            """
            SELECT corpus_id, sequence, version, manifest_checksum, document_json
            FROM corpus_activations WHERE corpus_id = ?
            ORDER BY sequence DESC LIMIT 1
            """,
            (corpus_id,),
        ).fetchone()
        return _parse_corpus_activation_row(row) if row is not None else None

    def save_corpus_activation(self, activation: CorpusActivation) -> None:
        existing = self.latest_corpus_activation(activation.corpus_id)
        _validate_corpus_activation_transition(existing, activation)
        try:
            self._connection.execute(
                """
                INSERT INTO corpus_activations (
                    corpus_id, sequence, version, manifest_checksum, document_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    activation.corpus_id,
                    activation.sequence,
                    activation.version,
                    activation.manifest_checksum,
                    activation.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def _validate_observed_source(self, state: IdentityStreamObservedState) -> None:
        if state.signal_id is not None:
            signal = self.get_identity_signal(state.signal_id)
            if (
                signal is None
                or signal.stream_id != state.stream_id
                or signal.stream_status is not state.status
                or signal.stream_status_reason_hash != state.reason_hash
            ):
                raise StateIntegrityError
            return
        if state.reconciliation_id is not None:
            reconciliation = self.get_identity_stream_status_reconciliation(state.reconciliation_id)
            if (
                reconciliation is None
                or reconciliation.stream_id != state.stream_id
                or reconciliation.status is not IdentityStreamStatusReconciliationStatus.OBSERVED
                or reconciliation.observed_status is not state.status
                or reconciliation.observed_reason_hash != state.reason_hash
            ):
                raise StateIntegrityError
            return
        operation = self.get_identity_stream_status_operation(state.operation_id or "")
        if (
            operation is None
            or operation.stream_id != state.stream_id
            or operation.desired_status is not state.status
            or operation.reason_hash != state.reason_hash
            or operation.status is not IdentityStreamStatusOperationStatus.CONFIRMED
        ):
            raise StateIntegrityError

    def get_identity_signal(self, event_id: str) -> IdentitySignalRecord | None:
        row = self._connection.execute(
            "SELECT event_id, payload_hash, document_json FROM identity_signals WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        return _parse_identity_signal_row(row) if row is not None else None

    def save_identity_signal(self, signal: IdentitySignalRecord) -> None:
        try:
            self._connection.execute(
                """
                INSERT INTO identity_signals (event_id, payload_hash, document_json)
                VALUES (?, ?, ?)
                """,
                (signal.event_id, signal.payload_hash, signal.model_dump_json()),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_subject_state(self, subject: str) -> IdentitySubjectState | None:
        row = self._connection.execute(
            """
            SELECT subject, signal_id, recovered_event_id, document_json
            FROM identity_subject_states WHERE subject = ?
            """,
            (subject,),
        ).fetchone()
        return _parse_identity_subject_state_row(row) if row is not None else None

    def save_identity_subject_state(self, state: IdentitySubjectState) -> None:
        try:
            self._connection.execute(
                """
                INSERT INTO identity_subject_states (
                    subject, signal_id, recovered_event_id, document_json
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(subject) DO UPDATE SET
                    signal_id = excluded.signal_id,
                    recovered_event_id = excluded.recovered_event_id,
                    document_json = excluded.document_json
                """,
                (
                    state.subject,
                    state.signal_id,
                    state.recovered_event_id,
                    state.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_token_revocation(self, token_id: str) -> IdentityTokenRevocation | None:
        row = self._connection.execute(
            """
            SELECT token_id, signal_id, document_json
            FROM identity_token_revocations WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()
        return _parse_identity_token_revocation_row(row) if row is not None else None

    def save_identity_token_revocation(self, revocation: IdentityTokenRevocation) -> None:
        try:
            self._connection.execute(
                """
                INSERT INTO identity_token_revocations (token_id, signal_id, document_json)
                VALUES (?, ?, ?)
                """,
                (revocation.token_id, revocation.signal_id, revocation.model_dump_json()),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def get_identity_stream_checkpoint(self, stream_id: str) -> IdentityStreamCheckpoint | None:
        row = self._connection.execute(
            """
            SELECT stream_id, document_json
            FROM identity_stream_checkpoints WHERE stream_id = ?
            """,
            (stream_id,),
        ).fetchone()
        return _parse_identity_stream_checkpoint_row(row) if row is not None else None

    def save_identity_stream_checkpoint(self, checkpoint: IdentityStreamCheckpoint) -> None:
        self._connection.execute(
            """
            INSERT INTO identity_stream_checkpoints (stream_id, document_json)
            VALUES (?, ?)
            ON CONFLICT(stream_id) DO UPDATE SET document_json = excluded.document_json
            """,
            (checkpoint.stream_id, checkpoint.model_dump_json()),
        )

    def get_identity_stream_unsolicited_verification_state(
        self,
        stream_id: str,
    ) -> IdentityStreamUnsolicitedVerificationState | None:
        row = self._connection.execute(
            """
            SELECT stream_id, window_started_at, accepted_count, last_received_at,
                   last_signal_id, document_json
            FROM identity_stream_unsolicited_verifications WHERE stream_id = ?
            """,
            (stream_id,),
        ).fetchone()
        return _parse_unsolicited_verification_row(row) if row is not None else None

    def save_identity_stream_unsolicited_verification_state(
        self,
        state: IdentityStreamUnsolicitedVerificationState,
    ) -> None:
        existing = self.get_identity_stream_unsolicited_verification_state(state.stream_id)
        _validate_unsolicited_verification_transition(existing, state)
        self._validate_unsolicited_verification_signal(state)
        try:
            self._connection.execute(
                """
                INSERT INTO identity_stream_unsolicited_verifications (
                    stream_id, window_started_at, accepted_count, last_received_at,
                    last_signal_id, document_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(stream_id) DO UPDATE SET
                    window_started_at = excluded.window_started_at,
                    accepted_count = excluded.accepted_count,
                    last_received_at = excluded.last_received_at,
                    last_signal_id = excluded.last_signal_id,
                    document_json = excluded.document_json
                """,
                (
                    state.stream_id,
                    state.window_started_at.isoformat(),
                    state.accepted_count,
                    state.last_received_at.isoformat(),
                    state.last_signal_id,
                    state.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def _validate_unsolicited_verification_signal(
        self,
        state: IdentityStreamUnsolicitedVerificationState,
    ) -> None:
        signal = self.get_identity_signal(state.last_signal_id)
        if (
            signal is None
            or signal.stream_id != state.stream_id
            or signal.event_type is not IdentitySignalType.STREAM_VERIFICATION
            or signal.verification_state_hash is not None
            or signal.received_at != state.last_received_at
        ):
            raise StateIntegrityError

    def get_identity_stream_verification(
        self,
        verification_id: str,
    ) -> IdentityStreamVerification | None:
        row = self._connection.execute(
            """
            SELECT verification_id, stream_id, state_hash, status, requested_at,
                   completed_at, signal_id, document_json
            FROM identity_stream_verifications WHERE verification_id = ?
            """,
            (verification_id,),
        ).fetchone()
        return _parse_identity_stream_verification_row(row) if row is not None else None

    def get_identity_stream_verification_by_state(
        self,
        stream_id: str,
        state_hash: str,
    ) -> IdentityStreamVerification | None:
        row = self._connection.execute(
            """
            SELECT verification_id, stream_id, state_hash, status, requested_at,
                   completed_at, signal_id, document_json
            FROM identity_stream_verifications
            WHERE stream_id = ? AND state_hash = ?
            """,
            (stream_id, state_hash),
        ).fetchone()
        return _parse_identity_stream_verification_row(row) if row is not None else None

    def latest_identity_stream_verification(
        self,
        stream_id: str,
    ) -> IdentityStreamVerification | None:
        row = self._connection.execute(
            """
            SELECT verification_id, stream_id, state_hash, status, requested_at,
                   completed_at, signal_id, document_json
            FROM identity_stream_verifications
            WHERE stream_id = ?
            ORDER BY rowid DESC LIMIT 1
            """,
            (stream_id,),
        ).fetchone()
        return _parse_identity_stream_verification_row(row) if row is not None else None

    def latest_verified_identity_stream_verification(
        self,
        stream_id: str,
    ) -> IdentityStreamVerification | None:
        row = self._connection.execute(
            """
            SELECT verification_id, stream_id, state_hash, status, requested_at,
                   completed_at, signal_id, document_json
            FROM identity_stream_verifications
            WHERE stream_id = ? AND status = ?
            ORDER BY completed_at DESC, rowid DESC LIMIT 1
            """,
            (stream_id, IdentityStreamVerificationStatus.VERIFIED.value),
        ).fetchone()
        return _parse_identity_stream_verification_row(row) if row is not None else None

    def save_identity_stream_verification(
        self,
        verification: IdentityStreamVerification,
    ) -> None:
        try:
            cursor = self._connection.execute(
                """
                INSERT INTO identity_stream_verifications (
                    verification_id, stream_id, state_hash, status, requested_at,
                    completed_at, signal_id, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(verification_id) DO UPDATE SET
                    status = excluded.status,
                    completed_at = excluded.completed_at,
                    signal_id = excluded.signal_id,
                    document_json = excluded.document_json
                WHERE identity_stream_verifications.stream_id = excluded.stream_id
                  AND identity_stream_verifications.state_hash = excluded.state_hash
                  AND identity_stream_verifications.requested_at = excluded.requested_at
                """,
                (
                    verification.verification_id,
                    verification.stream_id,
                    verification.state_hash,
                    verification.status.value,
                    verification.requested_at.isoformat(),
                    (
                        verification.completed_at.isoformat()
                        if verification.completed_at is not None
                        else None
                    ),
                    verification.signal_id,
                    verification.model_dump_json(),
                ),
            )
            if cursor.rowcount != 1:
                raise StateIntegrityError
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def last_audit_event(self) -> AuditEvent | None:
        row = self._connection.execute(
            """
            SELECT sequence, event_hash, previous_hash, document_json
            FROM audit_events ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        return _parse_audit_row(row) if row is not None else None

    def audit_events(self) -> tuple[AuditEvent, ...]:
        rows = self._connection.execute(
            """
            SELECT sequence, event_hash, previous_hash, document_json
            FROM audit_events ORDER BY sequence
            """
        ).fetchall()
        return tuple(_parse_audit_row(row) for row in rows)

    def append_audit_event(self, event: AuditEvent) -> None:
        previous = self.last_audit_event()
        expected_sequence = previous.sequence + 1 if previous is not None else 1
        expected_hash = previous.event_hash if previous is not None else "GENESIS"
        if event.sequence != expected_sequence or event.previous_hash != expected_hash:
            raise StateIntegrityError
        try:
            self._connection.execute(
                """
                INSERT INTO audit_events (
                    sequence, event_hash, previous_hash, document_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    event.sequence,
                    event.event_hash,
                    event.previous_hash,
                    event.model_dump_json(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise StateIntegrityError from exc

    def verify_integrity(self) -> bool:
        check = self._connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            return False
        if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            return False
        schema = self._connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if schema is None or schema[0] != _SCHEMA_VERSION:
            return False
        for row in self._connection.execute(
            "SELECT proposal_id, document_json FROM action_proposals"
        ).fetchall():
            _parse_proposal_row(row)
        for row in self._connection.execute(
            "SELECT proposal_id, approval_id, document_json FROM approval_receipts"
        ).fetchall():
            _parse_approval_row(row)
        for row in self._connection.execute(
            "SELECT proposal_id, execution_id, task_id, document_json FROM action_executions"
        ).fetchall():
            _parse_execution_row(row)
        for row in self._connection.execute(
            "SELECT sequence, event_hash, previous_hash, document_json FROM audit_events"
        ).fetchall():
            _parse_audit_row(row)
        for row in self._connection.execute(
            "SELECT event_id, payload_hash, document_json FROM identity_signals"
        ).fetchall():
            _parse_identity_signal_row(row)
        for row in self._connection.execute(
            """
            SELECT subject, signal_id, recovered_event_id, document_json
            FROM identity_subject_states
            """
        ).fetchall():
            _parse_identity_subject_state_row(row)
        for row in self._connection.execute(
            "SELECT token_id, signal_id, document_json FROM identity_token_revocations"
        ).fetchall():
            _parse_identity_token_revocation_row(row)
        for row in self._connection.execute(
            "SELECT stream_id, document_json FROM identity_stream_checkpoints"
        ).fetchall():
            _parse_identity_stream_checkpoint_row(row)
        for row in self._connection.execute(
            """
            SELECT stream_id, window_started_at, accepted_count, last_received_at,
                   last_signal_id, document_json
            FROM identity_stream_unsolicited_verifications
            """
        ).fetchall():
            unsolicited = _parse_unsolicited_verification_row(row)
            self._validate_unsolicited_verification_signal(unsolicited)
        for row in self._connection.execute(
            """
            SELECT verification_id, stream_id, state_hash, status, requested_at,
                   completed_at, signal_id, document_json
            FROM identity_stream_verifications
            """
        ).fetchall():
            _parse_identity_stream_verification_row(row)
        for row in self._connection.execute(
            """
            SELECT operation_id, stream_id, desired_status, status, reason_hash,
                   requested_at, completed_at, document_json
            FROM identity_stream_status_operations
            """
        ).fetchall():
            _parse_identity_stream_status_operation_row(row)
        for row in self._connection.execute(
            """
            SELECT reconciliation_id, stream_id, operation_id, status, requested_at,
                   completed_at, attempts, observed_status, observed_reason_hash,
                   failure, document_json
            FROM identity_stream_status_reconciliations
            """
        ).fetchall():
            reconciliation = _parse_identity_stream_status_reconciliation_row(row)
            operation = self.get_identity_stream_status_operation(reconciliation.operation_id)
            if operation is None or operation.stream_id != reconciliation.stream_id:
                raise StateIntegrityError
        for row in self._connection.execute(
            """
            SELECT stream_id, sequence, active_run_id, active_started_at,
                   lease_expires_at, last_run_id, last_completed_at, next_due_at,
                   consecutive_failures, last_outcome, last_reconciliation_id,
                   alert_level, document_json
            FROM identity_stream_recovery_schedules
            """
        ).fetchall():
            schedule = _parse_identity_stream_recovery_schedule_row(row)
            self._validate_recovery_schedule_reconciliation(schedule)
        for row in self._connection.execute(
            """
            SELECT stream_id, status, observed_at, signal_id, operation_id,
                   reconciliation_id, document_json
            FROM identity_stream_observed_states
            """
        ).fetchall():
            observed = _parse_identity_stream_observed_state_row(row)
            self._validate_observed_source(observed)
        applied_by_incident: dict[str, int] = {}
        for row in self._connection.execute(
            """
            SELECT provider_event_id, incident_id, stream_id, subject, cursor_sequence,
                   document_json
            FROM identity_gap_recovered_events
            """
        ).fetchall():
            recovered = _parse_gap_recovered_event_row(row)
            incident = self.get_identity_gap_recovery_state(recovered.incident_id)
            if (
                incident is None
                or incident.stream_id != recovered.stream_id
                or recovered.cursor_sequence > incident.cursor_sequence
            ):
                raise StateIntegrityError
            applied_by_incident[recovered.incident_id] = (
                applied_by_incident.get(recovered.incident_id, 0) + 1
            )
        for row in self._connection.execute(
            """
            SELECT incident_id, stream_id, status, cursor_sequence, closed_at, document_json
            FROM identity_gap_recovery_states
            """
        ).fetchall():
            state = _parse_gap_recovery_state_row(row)
            if applied_by_incident.get(state.incident_id, 0) != state.events_applied:
                raise StateIntegrityError
        previous: dict[str, CorpusActivation] = {}
        for row in self._connection.execute(
            """
            SELECT corpus_id, sequence, version, manifest_checksum, document_json
            FROM corpus_activations ORDER BY corpus_id, sequence
            """
        ).fetchall():
            activation = _parse_corpus_activation_row(row)
            _validate_corpus_activation_transition(previous.get(activation.corpus_id), activation)
            previous[activation.corpus_id] = activation
        return True


class SqliteStateStore:
    """Durable single-node simulation adapter; not the production database architecture."""

    def __init__(self, database_path: str | Path, *, timeout_seconds: float = 3.0) -> None:
        path = Path(database_path)
        if not path.is_absolute() or path.name in {"", ".", "..", ":memory:"}:
            raise ValueError("SQLite state path must be an absolute file path")
        if path.exists() and (path.is_dir() or path.is_symlink()):
            raise ValueError("SQLite state path must be a regular non-symlink file")
        if not path.parent.is_dir():
            raise ValueError("SQLite state parent directory must already exist")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError(
                "SQLite state timeout must be greater than zero and at most 30 seconds"
            )
        self._path = path
        self._timeout_seconds = timeout_seconds
        self._local = local()
        self._initialize()

    @contextmanager
    def transaction(self) -> Iterator[StateTransaction]:
        current = getattr(self._local, "transaction", None)
        if isinstance(current, _SqliteTransaction):
            try:
                yield current
            except BaseException:
                current.rollback_only = True
                raise
            return

        connection = self._connect()
        transaction = _SqliteTransaction(connection)
        self._local.transaction = transaction
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield transaction
            if transaction.rollback_only:
                raise StateStoreUnavailable
            connection.commit()
        except sqlite3.Error as exc:
            _rollback(connection)
            raise StateStoreUnavailable from exc
        except BaseException:
            _rollback(connection)
            raise
        finally:
            delattr(self._local, "transaction")
            connection.close()

    def verify_integrity(self) -> bool:
        try:
            with self.transaction() as transaction:
                if not isinstance(transaction, _SqliteTransaction):
                    return False
                return transaction.verify_integrity()
        except (StateIntegrityError, StateStoreUnavailable):
            return False

    def _initialize(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS action_proposals (
                    proposal_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS approval_receipts (
                    proposal_id TEXT PRIMARY KEY REFERENCES action_proposals(proposal_id),
                    approval_id TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS action_executions (
                    proposal_id TEXT PRIMARY KEY REFERENCES action_proposals(proposal_id),
                    execution_id TEXT NOT NULL UNIQUE,
                    task_id TEXT NOT NULL UNIQUE,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
                    previous_hash TEXT NOT NULL,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_signals (
                    event_id TEXT PRIMARY KEY,
                    payload_hash TEXT NOT NULL UNIQUE CHECK (length(payload_hash) = 64),
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_subject_states (
                    subject TEXT PRIMARY KEY,
                    signal_id TEXT REFERENCES identity_signals(event_id),
                    recovered_event_id TEXT
                        REFERENCES identity_gap_recovered_events(provider_event_id),
                    document_json TEXT NOT NULL,
                    CHECK (
                        (signal_id IS NOT NULL AND recovered_event_id IS NULL)
                        OR (signal_id IS NULL AND recovered_event_id IS NOT NULL)
                    )
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_token_revocations (
                    token_id TEXT PRIMARY KEY,
                    signal_id TEXT NOT NULL REFERENCES identity_signals(event_id),
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_stream_checkpoints (
                    stream_id TEXT PRIMARY KEY,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_stream_unsolicited_verifications (
                    stream_id TEXT PRIMARY KEY,
                    window_started_at TEXT NOT NULL,
                    accepted_count INTEGER NOT NULL CHECK (
                        accepted_count BETWEEN 1 AND 100
                    ),
                    last_received_at TEXT NOT NULL,
                    last_signal_id TEXT NOT NULL REFERENCES identity_signals(event_id),
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_stream_verifications (
                    verification_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL,
                    state_hash TEXT NOT NULL UNIQUE CHECK (length(state_hash) = 64),
                    status TEXT NOT NULL CHECK (
                        status IN ('REQUESTING', 'PENDING', 'VERIFIED', 'FAILED', 'EXPIRED')
                    ),
                    requested_at TEXT NOT NULL,
                    completed_at TEXT,
                    signal_id TEXT REFERENCES identity_signals(event_id),
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE INDEX IF NOT EXISTS idx_identity_stream_verifications_latest
                    ON identity_stream_verifications(stream_id, requested_at DESC);
                CREATE TABLE IF NOT EXISTS identity_stream_status_operations (
                    operation_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL,
                    desired_status TEXT NOT NULL CHECK (
                        desired_status IN ('enabled', 'paused', 'disabled')
                    ),
                    status TEXT NOT NULL CHECK (
                        status IN ('REQUESTING', 'CONFIRMED', 'OUTCOME_UNKNOWN')
                    ),
                    reason_hash TEXT CHECK (reason_hash IS NULL OR length(reason_hash) = 64),
                    requested_at TEXT NOT NULL,
                    completed_at TEXT,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE INDEX IF NOT EXISTS idx_identity_stream_status_operations_latest
                    ON identity_stream_status_operations(stream_id, requested_at DESC);
                CREATE TABLE IF NOT EXISTS identity_stream_status_reconciliations (
                    reconciliation_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL
                        REFERENCES identity_stream_status_operations(operation_id),
                    status TEXT NOT NULL CHECK (
                        status IN ('REQUESTING', 'OBSERVED', 'FAILED', 'SUPERSEDED')
                    ),
                    requested_at TEXT NOT NULL,
                    completed_at TEXT,
                    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 5),
                    observed_status TEXT CHECK (
                        observed_status IS NULL
                        OR observed_status IN ('enabled', 'paused', 'disabled')
                    ),
                    observed_reason_hash TEXT CHECK (
                        observed_reason_hash IS NULL OR length(observed_reason_hash) = 64
                    ),
                    failure TEXT CHECK (
                        failure IS NULL OR failure IN (
                            'NON_RETRYABLE', 'RETRY_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED'
                        )
                    ),
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_stream_recovery_schedules (
                    stream_id TEXT PRIMARY KEY,
                    sequence INTEGER NOT NULL CHECK (
                        sequence BETWEEN 1 AND 2147483647
                    ),
                    active_run_id TEXT,
                    active_started_at TEXT,
                    lease_expires_at TEXT,
                    last_run_id TEXT,
                    last_completed_at TEXT,
                    next_due_at TEXT NOT NULL,
                    consecutive_failures INTEGER NOT NULL CHECK (
                        consecutive_failures BETWEEN 0 AND 100
                    ),
                    last_outcome TEXT CHECK (
                        last_outcome IS NULL OR last_outcome IN (
                            'RECOVERED', 'DRIFTED', 'FAILED', 'UNCONFIGURED', 'SUPERSEDED'
                        )
                    ),
                    last_reconciliation_id TEXT
                        REFERENCES identity_stream_status_reconciliations(reconciliation_id),
                    alert_level TEXT NOT NULL CHECK (
                        alert_level IN ('CLEAR', 'WARNING', 'CRITICAL')
                    ),
                    document_json TEXT NOT NULL,
                    CHECK (
                        (
                            active_run_id IS NULL AND active_started_at IS NULL
                            AND lease_expires_at IS NULL
                        )
                        OR (
                            active_run_id IS NOT NULL AND active_started_at IS NOT NULL
                            AND lease_expires_at IS NOT NULL
                        )
                    )
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_stream_observed_states (
                    stream_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL CHECK (status IN ('enabled', 'paused', 'disabled')),
                    observed_at TEXT NOT NULL,
                    signal_id TEXT REFERENCES identity_signals(event_id),
                    operation_id TEXT REFERENCES identity_stream_status_operations(operation_id),
                    reconciliation_id TEXT
                        REFERENCES identity_stream_status_reconciliations(reconciliation_id),
                    document_json TEXT NOT NULL,
                    CHECK (
                        (
                            signal_id IS NOT NULL AND operation_id IS NULL
                            AND reconciliation_id IS NULL
                        )
                        OR (
                            signal_id IS NULL AND operation_id IS NOT NULL
                            AND reconciliation_id IS NULL
                        )
                        OR (
                            signal_id IS NULL AND operation_id IS NULL
                            AND reconciliation_id IS NOT NULL
                        )
                    )
                ) STRICT;
                CREATE TABLE IF NOT EXISTS identity_gap_recovery_states (
                    incident_id TEXT PRIMARY KEY,
                    stream_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('OPEN', 'RECOVERING', 'RECOVERED', 'ABANDONED')
                    ),
                    cursor_sequence INTEGER NOT NULL CHECK (
                        cursor_sequence BETWEEN 0 AND 2147483647
                    ),
                    closed_at TEXT,
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE UNIQUE INDEX IF NOT EXISTS identity_gap_recovery_open_stream
                    ON identity_gap_recovery_states(stream_id)
                    WHERE closed_at IS NULL;
                CREATE TABLE IF NOT EXISTS identity_gap_recovered_events (
                    provider_event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL
                        REFERENCES identity_gap_recovery_states(incident_id),
                    stream_id TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    cursor_sequence INTEGER NOT NULL CHECK (
                        cursor_sequence BETWEEN 1 AND 2147483647
                    ),
                    document_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS corpus_activations (
                    corpus_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK (
                        sequence BETWEEN 1 AND 2147483647
                    ),
                    version TEXT NOT NULL,
                    manifest_checksum TEXT NOT NULL CHECK (length(manifest_checksum) = 64),
                    document_json TEXT NOT NULL,
                    PRIMARY KEY (corpus_id, sequence)
                ) STRICT;
                INSERT OR IGNORE INTO schema_metadata (key, value)
                VALUES ('schema_version', '10');
                COMMIT;
                """
            )
            row = connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is not None and row[0] in {"1", "2", "3", "4", "5", "6", "7", "8"}:
                connection.executescript(_SUBJECT_STATE_REBUILD_SQL)
            if row is not None and row[0] == "5":
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE identity_stream_observed_states
                        RENAME TO identity_stream_observed_states_v5;
                    CREATE TABLE identity_stream_observed_states (
                        stream_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL CHECK (
                            status IN ('enabled', 'paused', 'disabled')
                        ),
                        observed_at TEXT NOT NULL,
                        signal_id TEXT REFERENCES identity_signals(event_id),
                        operation_id TEXT
                            REFERENCES identity_stream_status_operations(operation_id),
                        reconciliation_id TEXT
                            REFERENCES identity_stream_status_reconciliations(reconciliation_id),
                        document_json TEXT NOT NULL,
                        CHECK (
                            (
                                signal_id IS NOT NULL AND operation_id IS NULL
                                AND reconciliation_id IS NULL
                            )
                            OR (
                                signal_id IS NULL AND operation_id IS NOT NULL
                                AND reconciliation_id IS NULL
                            )
                            OR (
                                signal_id IS NULL AND operation_id IS NULL
                                AND reconciliation_id IS NOT NULL
                            )
                        )
                    ) STRICT;
                    INSERT INTO identity_stream_observed_states (
                        stream_id, status, observed_at, signal_id, operation_id,
                        reconciliation_id, document_json
                    )
                    SELECT stream_id, status, observed_at, signal_id, operation_id,
                           NULL, document_json
                    FROM identity_stream_observed_states_v5;
                    DROP TABLE identity_stream_observed_states_v5;
                    UPDATE schema_metadata SET value = '10' WHERE key = 'schema_version';
                    COMMIT;
                    """
                )
            elif row is not None and row[0] in {"1", "2", "3", "4", "6", "7", "8", "9"}:
                if row[0] == "2":
                    for signal_row in connection.execute(
                        "SELECT event_id, payload_hash, document_json FROM identity_signals"
                    ).fetchall():
                        _parse_identity_signal_row(signal_row)
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE schema_metadata SET value = ? WHERE key = 'schema_version'",
                    (_SCHEMA_VERSION,),
                )
                connection.commit()
            elif row is None or row[0] != _SCHEMA_VERSION:
                raise StateIntegrityError
        except StateIntegrityError:
            raise
        except sqlite3.Error as exc:
            raise StateStoreUnavailable from exc
        finally:
            if connection is not None:
                _rollback(connection)
                connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA trusted_schema = OFF")
        except sqlite3.Error:
            connection.close()
            raise
        return connection


def _parse_model[ModelT: BaseModel](document: object, model_type: type[ModelT]) -> ModelT:
    if not isinstance(document, str):
        raise StateIntegrityError
    try:
        return model_type.model_validate_json(document)
    except (ValidationError, ValueError, TypeError) as exc:
        raise StateIntegrityError from exc


def _parse_proposal_row(row: tuple[object, ...]) -> ActionProposal:
    proposal = _parse_model(row[1], ActionProposal)
    if proposal.proposal_id != row[0]:
        raise StateIntegrityError
    return proposal


def _parse_approval_row(row: tuple[object, ...]) -> ApprovalReceipt:
    receipt = _parse_model(row[2], ApprovalReceipt)
    if receipt.proposal_id != row[0] or receipt.approval_id != row[1]:
        raise StateIntegrityError
    return receipt


def _parse_execution_row(row: tuple[object, ...]) -> ActionExecutionResult:
    result = _parse_model(row[3], ActionExecutionResult)
    if result.proposal_id != row[0] or result.execution_id != row[1] or result.task_id != row[2]:
        raise StateIntegrityError
    return result


def _parse_audit_row(row: tuple[object, ...]) -> AuditEvent:
    event = _parse_model(row[3], AuditEvent)
    if event.sequence != row[0] or event.event_hash != row[1] or event.previous_hash != row[2]:
        raise StateIntegrityError
    return event


def _parse_identity_signal_row(row: tuple[object, ...]) -> IdentitySignalRecord:
    signal = _parse_model(row[2], IdentitySignalRecord)
    if signal.event_id != row[0] or signal.payload_hash != row[1]:
        raise StateIntegrityError
    return signal


def _parse_identity_subject_state_row(row: tuple[object, ...]) -> IdentitySubjectState:
    state = _parse_model(row[3], IdentitySubjectState)
    if state.subject != row[0] or state.signal_id != row[1] or state.recovered_event_id != row[2]:
        raise StateIntegrityError
    return state


def _parse_identity_token_revocation_row(row: tuple[object, ...]) -> IdentityTokenRevocation:
    revocation = _parse_model(row[2], IdentityTokenRevocation)
    if revocation.token_id != row[0] or revocation.signal_id != row[1]:
        raise StateIntegrityError
    return revocation


def _parse_identity_stream_checkpoint_row(
    row: tuple[object, ...],
) -> IdentityStreamCheckpoint:
    checkpoint = _parse_model(row[1], IdentityStreamCheckpoint)
    if checkpoint.stream_id != row[0]:
        raise StateIntegrityError
    return checkpoint


def _parse_unsolicited_verification_row(
    row: tuple[object, ...],
) -> IdentityStreamUnsolicitedVerificationState:
    state = _parse_model(row[5], IdentityStreamUnsolicitedVerificationState)
    if (
        state.stream_id != row[0]
        or state.window_started_at.isoformat() != row[1]
        or state.accepted_count != row[2]
        or state.last_received_at.isoformat() != row[3]
        or state.last_signal_id != row[4]
    ):
        raise StateIntegrityError
    return state


def _parse_identity_stream_verification_row(
    row: tuple[object, ...],
) -> IdentityStreamVerification:
    verification = _parse_model(row[7], IdentityStreamVerification)
    completed_at = (
        verification.completed_at.isoformat() if verification.completed_at is not None else None
    )
    if (
        verification.verification_id != row[0]
        or verification.stream_id != row[1]
        or verification.state_hash != row[2]
        or verification.status.value != row[3]
        or verification.requested_at.isoformat() != row[4]
        or completed_at != row[5]
        or verification.signal_id != row[6]
    ):
        raise StateIntegrityError
    return verification


def _parse_identity_stream_status_operation_row(
    row: tuple[object, ...],
) -> IdentityStreamStatusOperation:
    operation = _parse_model(row[7], IdentityStreamStatusOperation)
    completed_at = (
        operation.completed_at.isoformat() if operation.completed_at is not None else None
    )
    if (
        operation.operation_id != row[0]
        or operation.stream_id != row[1]
        or operation.desired_status.value != row[2]
        or operation.status.value != row[3]
        or operation.reason_hash != row[4]
        or operation.requested_at.isoformat() != row[5]
        or completed_at != row[6]
    ):
        raise StateIntegrityError
    return operation


def _parse_identity_stream_status_reconciliation_row(
    row: tuple[object, ...],
) -> IdentityStreamStatusReconciliation:
    reconciliation = _parse_model(row[10], IdentityStreamStatusReconciliation)
    completed_at = (
        reconciliation.completed_at.isoformat() if reconciliation.completed_at is not None else None
    )
    observed_status = (
        reconciliation.observed_status.value if reconciliation.observed_status is not None else None
    )
    failure = reconciliation.failure.value if reconciliation.failure is not None else None
    if (
        reconciliation.reconciliation_id != row[0]
        or reconciliation.stream_id != row[1]
        or reconciliation.operation_id != row[2]
        or reconciliation.status.value != row[3]
        or reconciliation.requested_at.isoformat() != row[4]
        or completed_at != row[5]
        or reconciliation.attempts != row[6]
        or observed_status != row[7]
        or reconciliation.observed_reason_hash != row[8]
        or failure != row[9]
    ):
        raise StateIntegrityError
    return reconciliation


def _parse_identity_stream_recovery_schedule_row(
    row: tuple[object, ...],
) -> IdentityStreamRecoverySchedule:
    schedule = _parse_model(row[12], IdentityStreamRecoverySchedule)
    active_started_at = (
        schedule.active_started_at.isoformat() if schedule.active_started_at is not None else None
    )
    lease_expires_at = (
        schedule.lease_expires_at.isoformat() if schedule.lease_expires_at is not None else None
    )
    last_completed_at = (
        schedule.last_completed_at.isoformat() if schedule.last_completed_at is not None else None
    )
    last_outcome = schedule.last_outcome.value if schedule.last_outcome is not None else None
    if (
        schedule.stream_id != row[0]
        or schedule.sequence != row[1]
        or schedule.active_run_id != row[2]
        or active_started_at != row[3]
        or lease_expires_at != row[4]
        or schedule.last_run_id != row[5]
        or last_completed_at != row[6]
        or schedule.next_due_at.isoformat() != row[7]
        or schedule.consecutive_failures != row[8]
        or last_outcome != row[9]
        or schedule.last_reconciliation_id != row[10]
        or schedule.alert_level.value != row[11]
    ):
        raise StateIntegrityError
    return schedule


def _parse_identity_stream_observed_state_row(
    row: tuple[object, ...],
) -> IdentityStreamObservedState:
    state = _parse_model(row[6], IdentityStreamObservedState)
    if (
        state.stream_id != row[0]
        or state.status.value != row[1]
        or state.observed_at.isoformat() != row[2]
        or state.signal_id != row[3]
        or state.operation_id != row[4]
        or state.reconciliation_id != row[5]
    ):
        raise StateIntegrityError
    return state


def _parse_corpus_activation_row(row: tuple[object, ...]) -> CorpusActivation:
    activation = _parse_model(row[4], CorpusActivation)
    if (
        activation.corpus_id != row[0]
        or activation.sequence != row[1]
        or activation.version != row[2]
        or activation.manifest_checksum != row[3]
    ):
        raise StateIntegrityError
    return activation


def _validate_corpus_activation_transition(
    existing: CorpusActivation | None,
    activation: CorpusActivation,
) -> None:
    """Corpus activations are append-only and each one names the version it replaced.

    Rollback is an ordinary activation of an earlier version, so the history stays a complete record
    of which corpus answered queries at any point rather than a mutable pointer.
    """

    if existing is None:
        if activation.sequence != 1 or activation.previous_version is not None:
            raise StateIntegrityError
        return
    if (
        existing.corpus_id != activation.corpus_id
        or activation.sequence != existing.sequence + 1
        or activation.previous_version != existing.version
        or activation.activated_at < existing.activated_at
    ):
        raise StateIntegrityError


def _parse_gap_recovery_state_row(row: tuple[object, ...]) -> IdentityGapRecoveryState:
    state = _parse_model(row[5], IdentityGapRecoveryState)
    closed_at = state.closed_at.isoformat() if state.closed_at is not None else None
    if (
        state.incident_id != row[0]
        or state.stream_id != row[1]
        or state.status.value != row[2]
        or state.cursor_sequence != row[3]
        or closed_at != row[4]
    ):
        raise StateIntegrityError
    return state


def _parse_gap_recovered_event_row(row: tuple[object, ...]) -> IdentityGapRecoveredEvent:
    event = _parse_model(row[5], IdentityGapRecoveredEvent)
    if (
        event.provider_event_id != row[0]
        or event.incident_id != row[1]
        or event.stream_id != row[2]
        or event.subject != row[3]
        or event.cursor_sequence != row[4]
    ):
        raise StateIntegrityError
    return event


def _validate_status_operation_transition(
    existing: IdentityStreamStatusOperation | None,
    operation: IdentityStreamStatusOperation,
) -> None:
    if existing is None:
        if operation.status is not IdentityStreamStatusOperationStatus.REQUESTING:
            raise StateIntegrityError
        return
    if (
        existing.stream_id != operation.stream_id
        or existing.desired_status is not operation.desired_status
        or existing.reason_hash != operation.reason_hash
        or existing.requested_at != operation.requested_at
    ):
        raise StateIntegrityError
    if existing == operation:
        return
    allowed = {
        IdentityStreamStatusOperationStatus.REQUESTING: {
            IdentityStreamStatusOperationStatus.CONFIRMED,
            IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN,
        },
        IdentityStreamStatusOperationStatus.OUTCOME_UNKNOWN: {
            IdentityStreamStatusOperationStatus.CONFIRMED,
        },
        IdentityStreamStatusOperationStatus.CONFIRMED: set(),
    }
    if operation.status not in allowed[existing.status]:
        raise StateIntegrityError


def _validate_unsolicited_verification_transition(
    existing: IdentityStreamUnsolicitedVerificationState | None,
    state: IdentityStreamUnsolicitedVerificationState,
) -> None:
    if existing is None:
        return
    if state.stream_id != existing.stream_id or state.last_received_at < existing.last_received_at:
        raise StateIntegrityError
    if state.window_started_at == existing.window_started_at:
        if (
            state.accepted_count != existing.accepted_count + 1
            or state.last_received_at < existing.last_received_at
            or state.last_signal_id == existing.last_signal_id
        ):
            raise StateIntegrityError
        return
    if (
        state.window_started_at <= existing.window_started_at
        or state.accepted_count != 1
        or state.last_received_at != state.window_started_at
        or state.last_signal_id == existing.last_signal_id
    ):
        raise StateIntegrityError


def _validate_status_reconciliation_transition(
    existing: IdentityStreamStatusReconciliation | None,
    reconciliation: IdentityStreamStatusReconciliation,
) -> None:
    if existing is None:
        if reconciliation.status is not IdentityStreamStatusReconciliationStatus.REQUESTING:
            raise StateIntegrityError
        return
    if (
        existing.stream_id != reconciliation.stream_id
        or existing.operation_id != reconciliation.operation_id
        or existing.requested_at != reconciliation.requested_at
    ):
        raise StateIntegrityError
    if existing == reconciliation:
        return
    if (
        existing.status is not IdentityStreamStatusReconciliationStatus.REQUESTING
        or reconciliation.status is IdentityStreamStatusReconciliationStatus.REQUESTING
    ):
        raise StateIntegrityError


def _validate_gap_recovery_transition(
    existing: IdentityGapRecoveryState | None,
    state: IdentityGapRecoveryState,
) -> None:
    """Enforce compare-and-swap cursor sequencing for compensating gap recovery.

    A page may only be committed against the sequence its worker read. Two workers that fetch the
    same cursor therefore cannot both apply it: the second commit fails rather than reapplying the
    page or rewinding the cursor.
    """

    if existing is None:
        if state.cursor_sequence != 0 or state.status is not IdentityGapIncidentStatus.OPEN:
            raise StateIntegrityError
        return
    if (
        existing.stream_id != state.stream_id
        or existing.opened_at != state.opened_at
        or state.updated_at < existing.updated_at
        or existing.closed_at is not None
    ):
        raise StateIntegrityError
    closing = state.closed_at is not None
    if closing:
        if state.cursor_sequence != existing.cursor_sequence:
            raise StateIntegrityError
    elif state.cursor_sequence != existing.cursor_sequence + 1:
        raise StateIntegrityError
    if (
        state.events_applied < existing.events_applied
        or state.events_ignored < existing.events_ignored
        or state.events_duplicate < existing.events_duplicate
    ):
        raise StateIntegrityError
    if existing.caught_up_at is not None and state.caught_up_at != existing.caught_up_at:
        raise StateIntegrityError


def _validate_recovery_schedule_transition(
    existing: IdentityStreamRecoverySchedule | None,
    schedule: IdentityStreamRecoverySchedule,
) -> None:
    if existing is None:
        if (
            schedule.sequence != 1
            or schedule.active_run_id is None
            or schedule.active_started_at != schedule.next_due_at
        ):
            raise StateIntegrityError
        return
    if existing.stream_id != schedule.stream_id or schedule.sequence != existing.sequence + 1:
        raise StateIntegrityError
    previous_history = (
        existing.last_run_id,
        existing.last_completed_at,
        existing.next_due_at,
        existing.consecutive_failures,
        existing.last_outcome,
        existing.last_reconciliation_id,
        existing.alert_level,
    )
    candidate_history = (
        schedule.last_run_id,
        schedule.last_completed_at,
        schedule.next_due_at,
        schedule.consecutive_failures,
        schedule.last_outcome,
        schedule.last_reconciliation_id,
        schedule.alert_level,
    )
    if existing.active_run_id is None:
        if (
            schedule.active_run_id is None
            or schedule.active_started_at is None
            or schedule.active_started_at < existing.next_due_at
            or candidate_history != previous_history
        ):
            raise StateIntegrityError
        return
    if schedule.active_run_id is not None:
        if (
            schedule.active_run_id == existing.active_run_id
            or schedule.active_started_at is None
            or existing.lease_expires_at is None
            or schedule.active_started_at < existing.lease_expires_at
            or candidate_history != previous_history
        ):
            raise StateIntegrityError
        return
    if (
        schedule.last_run_id != existing.active_run_id
        or schedule.last_completed_at is None
        or existing.active_started_at is None
        or schedule.last_completed_at < existing.active_started_at
    ):
        raise StateIntegrityError


def _copy_models[ModelT: BaseModel](values: dict[str, ModelT]) -> dict[str, ModelT]:
    return {key: value.model_copy(deep=True) for key, value in values.items()}


def _rollback(connection: sqlite3.Connection) -> None:
    with suppress(sqlite3.Error):
        connection.rollback()

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from polaris.domain import (
    ActionExecutionResult,
    ActionProposal,
    ApprovalDecision,
    ApprovalReceipt,
    FollowUpAction,
    Principal,
    ProposalStatus,
    PurposeOfUse,
)
from polaris.errors import AuthorizationError, ConflictError, NotFoundError, PolarisError
from polaris.security.policy import PolicyEngine
from polaris.security.text import contains_prohibited_clinical_action
from polaris.services.audit import AuditLedger, utc_now
from polaris.services.patients import PatientService
from polaris.services.state import PolarisStateStore, StateIntegrityError, StateTransaction


class ActionService:
    def __init__(
        self,
        *,
        policy: PolicyEngine,
        patients: PatientService,
        audit: AuditLedger,
        signing_key: str,
        ttl_seconds: int,
        clock: Callable[[], datetime] = utc_now,
        state: PolarisStateStore | None = None,
    ) -> None:
        self._policy = policy
        self._patients = patients
        self._audit = audit
        self._signing_key = signing_key.encode()
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._state = state or audit.state_store
        if self._state is not audit.state_store:
            raise ValueError("Action and audit services must share one transactional state store")

    def propose(
        self,
        *,
        principal: Principal,
        purpose: PurposeOfUse,
        action: FollowUpAction,
        correlation_id: str,
    ) -> ActionProposal:
        if contains_prohibited_clinical_action(action.summary):
            self._audit.append(
                actor=principal.subject,
                event_type="action.propose",
                outcome="ACTION_CLINICAL_CONTENT_DENIED",
                correlation_id=correlation_id,
                metadata={"patient_id": action.patient_id, "action_type": action.action_type},
            )
            raise AuthorizationError("ACTION_CLINICAL_CONTENT_DENIED")

        patient = self._patients.authorized_patient(
            principal=principal,
            purpose=purpose,
            patient_id=action.patient_id,
            correlation_id=correlation_id,
        )
        decision = self._policy.propose_action(principal, purpose, patient, action)
        if not decision.allowed:
            self._audit.append(
                actor=principal.subject,
                event_type="action.propose",
                outcome=decision.code,
                correlation_id=correlation_id,
                metadata={
                    "patient_id": action.patient_id,
                    "action_type": action.action_type,
                    "policy_version": decision.policy_version,
                },
            )
            raise AuthorizationError(decision.code)

        now = self._clock()
        proposal = ActionProposal(
            proposal_id=f"PRP-{uuid4().hex}",
            action=action,
            action_digest=action_digest(action),
            requester=principal,
            purpose=purpose,
            status=ProposalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        with self._state.transaction() as transaction:
            if transaction.get_proposal(proposal.proposal_id) is not None:
                raise StateIntegrityError
            transaction.save_proposal(proposal)
            self._audit.append(
                actor=principal.subject,
                event_type="action.propose",
                outcome=decision.code,
                correlation_id=correlation_id,
                metadata={
                    "patient_id": action.patient_id,
                    "action_type": action.action_type,
                    "proposal_id": proposal.proposal_id,
                    "policy_version": decision.policy_version,
                },
            )
        return proposal.model_copy(deep=True)

    def decide(
        self,
        *,
        proposal_id: str,
        approver: Principal,
        purpose: PurposeOfUse,
        decision: ApprovalDecision,
        expected_action_digest: str,
        correlation_id: str,
    ) -> ApprovalReceipt:
        deferred_error: PolarisError | None = None
        receipt: ApprovalReceipt | None = None
        with self._state.transaction() as transaction:
            proposal = self._get_proposal(transaction, proposal_id)
            now = self._clock()
            if proposal.status is not ProposalStatus.PENDING:
                raise ConflictError("PROPOSAL_NOT_PENDING", "Proposal is not pending")
            if now >= proposal.expires_at:
                transaction.save_proposal(
                    proposal.model_copy(update={"status": ProposalStatus.EXPIRED})
                )
                self._audit.append(
                    actor=approver.subject,
                    event_type="action.approve",
                    outcome="PROPOSAL_EXPIRED",
                    correlation_id=correlation_id,
                    metadata={"proposal_id": proposal_id},
                )
                deferred_error = ConflictError("PROPOSAL_EXPIRED", "Proposal has expired")
            else:
                current_digest = action_digest(proposal.action)
                if not hmac.compare_digest(
                    current_digest, proposal.action_digest
                ) or not hmac.compare_digest(expected_action_digest, proposal.action_digest):
                    self._audit.append(
                        actor=approver.subject,
                        event_type="action.approve",
                        outcome="ACTION_DIGEST_MISMATCH",
                        correlation_id=correlation_id,
                        metadata={"proposal_id": proposal_id},
                    )
                    deferred_error = ConflictError(
                        "ACTION_DIGEST_MISMATCH", "Action does not match the reviewed proposal"
                    )
                else:
                    policy_decision = self._policy.approve_action(
                        approver,
                        proposal.requester,
                        purpose,
                        proposal.action.facility_id,
                    )
                    self._audit.append(
                        actor=approver.subject,
                        event_type="action.approve",
                        outcome=(
                            (
                                "ACTION_APPROVED"
                                if decision is ApprovalDecision.APPROVE
                                else "ACTION_REJECTED"
                            )
                            if policy_decision.allowed
                            else policy_decision.code
                        ),
                        correlation_id=correlation_id,
                        metadata={
                            "proposal_id": proposal.proposal_id,
                            "decision": decision.value,
                            "policy_version": policy_decision.policy_version,
                        },
                    )
                    if not policy_decision.allowed:
                        deferred_error = AuthorizationError(policy_decision.code)
                    else:
                        new_status = (
                            ProposalStatus.APPROVED
                            if decision is ApprovalDecision.APPROVE
                            else ProposalStatus.REJECTED
                        )
                        approval_id = f"APR-{uuid4().hex}"
                        receipt_payload: dict[str, object] = {
                            "approval_id": approval_id,
                            "proposal_id": proposal.proposal_id,
                            "decision": decision,
                            "approver_subject": approver.subject,
                            "action_digest": proposal.action_digest,
                            "approved_at": now,
                            "expires_at": proposal.expires_at,
                            "policy_version": policy_decision.policy_version,
                        }
                        receipt = ApprovalReceipt(
                            approval_id=approval_id,
                            proposal_id=proposal.proposal_id,
                            decision=decision,
                            approver_subject=approver.subject,
                            action_digest=proposal.action_digest,
                            approved_at=now,
                            expires_at=proposal.expires_at,
                            policy_version=policy_decision.policy_version,
                            signature=self._sign_receipt(receipt_payload),
                        )
                        transaction.save_proposal(
                            proposal.model_copy(update={"status": new_status})
                        )
                        transaction.save_approval(receipt)
        if deferred_error is not None:
            raise deferred_error
        if receipt is None:
            raise StateIntegrityError
        return receipt.model_copy(deep=True)

    def execute(
        self,
        *,
        proposal_id: str,
        executor: Principal,
        purpose: PurposeOfUse,
        expected_action_digest: str,
        correlation_id: str,
    ) -> ActionExecutionResult:
        preflight_error: PolarisError | None = None
        preflight_result: ActionExecutionResult | None = None
        proposal: ActionProposal | None = None
        with self._state.transaction() as transaction:
            proposal = self._get_proposal(transaction, proposal_id)
            execution_decision = self._policy.execute_action(
                executor,
                purpose,
                proposal.action.facility_id,
            )
            if not execution_decision.allowed:
                self._audit.append(
                    actor=executor.subject,
                    event_type="action.execute",
                    outcome=execution_decision.code,
                    correlation_id=correlation_id,
                    metadata={"proposal_id": proposal_id},
                )
                preflight_error = AuthorizationError(execution_decision.code)
            else:
                existing = transaction.get_execution(proposal_id)
                if existing is not None:
                    self._audit.append(
                        actor=executor.subject,
                        event_type="action.execute",
                        outcome="ACTION_IDEMPOTENT_REPLAY",
                        correlation_id=correlation_id,
                        metadata={"proposal_id": proposal_id, "task_id": existing.task_id},
                    )
                    preflight_result = existing.model_copy(
                        update={"idempotent_replay": True}, deep=True
                    )
                elif proposal.status is not ProposalStatus.APPROVED:
                    self._audit.append(
                        actor=executor.subject,
                        event_type="action.execute",
                        outcome="PROPOSAL_NOT_APPROVED",
                        correlation_id=correlation_id,
                        metadata={"proposal_id": proposal_id},
                    )
                    preflight_error = ConflictError(
                        "PROPOSAL_NOT_APPROVED", "Proposal is not approved"
                    )
                else:
                    now = self._clock()
                    if now >= proposal.expires_at:
                        transaction.save_proposal(
                            proposal.model_copy(update={"status": ProposalStatus.EXPIRED})
                        )
                        self._audit.append(
                            actor=executor.subject,
                            event_type="action.execute",
                            outcome="PROPOSAL_EXPIRED",
                            correlation_id=correlation_id,
                            metadata={"proposal_id": proposal_id},
                        )
                        preflight_error = ConflictError("PROPOSAL_EXPIRED", "Proposal has expired")
                    else:
                        try:
                            self._validated_execution_receipt(
                                transaction,
                                proposal,
                                expected_action_digest,
                            )
                        except ConflictError as exc:
                            self._audit.append(
                                actor=executor.subject,
                                event_type="action.execute",
                                outcome=exc.code,
                                correlation_id=correlation_id,
                                metadata={"proposal_id": proposal_id},
                            )
                            preflight_error = exc
        if preflight_error is not None:
            raise preflight_error
        if preflight_result is not None:
            return preflight_result
        if proposal is None:
            raise StateIntegrityError

        patient = self._patients.authorized_patient(
            principal=proposal.requester,
            purpose=proposal.purpose,
            patient_id=proposal.action.patient_id,
            correlation_id=correlation_id,
        )
        requester_decision = self._policy.propose_action(
            proposal.requester, proposal.purpose, patient, proposal.action
        )
        if not requester_decision.allowed:
            self._audit.append(
                actor=executor.subject,
                event_type="action.execute",
                outcome="REQUESTER_REAUTHORIZATION_DENIED",
                correlation_id=correlation_id,
                metadata={"proposal_id": proposal_id},
            )
            raise AuthorizationError("REQUESTER_REAUTHORIZATION_DENIED")

        deferred_error: PolarisError | None = None
        result: ActionExecutionResult | None = None
        with self._state.transaction() as transaction:
            current = self._get_proposal(transaction, proposal_id)
            current_execution = transaction.get_execution(proposal_id)
            if current_execution is not None:
                self._audit.append(
                    actor=executor.subject,
                    event_type="action.execute",
                    outcome="ACTION_IDEMPOTENT_REPLAY",
                    correlation_id=correlation_id,
                    metadata={
                        "proposal_id": proposal_id,
                        "task_id": current_execution.task_id,
                    },
                )
                result = current_execution.model_copy(update={"idempotent_replay": True}, deep=True)
            else:
                final_execution_decision = self._policy.execute_action(
                    executor,
                    purpose,
                    current.action.facility_id,
                )
                if not final_execution_decision.allowed:
                    self._audit.append(
                        actor=executor.subject,
                        event_type="action.execute",
                        outcome=final_execution_decision.code,
                        correlation_id=correlation_id,
                        metadata={"proposal_id": proposal_id},
                    )
                    deferred_error = AuthorizationError(final_execution_decision.code)
                elif current.status is not ProposalStatus.APPROVED:
                    self._audit.append(
                        actor=executor.subject,
                        event_type="action.execute",
                        outcome="PROPOSAL_NOT_APPROVED",
                        correlation_id=correlation_id,
                        metadata={"proposal_id": proposal_id},
                    )
                    deferred_error = ConflictError(
                        "PROPOSAL_NOT_APPROVED", "Proposal is not approved"
                    )
                else:
                    now = self._clock()
                    if now >= current.expires_at:
                        transaction.save_proposal(
                            current.model_copy(update={"status": ProposalStatus.EXPIRED})
                        )
                        self._audit.append(
                            actor=executor.subject,
                            event_type="action.execute",
                            outcome="PROPOSAL_EXPIRED",
                            correlation_id=correlation_id,
                            metadata={"proposal_id": proposal_id},
                        )
                        deferred_error = ConflictError("PROPOSAL_EXPIRED", "Proposal has expired")
                    else:
                        try:
                            self._validated_execution_receipt(
                                transaction,
                                current,
                                expected_action_digest,
                            )
                        except ConflictError as exc:
                            self._audit.append(
                                actor=executor.subject,
                                event_type="action.execute",
                                outcome=exc.code,
                                correlation_id=correlation_id,
                                metadata={"proposal_id": proposal_id},
                            )
                            deferred_error = exc
                        else:
                            final_requester_decision = self._policy.propose_action(
                                current.requester,
                                current.purpose,
                                patient,
                                current.action,
                            )
                            if not final_requester_decision.allowed:
                                self._audit.append(
                                    actor=executor.subject,
                                    event_type="action.execute",
                                    outcome="REQUESTER_REAUTHORIZATION_DENIED",
                                    correlation_id=correlation_id,
                                    metadata={"proposal_id": proposal_id},
                                )
                                deferred_error = AuthorizationError(
                                    "REQUESTER_REAUTHORIZATION_DENIED"
                                )
                            else:
                                result = ActionExecutionResult(
                                    execution_id=f"EXE-{uuid4().hex}",
                                    proposal_id=proposal_id,
                                    task_id=f"TASK-{uuid4().hex}",
                                    executed_at=now,
                                    idempotent_replay=False,
                                )
                                transaction.save_execution(result)
                                transaction.save_proposal(
                                    current.model_copy(update={"status": ProposalStatus.EXECUTED})
                                )
                                self._audit.append(
                                    actor=executor.subject,
                                    event_type="action.execute",
                                    outcome="ACTION_EXECUTED",
                                    correlation_id=correlation_id,
                                    metadata={
                                        "proposal_id": proposal_id,
                                        "task_id": result.task_id,
                                        "policy_version": final_execution_decision.policy_version,
                                    },
                                )
        if deferred_error is not None:
            raise deferred_error
        if result is None:
            raise StateIntegrityError
        return result.model_copy(deep=True)

    def get_proposal(self, proposal_id: str) -> ActionProposal:
        with self._state.transaction() as transaction:
            return self._get_proposal(transaction, proposal_id).model_copy(deep=True)

    def _get_proposal(
        self,
        transaction: StateTransaction,
        proposal_id: str,
    ) -> ActionProposal:
        proposal = transaction.get_proposal(proposal_id)
        if proposal is None:
            raise NotFoundError("PROPOSAL_NOT_FOUND")
        return proposal

    def _validated_execution_receipt(
        self,
        transaction: StateTransaction,
        proposal: ActionProposal,
        expected_action_digest: str,
    ) -> ApprovalReceipt:
        receipt = transaction.get_approval(proposal.proposal_id)
        if receipt is None or receipt.decision is not ApprovalDecision.APPROVE:
            raise ConflictError("APPROVAL_NOT_AVAILABLE", "Valid approval is not available")
        if (
            not self._verify_receipt(receipt)
            or receipt.proposal_id != proposal.proposal_id
            or receipt.approver_subject == proposal.requester.subject
            or receipt.expires_at != proposal.expires_at
            or not proposal.created_at <= receipt.approved_at < receipt.expires_at
        ):
            raise ConflictError("APPROVAL_INTEGRITY_FAILURE", "Approval integrity check failed")
        current_digest = action_digest(proposal.action)
        if not all(
            hmac.compare_digest(candidate, proposal.action_digest)
            for candidate in (expected_action_digest, current_digest, receipt.action_digest)
        ):
            raise ConflictError(
                "ACTION_DIGEST_MISMATCH", "Action does not match the approved proposal"
            )
        return receipt

    def _sign_receipt(self, payload: Mapping[str, object]) -> str:
        canonical = _canonical_receipt_payload(payload)
        return hmac.new(self._signing_key, canonical, hashlib.sha256).hexdigest()

    def _verify_receipt(self, receipt: ApprovalReceipt) -> bool:
        payload: dict[str, object] = {
            "approval_id": receipt.approval_id,
            "proposal_id": receipt.proposal_id,
            "decision": receipt.decision,
            "approver_subject": receipt.approver_subject,
            "action_digest": receipt.action_digest,
            "approved_at": receipt.approved_at,
            "expires_at": receipt.expires_at,
            "policy_version": receipt.policy_version,
        }
        return hmac.compare_digest(receipt.signature, self._sign_receipt(payload))


def action_digest(action: FollowUpAction) -> str:
    canonical = json.dumps(
        action.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _canonical_receipt_payload(payload: Mapping[str, object]) -> bytes:
    serializable: dict[str, object] = {}
    for key, value in payload.items():
        if isinstance(value, datetime):
            serializable[key] = value.astimezone(UTC).isoformat()
        elif isinstance(value, ApprovalDecision):
            serializable[key] = value.value
        else:
            serializable[key] = value
    return json.dumps(
        serializable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()

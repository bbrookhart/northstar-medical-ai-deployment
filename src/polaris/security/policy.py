from __future__ import annotations

from typing import Protocol

from polaris.domain import (
    AuthorizationOperation,
    AuthorizationRequest,
    ConsentDecision,
    DataSensitivity,
    Decision,
    FollowUpAction,
    Principal,
    PurposeOfUse,
    SyntheticPatient,
)


class PatientPolicyContext(Protocol):
    patient_id: str
    facility_id: str
    sensitivities: frozenset[DataSensitivity]
    consent_decision: ConsentDecision


class PolicyEngine:
    """Central, deterministic, deny-by-default authorization decision point."""

    VERSION = "NS-POL-2026.08.11-3"

    _POLICY_ROLES = frozenset({"care_coordinator", "nurse", "compliance_analyst"})
    _PATIENT_ROLES = frozenset({"care_coordinator", "nurse"})
    _PATIENT_PURPOSES = frozenset({PurposeOfUse.TREATMENT, PurposeOfUse.HEALTHCARE_OPERATIONS})

    def authorize(self, request: AuthorizationRequest) -> Decision:
        match request.operation:
            case AuthorizationOperation.POLICY_QUERY:
                return self._policy_query(request)
            case AuthorizationOperation.PATIENT_READ:
                return self._patient_read(request)
            case AuthorizationOperation.ACTION_PROPOSE:
                return self._propose_action(request)
            case AuthorizationOperation.ACTION_APPROVE:
                return self._approve_action(request)
            case AuthorizationOperation.ACTION_EXECUTE:
                return self._execute_action(request)
            case AuthorizationOperation.AUDIT_READ:
                return self._audit_read(request)
        return self._decision(False, "", "POLICY_OPERATION_DENIED")

    def policy_query(self, principal: Principal, purpose: PurposeOfUse) -> Decision:
        return self.authorize(
            AuthorizationRequest(
                principal=principal,
                purpose=purpose,
                operation=AuthorizationOperation.POLICY_QUERY,
            )
        )

    def patient_read(
        self,
        principal: Principal,
        purpose: PurposeOfUse,
        patient: PatientPolicyContext,
    ) -> Decision:
        return self.authorize(
            AuthorizationRequest(
                principal=principal,
                purpose=purpose,
                operation=AuthorizationOperation.PATIENT_READ,
                patient_id=patient.patient_id,
                facility_id=patient.facility_id,
                sensitivities=patient.sensitivities,
                consent_decision=patient.consent_decision,
            )
        )

    def propose_action(
        self,
        principal: Principal,
        purpose: PurposeOfUse,
        patient: SyntheticPatient,
        action: FollowUpAction,
    ) -> Decision:
        return self.authorize(
            AuthorizationRequest(
                principal=principal,
                purpose=purpose,
                operation=AuthorizationOperation.ACTION_PROPOSE,
                patient_id=patient.patient_id,
                facility_id=patient.facility_id,
                sensitivities=patient.sensitivities,
                consent_decision=patient.consent_decision,
                action_patient_id=action.patient_id,
                action_facility_id=action.facility_id,
            )
        )

    def approve_action(
        self,
        approver: Principal,
        requester: Principal,
        purpose: PurposeOfUse,
        facility_id: str,
    ) -> Decision:
        return self.authorize(
            AuthorizationRequest(
                principal=approver,
                purpose=purpose,
                operation=AuthorizationOperation.ACTION_APPROVE,
                facility_id=facility_id,
                requester_subject=requester.subject,
            )
        )

    def execute_action(
        self,
        executor: Principal,
        purpose: PurposeOfUse,
        facility_id: str,
    ) -> Decision:
        return self.authorize(
            AuthorizationRequest(
                principal=executor,
                purpose=purpose,
                operation=AuthorizationOperation.ACTION_EXECUTE,
                facility_id=facility_id,
            )
        )

    def audit_read(self, principal: Principal, purpose: PurposeOfUse) -> Decision:
        return self.authorize(
            AuthorizationRequest(
                principal=principal,
                purpose=purpose,
                operation=AuthorizationOperation.AUDIT_READ,
            )
        )

    def _policy_query(self, request: AuthorizationRequest) -> Decision:
        allowed = (
            "polaris.policy.read" in request.principal.scopes
            and bool(request.principal.roles & self._POLICY_ROLES)
            and request.purpose
            in {
                PurposeOfUse.TREATMENT,
                PurposeOfUse.HEALTHCARE_OPERATIONS,
                PurposeOfUse.SECURITY,
                PurposeOfUse.TRAINING,
            }
        )
        return self._decision(
            allowed,
            "POLICY_QUERY_ALLOWED",
            "POLICY_QUERY_DENIED",
            obligations={"policy.citations_required", "policy.abstain_if_unsupported"},
        )

    def _patient_read(self, request: AuthorizationRequest) -> Decision:
        principal = request.principal
        if (
            request.patient_id is None
            or request.facility_id is None
            or not request.sensitivities
            or request.consent_decision is None
        ):
            return self._decision(False, "", "PATIENT_CONTEXT_DENIED")
        if "polaris.patient.read" not in principal.scopes:
            return self._decision(False, "", "PATIENT_SCOPE_DENIED")
        if not principal.roles & self._PATIENT_ROLES:
            return self._decision(False, "", "PATIENT_ROLE_DENIED")
        if request.purpose not in self._PATIENT_PURPOSES:
            return self._decision(False, "", "PATIENT_PURPOSE_DENIED")
        if request.facility_id not in principal.facilities:
            return self._decision(False, "", "PATIENT_FACILITY_DENIED")
        if request.patient_id not in principal.assigned_patients:
            return self._decision(False, "", "PATIENT_RELATIONSHIP_DENIED")
        if request.consent_decision is ConsentDecision.UNKNOWN:
            return self._decision(False, "", "PATIENT_CONSENT_UNKNOWN_DENIED")
        if request.consent_decision is ConsentDecision.DENY:
            return self._decision(False, "", "PATIENT_CONSENT_DENIED")
        if (
            DataSensitivity.SUD_PART2 in request.sensitivities
            and "part2_authorized" not in principal.roles
        ):
            return self._decision(False, "", "PATIENT_PART2_DENIED")
        return self._decision(
            True,
            "PATIENT_READ_ALLOWED",
            "",
            obligations={"patient.minimum_summary", "patient.no_raw_narrative"},
        )

    def _propose_action(self, request: AuthorizationRequest) -> Decision:
        if request.action_patient_id is None or request.action_facility_id is None:
            return self._decision(False, "", "ACTION_CONTEXT_DENIED")
        if "polaris.task.propose" not in request.principal.scopes:
            return self._decision(False, "", "ACTION_PROPOSER_SCOPE_DENIED")
        patient_decision = self._patient_read(
            request.model_copy(update={"operation": AuthorizationOperation.PATIENT_READ})
        )
        if not patient_decision.allowed:
            return patient_decision
        if not request.principal.roles & self._PATIENT_ROLES:
            return self._decision(False, "", "ACTION_PROPOSER_ROLE_DENIED")
        if (
            request.action_patient_id != request.patient_id
            or request.action_facility_id != request.facility_id
        ):
            return self._decision(False, "", "ACTION_TARGET_MISMATCH")
        return self._decision(
            True,
            "ACTION_PROPOSAL_ALLOWED",
            "",
            obligations={"action.independent_approval", "action.exact_digest"},
        )

    def _approve_action(self, request: AuthorizationRequest) -> Decision:
        principal = request.principal
        if request.facility_id is None or request.requester_subject is None:
            return self._decision(False, "", "APPROVER_CONTEXT_DENIED")
        if request.purpose is not PurposeOfUse.HEALTHCARE_OPERATIONS:
            return self._decision(False, "", "APPROVAL_PURPOSE_DENIED")
        if "polaris.task.approve" not in principal.scopes:
            return self._decision(False, "", "APPROVER_SCOPE_DENIED")
        if "task_approver" not in principal.roles:
            return self._decision(False, "", "APPROVER_ROLE_DENIED")
        if principal.subject == request.requester_subject:
            return self._decision(False, "", "APPROVER_INDEPENDENCE_DENIED")
        if request.facility_id not in principal.facilities:
            return self._decision(False, "", "APPROVER_FACILITY_DENIED")
        return self._decision(
            True,
            "ACTION_APPROVAL_ALLOWED",
            "",
            obligations={"action.exact_digest", "action.approval_expiry"},
        )

    def _execute_action(self, request: AuthorizationRequest) -> Decision:
        if request.facility_id is None:
            return self._decision(False, "", "EXECUTOR_CONTEXT_DENIED")
        allowed = (
            request.purpose is PurposeOfUse.HEALTHCARE_OPERATIONS
            and "polaris.task.execute" in request.principal.scopes
            and "task_executor" in request.principal.roles
            and request.facility_id in request.principal.facilities
        )
        return self._decision(
            allowed,
            "ACTION_EXECUTION_ALLOWED",
            "ACTION_EXECUTION_DENIED",
            obligations={"action.reauthorize_requester", "action.idempotent_execution"},
        )

    def _audit_read(self, request: AuthorizationRequest) -> Decision:
        allowed = (
            request.purpose is PurposeOfUse.SECURITY
            and "polaris.audit.read" in request.principal.scopes
            and "security_analyst" in request.principal.roles
        )
        return self._decision(
            allowed,
            "AUDIT_READ_ALLOWED",
            "AUDIT_ACCESS_DENIED",
            obligations={"audit.no_raw_restricted_content"},
        )

    @classmethod
    def _decision(
        cls,
        allowed: bool,
        allow_code: str,
        deny_code: str,
        *,
        obligations: set[str] | None = None,
    ) -> Decision:
        return Decision(
            allowed=allowed,
            code=allow_code if allowed else deny_code,
            policy_version=cls.VERSION,
            obligations=frozenset(obligations or ()) if allowed else frozenset(),
        )

from __future__ import annotations

import pytest

from polaris.domain import (
    AuthorizationOperation,
    AuthorizationRequest,
    ConsentDecision,
    DataSensitivity,
    Principal,
    PurposeOfUse,
)
from polaris.security.policy import PolicyEngine


def _principal() -> Principal:
    return Principal(
        subject="user-care-1",
        token_id="tok-policy-1",
        client_id="polaris-web",
        scopes=frozenset(
            {
                "polaris.policy.read",
                "polaris.patient.read",
                "polaris.task.propose",
                "polaris.task.approve",
                "polaris.task.execute",
                "polaris.audit.read",
            }
        ),
        roles=frozenset({"care_coordinator"}),
        facilities=frozenset({"FAC-NORTH"}),
        assigned_patients=frozenset({"SYN-P1001"}),
    )


@pytest.mark.parametrize(
    ("operation", "expected_code"),
    [
        (AuthorizationOperation.PATIENT_READ, "PATIENT_CONTEXT_DENIED"),
        (AuthorizationOperation.ACTION_PROPOSE, "ACTION_CONTEXT_DENIED"),
        (AuthorizationOperation.ACTION_APPROVE, "APPROVER_CONTEXT_DENIED"),
        (AuthorizationOperation.ACTION_EXECUTE, "EXECUTOR_CONTEXT_DENIED"),
    ],
)
def test_central_contract_denies_missing_operation_context(
    operation: AuthorizationOperation, expected_code: str
) -> None:
    decision = PolicyEngine().authorize(
        AuthorizationRequest(
            principal=_principal(),
            purpose=PurposeOfUse.HEALTHCARE_OPERATIONS,
            operation=operation,
        )
    )

    assert decision.allowed is False
    assert decision.code == expected_code
    assert decision.obligations == frozenset()
    assert decision.policy_version == PolicyEngine.VERSION


def test_patient_allow_decision_returns_enforceable_minimization_obligations() -> None:
    decision = PolicyEngine().authorize(
        AuthorizationRequest(
            principal=_principal(),
            purpose=PurposeOfUse.TREATMENT,
            operation=AuthorizationOperation.PATIENT_READ,
            patient_id="SYN-P1001",
            facility_id="FAC-NORTH",
            sensitivities=frozenset({DataSensitivity.GENERAL}),
            consent_decision=ConsentDecision.PERMIT,
        )
    )

    assert decision.allowed is True
    assert decision.code == "PATIENT_READ_ALLOWED"
    assert decision.obligations == frozenset(
        {"patient.minimum_summary", "patient.no_raw_narrative"}
    )

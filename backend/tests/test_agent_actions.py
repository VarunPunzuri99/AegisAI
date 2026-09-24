"""Action risk classification and intent alignment unit tests."""

from __future__ import annotations

from app.agents.action_risk import ACTION_RISK_MAP, classify_action_risk
from app.agents.intent_alignment import check_intent_alignment
from app.agents.types import ActionRiskLevel, ActionType


def test_read_search_low() -> None:
    assert classify_action_risk(ActionType.SEARCH_DOCUMENTS) == ActionRiskLevel.LOW
    assert classify_action_risk(ActionType.READ_PUBLIC_DATA) == ActionRiskLevel.LOW


def test_write_medium() -> None:
    assert classify_action_risk(ActionType.WRITE_DATA) == ActionRiskLevel.MEDIUM
    assert classify_action_risk(ActionType.READ_PRIVATE_DATA) == ActionRiskLevel.MEDIUM


def test_external_mutation_high() -> None:
    assert classify_action_risk(ActionType.EXTERNAL_API_MUTATION) == ActionRiskLevel.HIGH
    assert classify_action_risk(ActionType.SEND_EMAIL) == ActionRiskLevel.HIGH


def test_delete_financial_credential_critical() -> None:
    assert classify_action_risk(ActionType.DELETE_DATA) == ActionRiskLevel.CRITICAL
    assert classify_action_risk(ActionType.FINANCIAL_TRANSACTION) == ActionRiskLevel.CRITICAL
    assert classify_action_risk(ActionType.CREDENTIAL_CHANGE) == ActionRiskLevel.CRITICAL


def test_all_action_types_classified() -> None:
    for action in ActionType:
        risk = classify_action_risk(action)
        assert risk in ActionRiskLevel
        assert ACTION_RISK_MAP[action] == risk


def test_intent_alignment_pto_vs_email() -> None:
    assert (
        check_intent_alignment("Find the employee PTO policy.", ActionType.SEND_EMAIL)
        is False
    )


def test_intent_alignment_search_ok() -> None:
    assert (
        check_intent_alignment("Find the employee PTO policy.", ActionType.SEARCH_DOCUMENTS)
        is True
    )


def test_intent_alignment_missing_intent_true() -> None:
    # No evidence of mismatch — not treated as authorization.
    assert check_intent_alignment(None, ActionType.DELETE_DATA) is True
    assert check_intent_alignment("", ActionType.SEND_EMAIL) is True


def test_intent_email_with_email_intent() -> None:
    assert (
        check_intent_alignment("Please email HR about PTO.", ActionType.SEND_EMAIL)
        is True
    )


def test_prompt_risk_independent_of_action_risk() -> None:
    """Document the dual-risk model: classification does not use prompt score."""
    # Benign prompt could still request CRITICAL action — classification unchanged.
    assert classify_action_risk(ActionType.DELETE_DATA) == ActionRiskLevel.CRITICAL
    # Attack prompt does not change search risk.
    assert classify_action_risk(ActionType.SEARCH_DOCUMENTS) == ActionRiskLevel.LOW

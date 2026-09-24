"""Deterministic action-risk classification (no tools, no LLM)."""

from __future__ import annotations

from app.agents.types import ActionRiskLevel, ActionType


# Intrinsic action risk — independent of prompt risk score.
ACTION_RISK_MAP: dict[ActionType, ActionRiskLevel] = {
    ActionType.SEARCH_DOCUMENTS: ActionRiskLevel.LOW,
    ActionType.READ_PUBLIC_DATA: ActionRiskLevel.LOW,
    ActionType.READ_PRIVATE_DATA: ActionRiskLevel.MEDIUM,
    ActionType.WRITE_DATA: ActionRiskLevel.MEDIUM,
    ActionType.EXTERNAL_API_MUTATION: ActionRiskLevel.HIGH,
    ActionType.SEND_EMAIL: ActionRiskLevel.HIGH,
    ActionType.DELETE_DATA: ActionRiskLevel.CRITICAL,
    ActionType.FINANCIAL_TRANSACTION: ActionRiskLevel.CRITICAL,
    ActionType.CREDENTIAL_CHANGE: ActionRiskLevel.CRITICAL,
    ActionType.UNKNOWN: ActionRiskLevel.HIGH,
}


def classify_action_risk(action_type: ActionType) -> ActionRiskLevel:
    """Return the intrinsic risk level for an action type."""
    return ACTION_RISK_MAP.get(action_type, ActionRiskLevel.HIGH)


def action_requires_target(action_type: ActionType) -> bool:
    """Whether a non-empty target is required before READY_FOR_TOOL_GUARD."""
    return action_type not in {
        ActionType.UNKNOWN,
    }

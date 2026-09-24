"""Deterministic intent/action alignment hooks (no LLM judge)."""

from __future__ import annotations

from app.agents.types import ActionType

# Coarse intent keyword buckets for Phase 9 mismatch detection.
_READ_INTENT = (
    "find",
    "search",
    "lookup",
    "read",
    "show",
    "get",
    "retrieve",
    "pto",
    "policy",
    "document",
    "report",
)
_WRITE_INTENT = ("write", "update", "save", "create", "edit")
_EMAIL_INTENT = ("email", "send mail", "notify", "message")
_DELETE_INTENT = ("delete", "remove", "drop", "erase")
_FINANCE_INTENT = ("pay", "transfer", "invoice", "purchase", "refund")
_CREDENTIAL_INTENT = ("password", "credential", "permission", "role change", "api key")

_ACTION_EXPECTED: dict[ActionType, tuple[str, ...]] = {
    ActionType.SEARCH_DOCUMENTS: _READ_INTENT,
    ActionType.READ_PUBLIC_DATA: _READ_INTENT,
    ActionType.READ_PRIVATE_DATA: _READ_INTENT,
    ActionType.WRITE_DATA: _WRITE_INTENT,
    ActionType.SEND_EMAIL: _EMAIL_INTENT,
    ActionType.DELETE_DATA: _DELETE_INTENT,
    ActionType.FINANCIAL_TRANSACTION: _FINANCE_INTENT,
    ActionType.CREDENTIAL_CHANGE: _CREDENTIAL_INTENT,
    ActionType.EXTERNAL_API_MUTATION: (),
    ActionType.UNKNOWN: (),
}

# Actions that conflict with read-only intent language.
_MUTATING_ACTIONS = frozenset(
    {
        ActionType.WRITE_DATA,
        ActionType.EXTERNAL_API_MUTATION,
        ActionType.SEND_EMAIL,
        ActionType.DELETE_DATA,
        ActionType.FINANCIAL_TRANSACTION,
        ActionType.CREDENTIAL_CHANGE,
    }
)


def check_intent_alignment(
    declared_intent: str | None,
    action_type: ActionType,
) -> bool:
    """
    Return False when declared intent clearly mismatches the proposed action.

    Missing intent → True (no evidence of mismatch; not authorization).
    LLM-generated intent is never treated as authorization.
    """
    if not declared_intent or not declared_intent.strip():
        return True

    text = declared_intent.lower().strip()
    expected = _ACTION_EXPECTED.get(action_type, ())

    # Read-oriented intent + mutating action → mismatch
    if any(k in text for k in _READ_INTENT) and action_type in _MUTATING_ACTIONS:
        # Exception: intent also clearly asks for the mutating action
        if expected and any(k in text for k in expected):
            return True
        return False

    # If we have expected keywords for this action and none appear, soft mismatch
    # only when intent is specific enough (length) and action is mutating.
    if expected and action_type in _MUTATING_ACTIONS:
        if not any(k in text for k in expected):
            return False

    return True

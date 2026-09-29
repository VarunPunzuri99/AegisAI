"""Authorization matrix evaluation against Phase 10 tool firewall."""

from __future__ import annotations

from uuid import uuid4

from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal
from app.core.enums import Severity
from app.security.fusion_types import EvidenceLabel, UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.security.policy_engine import evaluate_policy
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState, ToolFirewallVerdict, ToolSecurityContext

# role/permission → tool → expected decision
AUTH_MATRIX: list[dict] = [
    {
        "id": "AM-001",
        "permissions": ["documents:public:read"],
        "tool": "search_public_documents",
        "action": ActionType.SEARCH_DOCUMENTS,
        "target": "public_documents",
        "params": {"query": "PTO", "limit": 5},
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.ALLOW,
    },
    {
        "id": "AM-002",
        "permissions": ["documents:public:read"],
        "tool": "read_public_document",
        "action": ActionType.READ_PUBLIC_DATA,
        "target": "public_documents",
        "params": {"document_id": "pub-1"},
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.ALLOW,
    },
    {
        "id": "AM-003",
        "permissions": ["documents:public:read"],
        "tool": "read_private_document",
        "action": ActionType.READ_PRIVATE_DATA,
        "target": "private_documents",
        "params": {"document_id": "priv-1"},
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.DENY,
    },
    {
        "id": "AM-004",
        "permissions": ["documents:private:read"],
        "tool": "read_private_document",
        "action": ActionType.READ_PRIVATE_DATA,
        "target": "private_documents",
        "params": {"document_id": "priv-1"},
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.ALLOW,
    },
    {
        "id": "AM-005",
        "permissions": ["records:write"],
        "tool": "write_record",
        "action": ActionType.WRITE_DATA,
        "target": "notes",
        "params": {"record_id": "n1", "content": "hello"},
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.ALLOW,
    },
    {
        "id": "AM-006",
        "permissions": ["records:write"],
        "tool": "delete_record",
        "action": ActionType.DELETE_DATA,
        "target": "notes",
        "params": {"record_id": "n1"},
        "approval": ApprovalState.APPROVED,
        "expected": ToolFirewallVerdict.DENY,
        "intent": "Please delete the note.",
    },
    {
        "id": "AM-007",
        "permissions": ["email:send"],
        "tool": "send_email",
        "action": ActionType.SEND_EMAIL,
        "target": "email",
        "params": {
            "recipient": "hr@example.com",
            "subject": "PTO",
            "body": "Please send PTO policy.",
        },
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.REQUIRES_APPROVAL,
        "intent": "Please email HR about PTO.",
    },
    {
        "id": "AM-008",
        "permissions": ["records:delete"],
        "tool": "delete_record",
        "action": ActionType.DELETE_DATA,
        "target": "notes",
        "params": {"record_id": "n1"},
        "approval": ApprovalState.NOT_REQUIRED,
        "expected": ToolFirewallVerdict.REQUIRES_APPROVAL,
        "intent": "Please delete the note.",
    },
]


def run_authorization_matrix() -> tuple[int, int, list[dict]]:
    """Returns (passed, total, failure details)."""
    fw = ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry())
    policy = PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="auth matrix fixture",
    )
    passed = 0
    failures: list[dict] = []
    for row in AUTH_MATRIX:
        proposal = AgentActionProposal(
            action_type=row["action"],
            target=row["target"],
            parameters=dict(row["params"]),
            action_risk=ActionRiskLevel.LOW,
            reason="auth matrix",
            intent_alignment=True,
            declared_intent=row.get("intent"),
        )
        # Fix action_risk to match tool
        from app.agents.action_risk import classify_action_risk

        proposal = AgentActionProposal(
            action_id=proposal.action_id,
            action_type=row["action"],
            target=row["target"],
            parameters=dict(row["params"]),
            action_risk=classify_action_risk(row["action"]),
            reason="auth matrix",
            intent_alignment=True,
            declared_intent=row.get("intent"),
        )
        ctx = ToolSecurityContext(
            user_id="matrix-user",
            session_id=uuid4(),
            permissions=frozenset(row["permissions"]),
            approval_state=row["approval"],
        )
        decision = fw.authorize_tool_call(
            proposal=proposal,
            tool_name=row["tool"],
            security_context=ctx,
            policy_decision=policy,
        )
        if decision.decision == row["expected"]:
            passed += 1
        else:
            failures.append(
                {
                    "id": row["id"],
                    "expected": row["expected"].value,
                    "actual": decision.decision.value,
                    "reason_codes": list(decision.reason_codes),
                }
            )
    return passed, len(AUTH_MATRIX), failures

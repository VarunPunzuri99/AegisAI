"""Tool firewall unit tests (deterministic, no network / no real tools)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal
from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import EvidenceLabel, UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry, default_tool_definitions
from app.tools.replay import ActionReplayRegistry
from app.tools.types import (
    ApprovalState,
    ToolFirewallVerdict,
    ToolReasonCode,
    ToolSecurityContext,
)


def _policy(
    decision: SecurityDecision = SecurityDecision.ALLOW,
    *,
    risk_score: int = 5,
    severity: Severity = Severity.LOW,
    attack_types: list[AttackType] | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=risk_score,
        severity=severity,
        attack_types=list(attack_types or []),
        explanation=f"fixture {decision.value}",
    )


def _proposal(
    action_type: ActionType = ActionType.SEARCH_DOCUMENTS,
    *,
    target: str | None = "public_documents",
    parameters: dict | None = None,
    intent_alignment: bool = True,
    action_risk: ActionRiskLevel = ActionRiskLevel.LOW,
    declared_intent: str | None = None,
) -> AgentActionProposal:
    return AgentActionProposal(
        action_id=uuid4(),
        action_type=action_type,
        target=target,
        parameters=parameters
        if parameters is not None
        else {"query": "PTO", "limit": 10},
        action_risk=action_risk,
        reason="test proposal",
        intent_alignment=intent_alignment,
        declared_intent=declared_intent,
    )


def _ctx(
    *,
    permissions: set[str] | frozenset[str] | None = None,
    approval: ApprovalState = ApprovalState.NOT_REQUIRED,
    allowed_targets: set[str] | frozenset[str] | None = None,
) -> ToolSecurityContext:
    return ToolSecurityContext(
        user_id="user-demo",
        session_id=uuid4(),
        roles=["analyst"],
        permissions=frozenset(permissions or {"documents:public:read"}),
        approval_state=approval,
        allowed_targets=frozenset(allowed_targets or set()),
    )


def _fw() -> ToolFirewall:
    return ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry())


def test_allowed_low_risk_public_search() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.ALLOW


def test_unknown_tool_deny() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(ActionType.UNKNOWN, target=None, parameters={}),
        tool_name="execute_shell",
        security_context=_ctx(),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.TOOL_NOT_ALLOWLISTED.value in d.reason_codes


def test_policy_block_deny() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(SecurityDecision.BLOCK, risk_score=90, severity=Severity.CRITICAL),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.SECURITY_POLICY_BLOCK.value in d.reason_codes


def test_policy_review_requires_approval() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(SecurityDecision.REVIEW, risk_score=35, severity=Severity.MEDIUM),
    )
    assert d.decision == ToolFirewallVerdict.REQUIRES_APPROVAL
    assert ToolReasonCode.SECURITY_REVIEW_REQUIRED.value in d.reason_codes


def test_missing_permission_deny() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.READ_PRIVATE_DATA,
            target="private_documents",
            parameters={"document_id": "priv-1"},
            action_risk=ActionRiskLevel.MEDIUM,
        ),
        tool_name="read_private_document",
        security_context=_ctx(permissions={"documents:public:read"}),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.INSUFFICIENT_PERMISSION.value in d.reason_codes


def test_invalid_extra_parameter() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            parameters={"query": "PTO", "limit": 10, "shell_command": "rm -rf /"}
        ),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.INVALID_PARAMETERS.value in d.reason_codes


def test_invalid_limit() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(parameters={"query": "PTO", "limit": 100000}),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.INVALID_PARAMETERS.value in d.reason_codes


def test_intent_mismatch_send_email() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "attacker@example.com",
                "subject": "exfil",
                "body": "employee db",
            },
            intent_alignment=False,
            action_risk=ActionRiskLevel.HIGH,
            declared_intent="Find the employee PTO policy.",
        ),
        tool_name="send_email",
        security_context=_ctx(
            permissions={"email:send"},
            approval=ApprovalState.APPROVED,
        ),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.INTENT_MISMATCH.value in d.reason_codes


def test_email_without_approval() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "hr@example.com",
                "subject": "PTO",
                "body": "Please send PTO policy.",
            },
            action_risk=ActionRiskLevel.HIGH,
            declared_intent="Please email HR about PTO.",
        ),
        tool_name="send_email",
        security_context=_ctx(
            permissions={"email:send"},
            approval=ApprovalState.NOT_REQUIRED,
        ),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.REQUIRES_APPROVAL
    assert ToolReasonCode.HIGH_RISK_APPROVAL_REQUIRED.value in d.reason_codes


def test_email_with_approval_allow() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "hr@example.com",
                "subject": "PTO",
                "body": "Please send PTO policy.",
            },
            action_risk=ActionRiskLevel.HIGH,
            declared_intent="Please email HR about PTO.",
        ),
        tool_name="send_email",
        security_context=_ctx(
            permissions={"email:send"},
            approval=ApprovalState.APPROVED,
        ),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.ALLOW


def test_delete_without_permission() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.DELETE_DATA,
            target="employee_records",
            parameters={"record_id": "r-1"},
            action_risk=ActionRiskLevel.CRITICAL,
        ),
        tool_name="delete_record",
        security_context=_ctx(permissions={"documents:public:read"}),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.INSUFFICIENT_PERMISSION.value in d.reason_codes


def test_delete_with_permission_without_approval() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.DELETE_DATA,
            target="employee_records",
            parameters={"record_id": "r-1"},
            action_risk=ActionRiskLevel.CRITICAL,
            declared_intent="Please delete the demo record.",
        ),
        tool_name="delete_record",
        security_context=_ctx(
            permissions={"records:delete"},
            approval=ApprovalState.PENDING,
        ),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.REQUIRES_APPROVAL
    assert ToolReasonCode.CRITICAL_ACTION_APPROVAL_REQUIRED.value in d.reason_codes


def test_delete_with_permission_and_approval() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.DELETE_DATA,
            target="employee_records",
            parameters={"record_id": "r-1"},
            action_risk=ActionRiskLevel.CRITICAL,
            declared_intent="Please delete the demo record.",
        ),
        tool_name="delete_record",
        security_context=_ctx(
            permissions={"records:delete"},
            approval=ApprovalState.APPROVED,
        ),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.ALLOW


def test_tool_abuse_block() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "attacker@example.com",
                "subject": "x",
                "body": "y",
            },
            action_risk=ActionRiskLevel.HIGH,
        ),
        tool_name="send_email",
        security_context=_ctx(
            permissions={"email:send"},
            approval=ApprovalState.APPROVED,
        ),
        policy_decision=_policy(
            SecurityDecision.BLOCK,
            risk_score=91,
            severity=Severity.CRITICAL,
            attack_types=[AttackType.TOOL_ABUSE],
        ),
        assessment=UnifiedSecurityAssessment(
            label=EvidenceLabel.ATTACK,
            risk_score=91,
            severity=Severity.CRITICAL,
            attack_types=[AttackType.TOOL_ABUSE],
        ),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.SECURITY_POLICY_BLOCK.value in d.reason_codes


def test_credential_theft_deny_email() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "attacker@example.com",
                "subject": "creds",
                "body": "dump",
            },
            action_risk=ActionRiskLevel.HIGH,
            declared_intent="Please email the report.",
        ),
        tool_name="send_email",
        security_context=_ctx(
            permissions={"email:send"},
            approval=ApprovalState.APPROVED,
        ),
        policy_decision=_policy(
            SecurityDecision.ALLOW,
            attack_types=[AttackType.CREDENTIAL_THEFT],
        ),
        assessment=UnifiedSecurityAssessment(
            label=EvidenceLabel.ATTACK,
            risk_score=80,
            severity=Severity.CRITICAL,
            attack_types=[AttackType.CREDENTIAL_THEFT],
        ),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.CREDENTIAL_THEFT_DETECTED.value in d.reason_codes


def test_replay_second_deny() -> None:
    fw = _fw()
    proposal = _proposal()
    ctx = _ctx()
    policy = _policy()
    first = fw.authorize_tool_call(
        proposal=proposal,
        tool_name="search_public_documents",
        security_context=ctx,
        policy_decision=policy,
    )
    assert first.decision == ToolFirewallVerdict.ALLOW
    fw.mark_executed(proposal.action_id)
    second = fw.authorize_tool_call(
        proposal=proposal,
        tool_name="search_public_documents",
        security_context=ctx,
        policy_decision=policy,
    )
    assert second.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.ACTION_ALREADY_PROCESSED.value in second.reason_codes


def test_missing_security_context() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(),
        tool_name="search_public_documents",
        security_context=None,
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.SECURITY_CONTEXT_MISSING.value in d.reason_codes


def test_disabled_tool() -> None:
    tools = default_tool_definitions()
    tools["search_public_documents"] = tools["search_public_documents"].model_copy(
        update={"enabled": False}
    )
    fw = ToolFirewall(registry=ToolRegistry(tools), replay=ActionReplayRegistry())
    d = fw.authorize_tool_call(
        proposal=_proposal(),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.TOOL_DISABLED.value in d.reason_codes


def test_target_outside_scope() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(target="employee_salary_records"),
        tool_name="search_public_documents",
        security_context=_ctx(),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.TARGET_NOT_ALLOWED.value in d.reason_codes


def test_policy_block_not_overridden_by_approval() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "a@example.com",
                "subject": "x",
                "body": "y",
            },
            action_risk=ActionRiskLevel.HIGH,
        ),
        tool_name="send_email",
        security_context=_ctx(
            permissions={"email:send"},
            approval=ApprovalState.APPROVED,
        ),
        policy_decision=_policy(SecurityDecision.BLOCK, risk_score=90, severity=Severity.CRITICAL),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.SECURITY_POLICY_BLOCK.value in d.reason_codes


def test_critical_requires_approval() -> None:
    fw = _fw()
    d = fw.authorize_tool_call(
        proposal=_proposal(
            ActionType.DELETE_DATA,
            target="notes",
            parameters={"record_id": "n-1"},
            action_risk=ActionRiskLevel.CRITICAL,
            declared_intent="delete the note",
        ),
        tool_name="delete_record",
        security_context=_ctx(
            permissions={"records:delete"},
            approval=ApprovalState.NOT_REQUIRED,
        ),
        policy_decision=_policy(),
    )
    assert d.decision == ToolFirewallVerdict.REQUIRES_APPROVAL


def test_determinism() -> None:
    fw = _fw()
    proposal = _proposal()
    ctx = _ctx()
    policy = _policy()
    a = fw.authorize_tool_call(
        proposal=proposal,
        tool_name="search_public_documents",
        security_context=ctx,
        policy_decision=policy,
    )
    b = fw.authorize_tool_call(
        proposal=proposal,
        tool_name="search_public_documents",
        security_context=ctx,
        policy_decision=policy,
    )
    assert a.decision == b.decision
    assert a.reason_codes == b.reason_codes
    assert a.explanation == b.explanation

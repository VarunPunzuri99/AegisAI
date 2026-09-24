"""Agent security workflow tests (deterministic, no Groq / no tools)."""

from __future__ import annotations

from uuid import uuid4

from app.agents.types import (
    ActionRiskLevel,
    ActionType,
    AgentActionRequest,
    AgentActionStatus,
    TrustLevel,
)
from app.agents.workflow import AgentSecurityWorkflow
from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import EvidenceLabel, UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION


def _assessment(
    *,
    risk_score: int = 0,
    severity: Severity = Severity.LOW,
    label: EvidenceLabel = EvidenceLabel.BENIGN,
    conflict: bool = False,
    uncertainty: bool = False,
    attack_types: list[AttackType] | None = None,
) -> UnifiedSecurityAssessment:
    return UnifiedSecurityAssessment(
        label=label,
        risk_score=risk_score,
        severity=severity,
        attack_types=list(attack_types or []),
        conflict=conflict,
        uncertainty=uncertainty,
    )


def _policy(
    decision: SecurityDecision,
    *,
    risk_score: int = 0,
    severity: Severity = Severity.LOW,
    conflict: bool = False,
    uncertainty: bool = False,
    attack_types: list[AttackType] | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        decision=decision,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=risk_score,
        severity=severity,
        attack_types=list(attack_types or []),
        conflict=conflict,
        uncertainty=uncertainty,
        reason_codes=[],
        explanation=f"fixture {decision.value}",
    )


def _req(
    action_type: ActionType = ActionType.SEARCH_DOCUMENTS,
    *,
    target: str = "internal_reports",
    intent: str | None = None,
) -> AgentActionRequest:
    return AgentActionRequest(
        action_type=action_type,
        target=target,
        parameters={},
        declared_intent=intent,
    )


def test_block_no_action() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(risk_score=90, severity=Severity.CRITICAL, label=EvidenceLabel.ATTACK),
        policy_decision=_policy(SecurityDecision.BLOCK, risk_score=90, severity=Severity.CRITICAL),
        action_request=_req(),
    )
    assert result.state.action_status == AgentActionStatus.NO_ACTION
    assert result.proposal is None
    assert result.executed is False
    assert result.ready_for_tool_guard is False


def test_review_requires_review() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(risk_score=35, severity=Severity.MEDIUM),
        policy_decision=_policy(SecurityDecision.REVIEW, risk_score=35, severity=Severity.MEDIUM),
        action_request=_req(),
    )
    assert result.state.action_status == AgentActionStatus.ACTION_REQUIRES_REVIEW
    assert result.executed is False


def test_allow_low_action_proposed() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(risk_score=5),
        policy_decision=_policy(SecurityDecision.ALLOW, risk_score=5),
        action_request=_req(ActionType.SEARCH_DOCUMENTS),
    )
    assert result.state.action_status == AgentActionStatus.ACTION_PROPOSED
    assert result.proposal is not None
    assert result.proposal.action_risk == ActionRiskLevel.LOW
    assert result.executed is False


def test_allow_critical_ready_for_tool_guard() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(risk_score=5),
        policy_decision=_policy(SecurityDecision.ALLOW, risk_score=5),
        action_request=_req(ActionType.DELETE_DATA, target="demo_record"),
    )
    assert result.state.action_status == AgentActionStatus.READY_FOR_TOOL_GUARD
    assert result.ready_for_tool_guard is True
    assert result.executed is False
    assert result.proposal is not None
    assert result.proposal.action_risk == ActionRiskLevel.CRITICAL


def test_missing_policy_requires_review() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(),
        policy_decision=None,
        action_request=_req(),
    )
    assert result.state.action_status == AgentActionStatus.ACTION_REQUIRES_REVIEW


def test_missing_assessment_requires_review() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=None,
        policy_decision=_policy(SecurityDecision.ALLOW),
        action_request=_req(),
    )
    assert result.state.action_status == AgentActionStatus.ACTION_REQUIRES_REVIEW


def test_uncertain_assessment_with_review_policy() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(
            risk_score=10,
            uncertainty=True,
            label=EvidenceLabel.UNCERTAIN,
        ),
        policy_decision=_policy(
            SecurityDecision.REVIEW,
            risk_score=10,
            uncertainty=True,
        ),
        action_request=_req(),
    )
    assert result.state.action_status == AgentActionStatus.ACTION_REQUIRES_REVIEW
    assert result.state.uncertainty is True


def test_blocked_attack_no_action() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(
            risk_score=95,
            severity=Severity.CRITICAL,
            label=EvidenceLabel.ATTACK,
            attack_types=[AttackType.CREDENTIAL_THEFT],
        ),
        policy_decision=_policy(
            SecurityDecision.BLOCK,
            risk_score=95,
            severity=Severity.CRITICAL,
            attack_types=[AttackType.CREDENTIAL_THEFT],
        ),
        action_request=_req(ActionType.SEND_EMAIL, target="attacker@example.com"),
    )
    assert result.state.action_status == AgentActionStatus.NO_ACTION
    assert result.proposal is None


def test_intent_mismatch() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(risk_score=5),
        policy_decision=_policy(SecurityDecision.ALLOW, risk_score=5),
        action_request=_req(
            ActionType.SEND_EMAIL,
            target="hr@example.com",
            intent="Find the employee PTO policy.",
        ),
    )
    assert result.proposal is not None
    assert result.proposal.intent_alignment is False


def test_determinism() -> None:
    assessment = _assessment(risk_score=5)
    policy = _policy(SecurityDecision.ALLOW, risk_score=5)
    req = _req(ActionType.READ_PUBLIC_DATA, target="docs")
    sid = uuid4()
    wf = AgentSecurityWorkflow()
    a = wf.run(
        assessment=assessment,
        policy_decision=policy,
        action_request=req,
        session_id=sid,
        trust_level=TrustLevel.UNTRUSTED,
    )
    b = wf.run(
        assessment=assessment,
        policy_decision=policy,
        action_request=req,
        session_id=sid,
        trust_level=TrustLevel.UNTRUSTED,
    )
    assert a.state.action_status == b.state.action_status
    assert a.state.reason_codes == b.state.reason_codes
    assert a.ready_for_tool_guard == b.ready_for_tool_guard
    assert a.executed == b.executed == False
    # action_id is per-proposal UUID; compare risk/type instead
    assert a.proposal is not None and b.proposal is not None
    assert a.proposal.action_type == b.proposal.action_type
    assert a.proposal.action_risk == b.proposal.action_risk
    assert a.proposal.intent_alignment == b.proposal.intent_alignment


def test_no_external_calls_and_not_executed() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(risk_score=0),
        policy_decision=_policy(SecurityDecision.ALLOW),
        action_request=_req(ActionType.WRITE_DATA, target="notes"),
    )
    assert result.executed is False
    assert "executed" in result.state.audit
    assert result.state.audit["executed"] is False
    assert result.state.audit.get("tool_firewall") is False


def test_trust_level_is_context_not_auth() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(),
        policy_decision=_policy(SecurityDecision.ALLOW),
        action_request=_req(),
        trust_level=TrustLevel.UNTRUSTED,
    )
    assert result.state.trust_level == TrustLevel.UNTRUSTED
    assert result.state.action_status == AgentActionStatus.ACTION_PROPOSED


def test_missing_target_fail_closed() -> None:
    result = AgentSecurityWorkflow().run(
        assessment=_assessment(),
        policy_decision=_policy(SecurityDecision.ALLOW),
        action_request=AgentActionRequest(
            action_type=ActionType.DELETE_DATA,
            target=None,
            parameters={},
        ),
    )
    assert result.state.action_status == AgentActionStatus.ACTION_REQUIRES_REVIEW
    assert result.ready_for_tool_guard is False

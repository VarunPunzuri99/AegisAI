"""Deterministic agent security workflow (consumes Phase 7–8; no tool execution)."""

from __future__ import annotations

from uuid import UUID, uuid4

from app.agents.action_risk import action_requires_target, classify_action_risk
from app.agents.intent_alignment import check_intent_alignment
from app.agents.types import (
    ActionRiskLevel,
    AgentActionProposal,
    AgentActionRequest,
    AgentActionStatus,
    AgentSecurityState,
    AgentStateTransition,
    AgentWorkflowResult,
    TrustLevel,
)
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision


class AgentReasonCode:
    POLICY_BLOCK = "POLICY_BLOCK"
    POLICY_REVIEW = "POLICY_REVIEW"
    POLICY_ALLOW = "POLICY_ALLOW"
    POLICY_ERROR = "POLICY_ERROR"
    POLICY_MISSING = "POLICY_MISSING"
    ASSESSMENT_MISSING = "ASSESSMENT_MISSING"
    UNCERTAINTY = "UNCERTAINTY"
    ACTION_VALIDATED = "ACTION_VALIDATED"
    ACTION_INVALID = "ACTION_INVALID"
    INTENT_MISMATCH = "INTENT_MISMATCH"
    CRITICAL_ACTION = "CRITICAL_ACTION"
    HIGH_ACTION = "HIGH_ACTION"
    READY_FOR_TOOL_GUARD = "READY_FOR_TOOL_GUARD"
    NO_ACTION_REQUESTED = "NO_ACTION_REQUESTED"


class AgentSecurityWorkflow:
    """
    Propagate PolicyDecision into agent state and optional action proposals.

    Does not recalculate risk, call LLMs, or execute tools.
    """

    def run(
        self,
        *,
        assessment: UnifiedSecurityAssessment | None,
        policy_decision: PolicyDecision | None,
        action_request: AgentActionRequest | None = None,
        session_id: UUID | None = None,
        trust_level: TrustLevel = TrustLevel.UNKNOWN,
    ) -> AgentWorkflowResult:
        sid = session_id or uuid4()
        transitions: list[AgentStateTransition] = []
        reason_codes: list[str] = []

        # --- Fail closed: missing security context ---
        if assessment is None:
            reason_codes.append(AgentReasonCode.ASSESSMENT_MISSING)
            state = self._safe_review_state(
                session_id=sid,
                trust_level=trust_level,
                assessment=None,
                policy_decision=policy_decision,
                reason_codes=reason_codes,
                transitions=transitions,
                detail="Security assessment missing; fail-closed to review.",
            )
            return AgentWorkflowResult(state=state, proposal=None, ready_for_tool_guard=False)

        if policy_decision is None:
            reason_codes.append(AgentReasonCode.POLICY_MISSING)
            state = self._safe_review_state(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=None,
                reason_codes=reason_codes,
                transitions=transitions,
                detail="Policy decision missing; fail-closed to review.",
            )
            return AgentWorkflowResult(state=state, proposal=None, ready_for_tool_guard=False)

        uncertainty = bool(assessment.uncertainty or policy_decision.uncertainty)
        conflict = bool(assessment.conflict or policy_decision.conflict)
        if uncertainty:
            reason_codes.append(AgentReasonCode.UNCERTAINTY)

        decision = policy_decision.decision

        # --- BLOCK ---
        if decision == SecurityDecision.BLOCK:
            reason_codes.append(AgentReasonCode.POLICY_BLOCK)
            transitions.append(
                AgentStateTransition(
                    previous_state=None,
                    new_state=AgentActionStatus.NO_ACTION,
                    reason_codes=list(reason_codes),
                    detail="Policy BLOCK — no action proposal generated.",
                )
            )
            state = self._build_state(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=policy_decision,
                action_status=AgentActionStatus.NO_ACTION,
                proposal=None,
                reason_codes=reason_codes,
                transitions=transitions,
            )
            return AgentWorkflowResult(state=state, proposal=None, ready_for_tool_guard=False)

        # --- ERROR (policy infrastructure) ---
        if decision == SecurityDecision.ERROR:
            reason_codes.append(AgentReasonCode.POLICY_ERROR)
            return self._result_requires_review(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=policy_decision,
                reason_codes=reason_codes,
                transitions=transitions,
                detail="Policy ERROR — fail-closed to review.",
            )

        # --- REVIEW ---
        if decision == SecurityDecision.REVIEW:
            reason_codes.append(AgentReasonCode.POLICY_REVIEW)
            return self._result_requires_review(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=policy_decision,
                reason_codes=reason_codes,
                transitions=transitions,
                detail="Policy REVIEW — action requires review; not executable.",
            )

        # --- ALLOW ---
        if decision != SecurityDecision.ALLOW:
            reason_codes.append(AgentReasonCode.POLICY_ERROR)
            return self._result_requires_review(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=policy_decision,
                reason_codes=reason_codes,
                transitions=transitions,
                detail=f"Unexpected policy decision {decision!r}; fail-closed.",
            )

        reason_codes.append(AgentReasonCode.POLICY_ALLOW)

        if action_request is None:
            reason_codes.append(AgentReasonCode.NO_ACTION_REQUESTED)
            transitions.append(
                AgentStateTransition(
                    previous_state=None,
                    new_state=AgentActionStatus.NO_ACTION,
                    reason_codes=list(reason_codes),
                    detail="ALLOW with no action requested.",
                )
            )
            state = self._build_state(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=policy_decision,
                action_status=AgentActionStatus.NO_ACTION,
                proposal=None,
                reason_codes=reason_codes,
                transitions=transitions,
            )
            return AgentWorkflowResult(state=state, proposal=None, ready_for_tool_guard=False)

        proposal, valid, val_codes = self._build_proposal(
            action_request=action_request,
            assessment=assessment,
            policy_decision=policy_decision,
            session_id=sid,
        )
        reason_codes.extend(val_codes)

        if not valid or proposal is None:
            reason_codes.append(AgentReasonCode.ACTION_INVALID)
            return self._result_requires_review(
                session_id=sid,
                trust_level=trust_level,
                assessment=assessment,
                policy_decision=policy_decision,
                reason_codes=reason_codes,
                transitions=transitions,
                detail="Action proposal failed validation; require review.",
                proposal=proposal,
            )

        # Proposal created
        transitions.append(
            AgentStateTransition(
                previous_state=None,
                new_state=AgentActionStatus.ACTION_PROPOSED,
                reason_codes=list(reason_codes),
                detail="Action proposed under ALLOW (not executed).",
            )
        )

        # Critical/high actions advance to tool-guard handoff state.
        # Low/medium remain ACTION_PROPOSED (still not executed; Phase 10 authorizes).
        if proposal.action_risk in {ActionRiskLevel.CRITICAL, ActionRiskLevel.HIGH}:
            if proposal.action_risk == ActionRiskLevel.CRITICAL:
                reason_codes.append(AgentReasonCode.CRITICAL_ACTION)
            else:
                reason_codes.append(AgentReasonCode.HIGH_ACTION)
            reason_codes.append(AgentReasonCode.READY_FOR_TOOL_GUARD)
            transitions.append(
                AgentStateTransition(
                    previous_state=AgentActionStatus.ACTION_PROPOSED,
                    new_state=AgentActionStatus.READY_FOR_TOOL_GUARD,
                    reason_codes=list(reason_codes),
                    detail=(
                        "Proposal ready for Phase 10 Tool Firewall. "
                        "No tool execution in Phase 9."
                    ),
                )
            )
            final_status = AgentActionStatus.READY_FOR_TOOL_GUARD
            ready = True
        else:
            final_status = AgentActionStatus.ACTION_PROPOSED
            ready = False

        if not proposal.intent_alignment:
            reason_codes.append(AgentReasonCode.INTENT_MISMATCH)

        state = self._build_state(
            session_id=sid,
            trust_level=trust_level,
            assessment=assessment,
            policy_decision=policy_decision,
            action_status=final_status,
            proposal=proposal,
            reason_codes=reason_codes,
            transitions=transitions,
        )
        return AgentWorkflowResult(
            state=state,
            proposal=proposal,
            ready_for_tool_guard=ready,
            executed=False,
        )

    def _build_proposal(
        self,
        *,
        action_request: AgentActionRequest,
        assessment: UnifiedSecurityAssessment,
        policy_decision: PolicyDecision,
        session_id: UUID,
    ) -> tuple[AgentActionProposal | None, bool, list[str]]:
        codes: list[str] = []
        action_type = action_request.action_type
        if action_type is None:
            return None, False, [AgentReasonCode.ACTION_INVALID]

        action_risk = classify_action_risk(action_type)
        if action_requires_target(action_type):
            if not action_request.target or not str(action_request.target).strip():
                return None, False, [AgentReasonCode.ACTION_INVALID]

        # Parameters must be a dict (structurally valid)
        if not isinstance(action_request.parameters, dict):
            return None, False, [AgentReasonCode.ACTION_INVALID]

        alignment = check_intent_alignment(
            action_request.declared_intent,
            action_type,
        )
        if not alignment:
            codes.append(AgentReasonCode.INTENT_MISMATCH)

        codes.append(AgentReasonCode.ACTION_VALIDATED)

        security_context = {
            "session_id": str(session_id),
            "policy_id": policy_decision.policy_id,
            "policy_version": policy_decision.policy_version,
            "policy_decision": policy_decision.decision.value,
            "risk_score": policy_decision.risk_score,
            "severity": policy_decision.severity.value,
            "prompt_attack_types": [t.value for t in policy_decision.attack_types],
            "action_risk": action_risk.value,
            "conflict": policy_decision.conflict,
            "uncertainty": policy_decision.uncertainty,
            "label": assessment.label.value,
        }

        proposal = AgentActionProposal(
            action_type=action_type,
            target=action_request.target,
            parameters=dict(action_request.parameters),
            action_risk=action_risk,
            reason=(
                f"Proposed {action_type.value} at action_risk={action_risk.value} "
                f"under policy {policy_decision.decision.value}."
            ),
            intent_alignment=alignment,
            declared_intent=action_request.declared_intent,
            security_context=security_context,
        )
        return proposal, True, codes

    def _result_requires_review(
        self,
        *,
        session_id: UUID,
        trust_level: TrustLevel,
        assessment: UnifiedSecurityAssessment | None,
        policy_decision: PolicyDecision | None,
        reason_codes: list[str],
        transitions: list[AgentStateTransition],
        detail: str,
        proposal: AgentActionProposal | None = None,
    ) -> AgentWorkflowResult:
        transitions.append(
            AgentStateTransition(
                previous_state=None,
                new_state=AgentActionStatus.ACTION_REQUIRES_REVIEW,
                reason_codes=list(reason_codes),
                detail=detail,
            )
        )
        state = self._build_state(
            session_id=session_id,
            trust_level=trust_level,
            assessment=assessment,
            policy_decision=policy_decision,
            action_status=AgentActionStatus.ACTION_REQUIRES_REVIEW,
            proposal=proposal,
            reason_codes=reason_codes,
            transitions=transitions,
        )
        return AgentWorkflowResult(state=state, proposal=proposal, ready_for_tool_guard=False)

    def _safe_review_state(
        self,
        *,
        session_id: UUID,
        trust_level: TrustLevel,
        assessment: UnifiedSecurityAssessment | None,
        policy_decision: PolicyDecision | None,
        reason_codes: list[str],
        transitions: list[AgentStateTransition],
        detail: str,
    ) -> AgentSecurityState:
        transitions.append(
            AgentStateTransition(
                previous_state=None,
                new_state=AgentActionStatus.ACTION_REQUIRES_REVIEW,
                reason_codes=list(reason_codes),
                detail=detail,
            )
        )
        return self._build_state(
            session_id=session_id,
            trust_level=trust_level,
            assessment=assessment,
            policy_decision=policy_decision,
            action_status=AgentActionStatus.ACTION_REQUIRES_REVIEW,
            proposal=None,
            reason_codes=reason_codes,
            transitions=transitions,
        )

    def _build_state(
        self,
        *,
        session_id: UUID,
        trust_level: TrustLevel,
        assessment: UnifiedSecurityAssessment | None,
        policy_decision: PolicyDecision | None,
        action_status: AgentActionStatus,
        proposal: AgentActionProposal | None,
        reason_codes: list[str],
        transitions: list[AgentStateTransition],
    ) -> AgentSecurityState:
        # Deduplicate reason codes preserving order
        seen: set[str] = set()
        ordered: list[str] = []
        for c in reason_codes:
            if c not in seen:
                seen.add(c)
                ordered.append(c)

        uncertainty = bool(
            (assessment.uncertainty if assessment else False)
            or (policy_decision.uncertainty if policy_decision else False)
            or assessment is None
            or policy_decision is None
        )
        conflict = bool(
            (assessment.conflict if assessment else False)
            or (policy_decision.conflict if policy_decision else False)
        )

        audit = {
            "session_id": str(session_id),
            "action_id": str(proposal.action_id) if proposal else None,
            "action_status": action_status.value,
            "policy_decision": (
                policy_decision.decision.value if policy_decision else None
            ),
            "policy_id": policy_decision.policy_id if policy_decision else None,
            "policy_version": (
                policy_decision.policy_version if policy_decision else None
            ),
            "risk_score": policy_decision.risk_score if policy_decision else None,
            "action_risk": proposal.action_risk.value if proposal else None,
            "reason_codes": ordered,
            "trust_level": trust_level.value,
            "executed": False,
            "tool_firewall": False,
            "note": "Phase 9 agent workflow — no tool execution.",
        }

        return AgentSecurityState(
            session_id=session_id,
            trust_level=trust_level,
            action_status=action_status,
            security_assessment=assessment,
            policy_decision=policy_decision,
            proposal=proposal,
            uncertainty=uncertainty,
            conflict=conflict,
            prompt_risk_score=(
                policy_decision.risk_score
                if policy_decision
                else (assessment.risk_score if assessment else None)
            ),
            prompt_severity=(
                policy_decision.severity
                if policy_decision
                else (assessment.severity if assessment else None)
            ),
            prompt_attack_types=list(
                policy_decision.attack_types
                if policy_decision
                else (assessment.attack_types if assessment else [])
            ),
            policy_id=policy_decision.policy_id if policy_decision else None,
            policy_version=(
                policy_decision.policy_version if policy_decision else None
            ),
            policy_decision_value=(
                policy_decision.decision if policy_decision else None
            ),
            transitions=list(transitions),
            reason_codes=ordered,
            audit=audit,
            metadata={
                "phase": 9,
                "ready_for_tool_guard": (
                    action_status == AgentActionStatus.READY_FOR_TOOL_GUARD
                ),
            },
        )

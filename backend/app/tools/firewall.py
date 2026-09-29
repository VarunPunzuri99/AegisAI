"""Deterministic Tool Firewall — independent of LLM and PolicyDecision alone."""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from app.agents.types import ActionRiskLevel, AgentActionProposal
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.tools.authorization import has_required_permissions, target_allowed
from app.tools.registry import ToolRegistry, DEFAULT_REGISTRY
from app.tools.replay import ActionReplayRegistry, DEFAULT_REPLAY_REGISTRY
from app.tools.types import (
    ApprovalState,
    ToolExecutionRequest,
    ToolFirewallDecision,
    ToolFirewallVerdict,
    ToolReasonCode,
    ToolSecurityContext,
)
from app.tools.validators import ParameterValidationError, validate_parameters

# Elevated attack types that force DENY for sensitive tools / reinforce block.
_ELEVATED_ATTACKS = frozenset(
    {
        AttackType.TOOL_ABUSE,
        AttackType.CREDENTIAL_THEFT,
        AttackType.SECRET_EXTRACTION,
    }
)


class ToolFirewall:
    """
    Authorize tool calls independently of agent/model output.

    Hard denials are never overridden by later approval.
    """

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        replay: ActionReplayRegistry | None = None,
    ) -> None:
        self.registry = registry or DEFAULT_REGISTRY
        self.replay = replay or DEFAULT_REPLAY_REGISTRY

    def authorize_tool_call(
        self,
        *,
        proposal: AgentActionProposal | None,
        tool_name: str,
        security_context: ToolSecurityContext | None,
        policy_decision: PolicyDecision | None = None,
        assessment: UnifiedSecurityAssessment | None = None,
    ) -> ToolFirewallDecision:
        """
        Deterministic authorization pipeline (fail-closed).

        Order:
          1. security context
          2. action proposal
          3. resolve tool / allowlist / enabled
          4. Phase 8 policy
          5. attack / security context
          6. permissions
          7. target scope
          8. parameters
          9. intent alignment
          10. approval
          11. replay
          12. ALLOW / DENY / REQUIRES_APPROVAL
        """
        reason_codes: list[str] = []

        # 1. Security context
        if security_context is None:
            return self._deny(
                tool_name=tool_name or "unknown",
                action_id=proposal.action_id if proposal else None,
                reason_codes=[ToolReasonCode.SECURITY_CONTEXT_MISSING.value],
                policy_decision=policy_decision,
                explanation="Security context missing; fail-closed.",
            )

        # 2. Action proposal
        if proposal is None:
            return self._deny(
                tool_name=tool_name or "unknown",
                action_id=None,
                reason_codes=[ToolReasonCode.ACTION_PROPOSAL_MISSING.value],
                policy_decision=policy_decision,
                explanation="Action proposal missing; fail-closed.",
                security_context=security_context,
            )

        action_id = proposal.action_id

        # 3. Resolve tool / allowlist / enabled
        if not tool_name or not self.registry.contains(tool_name):
            return self._deny(
                tool_name=tool_name or "unknown",
                action_id=action_id,
                reason_codes=[ToolReasonCode.TOOL_NOT_ALLOWLISTED.value],
                policy_decision=policy_decision,
                explanation=f"Tool '{tool_name}' is not on the allowlist.",
                security_context=security_context,
            )

        tool = self.registry.get(tool_name)
        if tool is None:
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.TOOL_NOT_ALLOWLISTED.value],
                policy_decision=policy_decision,
                explanation=f"Tool '{tool_name}' not found.",
                security_context=security_context,
            )

        if not tool.enabled:
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.TOOL_DISABLED.value],
                policy_decision=policy_decision,
                explanation=f"Tool '{tool_name}' is disabled.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 4. Phase 8 policy
        if policy_decision is None:
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.POLICY_DECISION_MISSING.value],
                policy_decision=None,
                explanation="Policy decision missing; fail-closed.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        decision_value = policy_decision.decision
        if decision_value == SecurityDecision.BLOCK:
            codes = [ToolReasonCode.SECURITY_POLICY_BLOCK.value]
            codes.extend(self._attack_reason_codes(proposal, assessment, policy_decision))
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=codes,
                policy_decision=policy_decision,
                explanation="Security policy BLOCK — tool execution denied.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        if decision_value == SecurityDecision.REVIEW:
            return self._requires_approval(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.SECURITY_REVIEW_REQUIRED.value],
                policy_decision=policy_decision,
                explanation="Security policy REVIEW — approval required; no execution.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        if decision_value == SecurityDecision.ERROR:
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.SECURITY_POLICY_BLOCK.value],
                policy_decision=policy_decision,
                explanation="Policy ERROR — fail-closed deny.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        if decision_value != SecurityDecision.ALLOW:
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.SECURITY_POLICY_BLOCK.value],
                policy_decision=policy_decision,
                explanation=f"Unexpected policy {decision_value!r}; deny.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 5. Attack / elevated security context (even under ALLOW)
        attack_codes = self._attack_reason_codes(proposal, assessment, policy_decision)
        if attack_codes:
            # Elevated attacks under ALLOW still DENY sensitive outbound/delete tools
            if tool.risk_level in {ActionRiskLevel.HIGH, ActionRiskLevel.CRITICAL}:
                return self._deny(
                    tool_name=tool_name,
                    action_id=action_id,
                    reason_codes=attack_codes,
                    policy_decision=policy_decision,
                    explanation="Elevated attack evidence present; high/critical tool denied.",
                    security_context=security_context,
                    risk_level=tool.risk_level,
                )
            reason_codes.extend(attack_codes)

        # 6. Permissions
        if not has_required_permissions(security_context, tool):
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.INSUFFICIENT_PERMISSION.value],
                policy_decision=policy_decision,
                explanation="Caller lacks required permissions for this tool.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 7. Target scope
        if not target_allowed(security_context, tool, proposal.target):
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.TARGET_NOT_ALLOWED.value],
                policy_decision=policy_decision,
                explanation=f"Target '{proposal.target}' not allowed for this tool/session.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 8. Parameters
        try:
            validate_parameters(tool, dict(proposal.parameters))
        except ParameterValidationError as exc:
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[exc.code],
                policy_decision=policy_decision,
                explanation=exc.message,
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 9. Intent alignment
        if proposal.intent_alignment is False:
            reason_codes.append(ToolReasonCode.INTENT_MISMATCH.value)
            if tool.risk_level in {ActionRiskLevel.HIGH, ActionRiskLevel.CRITICAL}:
                return self._deny(
                    tool_name=tool_name,
                    action_id=action_id,
                    reason_codes=list(reason_codes),
                    policy_decision=policy_decision,
                    explanation="Intent/action mismatch on high/critical tool — DENY.",
                    security_context=security_context,
                    risk_level=tool.risk_level,
                )
            # LOW/MEDIUM: DENY (strict Phase 10 default)
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=list(reason_codes),
                policy_decision=policy_decision,
                explanation="Intent/action mismatch — DENY.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 10. Approval requirements
        if tool.requires_approval or tool.risk_level in {
            ActionRiskLevel.HIGH,
            ActionRiskLevel.CRITICAL,
        }:
            approval = security_context.approval_state
            if approval == ApprovalState.REJECTED:
                code = (
                    ToolReasonCode.CRITICAL_ACTION_APPROVAL_REQUIRED.value
                    if tool.risk_level == ActionRiskLevel.CRITICAL
                    else ToolReasonCode.HIGH_RISK_APPROVAL_REQUIRED.value
                )
                return self._deny(
                    tool_name=tool_name,
                    action_id=action_id,
                    reason_codes=[code],
                    policy_decision=policy_decision,
                    explanation="Approval rejected — DENY.",
                    security_context=security_context,
                    risk_level=tool.risk_level,
                )
            if approval != ApprovalState.APPROVED:
                code = (
                    ToolReasonCode.CRITICAL_ACTION_APPROVAL_REQUIRED.value
                    if tool.risk_level == ActionRiskLevel.CRITICAL
                    else ToolReasonCode.HIGH_RISK_APPROVAL_REQUIRED.value
                )
                return self._requires_approval(
                    tool_name=tool_name,
                    action_id=action_id,
                    reason_codes=[code],
                    policy_decision=policy_decision,
                    explanation="High/critical tool requires explicit trusted approval.",
                    security_context=security_context,
                    risk_level=tool.risk_level,
                )

        # 11. Replay
        if self.replay.is_processed(action_id):
            return self._deny(
                tool_name=tool_name,
                action_id=action_id,
                reason_codes=[ToolReasonCode.ACTION_ALREADY_PROCESSED.value],
                policy_decision=policy_decision,
                explanation="Action ID already processed — replay denied.",
                security_context=security_context,
                risk_level=tool.risk_level,
            )

        # 12. ALLOW
        return self._allow(
            tool_name=tool_name,
            action_id=action_id,
            reason_codes=reason_codes or [ToolReasonCode.EXECUTION_SUCCESS.value],
            policy_decision=policy_decision,
            explanation="Tool call authorized (sandbox execution only).",
            security_context=security_context,
            risk_level=tool.risk_level,
        )

    def build_execution_request(
        self,
        *,
        decision: ToolFirewallDecision,
        proposal: AgentActionProposal,
    ) -> ToolExecutionRequest | None:
        """Create an execution request only when decision is ALLOW."""
        if decision.decision != ToolFirewallVerdict.ALLOW:
            return None
        if decision.action_id is None or decision.action_id != proposal.action_id:
            return None
        return ToolExecutionRequest(
            action_id=proposal.action_id,
            tool_name=decision.tool_name,
            parameters=dict(proposal.parameters),
            target=proposal.target,
            firewall_decision=decision,
            authorized=True,
        )

    def mark_executed(self, action_id: UUID) -> bool:
        """Mark action processed after successful authorization+execution handoff."""
        return self.replay.mark_processed(action_id)

    def _attack_types(
        self,
        proposal: AgentActionProposal,
        assessment: UnifiedSecurityAssessment | None,
        policy_decision: PolicyDecision | None,
    ) -> list[AttackType]:
        types: list[AttackType] = []
        if policy_decision:
            types.extend(policy_decision.attack_types)
        if assessment:
            types.extend(assessment.attack_types)
        # From proposal security_context if present
        raw = proposal.security_context.get("prompt_attack_types") or []
        for item in raw:
            try:
                at = AttackType(item) if not isinstance(item, AttackType) else item
                types.append(at)
            except ValueError:
                continue
        # Deduplicate
        seen: set[AttackType] = set()
        out: list[AttackType] = []
        for t in types:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def _attack_reason_codes(
        self,
        proposal: AgentActionProposal,
        assessment: UnifiedSecurityAssessment | None,
        policy_decision: PolicyDecision | None,
    ) -> list[str]:
        codes: list[str] = []
        for at in self._attack_types(proposal, assessment, policy_decision):
            if at == AttackType.TOOL_ABUSE:
                codes.append(ToolReasonCode.TOOL_ABUSE_DETECTED.value)
            elif at == AttackType.CREDENTIAL_THEFT:
                codes.append(ToolReasonCode.CREDENTIAL_THEFT_DETECTED.value)
            elif at == AttackType.SECRET_EXTRACTION:
                codes.append(ToolReasonCode.SECRET_EXTRACTION_DETECTED.value)
        return codes

    def _deny(
        self,
        *,
        tool_name: str,
        action_id: Optional[UUID],
        reason_codes: list[str],
        policy_decision: PolicyDecision | None,
        explanation: str,
        security_context: ToolSecurityContext | None = None,
        risk_level: ActionRiskLevel | None = None,
    ) -> ToolFirewallDecision:
        return self._decision(
            verdict=ToolFirewallVerdict.DENY,
            tool_name=tool_name,
            action_id=action_id,
            reason_codes=reason_codes,
            requires_approval=False,
            policy_decision=policy_decision,
            explanation=explanation,
            security_context=security_context,
            risk_level=risk_level,
        )

    def _requires_approval(
        self,
        *,
        tool_name: str,
        action_id: Optional[UUID],
        reason_codes: list[str],
        policy_decision: PolicyDecision | None,
        explanation: str,
        security_context: ToolSecurityContext | None = None,
        risk_level: ActionRiskLevel | None = None,
    ) -> ToolFirewallDecision:
        return self._decision(
            verdict=ToolFirewallVerdict.REQUIRES_APPROVAL,
            tool_name=tool_name,
            action_id=action_id,
            reason_codes=reason_codes,
            requires_approval=True,
            policy_decision=policy_decision,
            explanation=explanation,
            security_context=security_context,
            risk_level=risk_level,
        )

    def _allow(
        self,
        *,
        tool_name: str,
        action_id: Optional[UUID],
        reason_codes: list[str],
        policy_decision: PolicyDecision | None,
        explanation: str,
        security_context: ToolSecurityContext | None = None,
        risk_level: ActionRiskLevel | None = None,
    ) -> ToolFirewallDecision:
        return self._decision(
            verdict=ToolFirewallVerdict.ALLOW,
            tool_name=tool_name,
            action_id=action_id,
            reason_codes=reason_codes,
            requires_approval=False,
            policy_decision=policy_decision,
            explanation=explanation,
            security_context=security_context,
            risk_level=risk_level,
        )

    def _decision(
        self,
        *,
        verdict: ToolFirewallVerdict,
        tool_name: str,
        action_id: Optional[UUID],
        reason_codes: list[str],
        requires_approval: bool,
        policy_decision: PolicyDecision | None,
        explanation: str,
        security_context: ToolSecurityContext | None,
        risk_level: ActionRiskLevel | None,
    ) -> ToolFirewallDecision:
        seen: set[str] = set()
        ordered: list[str] = []
        for c in reason_codes:
            if c not in seen:
                seen.add(c)
                ordered.append(c)

        ctx: dict[str, Any] = {}
        if security_context:
            ctx = {
                "user_id": security_context.user_id,
                "session_id": str(security_context.session_id),
                "roles": list(security_context.roles),
                "permissions": sorted(security_context.permissions),
                "approval_state": security_context.approval_state.value,
                "tenant_id": security_context.tenant_id,
            }

        audit = {
            "action_id": str(action_id) if action_id else None,
            "tool_name": tool_name,
            "decision": verdict.value,
            "reason_codes": ordered,
            "risk_level": risk_level.value if risk_level else None,
            "policy_decision": (
                policy_decision.decision.value if policy_decision else None
            ),
            "policy_id": policy_decision.policy_id if policy_decision else None,
            "policy_version": (
                policy_decision.policy_version if policy_decision else None
            ),
            "approval_state": (
                security_context.approval_state.value if security_context else None
            ),
            "simulated": True,
            "executed": False,
        }

        return ToolFirewallDecision(
            decision=verdict,
            tool_name=tool_name,
            action_id=action_id,
            reason_codes=ordered,
            requires_approval=requires_approval,
            policy_id=policy_decision.policy_id if policy_decision else None,
            policy_version=(
                policy_decision.policy_version if policy_decision else None
            ),
            risk_level=risk_level,
            security_context=ctx,
            audit=audit,
            explanation=explanation,
        )

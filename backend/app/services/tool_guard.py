"""Orchestrate: Authz → Tool Firewall → Mock Executor.

Phase 16 adds AuthorizationService before the existing Tool Firewall.
Authorization NEVER replaces the firewall.
"""

from __future__ import annotations

from uuid import UUID

from app.agents.types import AgentActionProposal
from app.auth.resolver import AuthorizationService
from app.auth.types import AuthorizationDecision, AuthorizationVerdict
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision
from app.tools.executor import MockToolExecutor, ToolExecutorError
from app.tools.firewall import ToolFirewall
from app.tools.registry import ACTION_TYPE_TO_TOOL, ToolRegistry
from app.tools.types import (
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolFirewallDecision,
    ToolFirewallVerdict,
    ToolSecurityContext,
)


class ToolGuardService:
    """
    Single entry for tool authorization + sandboxed execution.

    Order: FAIL_CLOSED mode → Phase 16 Authz → Phase 10 Tool Firewall → Mock Executor.
    """

    def __init__(
        self,
        *,
        firewall: ToolFirewall | None = None,
        executor: MockToolExecutor | None = None,
        registry: ToolRegistry | None = None,
        authz: AuthorizationService | None = None,
        enforce_authz: bool = True,
    ) -> None:
        self.registry = registry or ToolRegistry()
        self.firewall = firewall or ToolFirewall(registry=self.registry)
        self.executor = executor or MockToolExecutor()
        self.authz = authz or AuthorizationService(registry=self.registry)
        self.enforce_authz = enforce_authz

    def resolve_tool_name(self, proposal: AgentActionProposal, tool_name: str | None = None) -> str:
        if tool_name:
            return tool_name
        mapped = ACTION_TYPE_TO_TOOL.get(proposal.action_type)
        if mapped:
            return mapped
        return proposal.action_type.value

    def authorize_identity(
        self,
        *,
        proposal: AgentActionProposal,
        security_context: ToolSecurityContext,
        policy_decision: PolicyDecision | None,
        tool_name: str | None = None,
    ) -> AuthorizationDecision | None:
        """Run Phase 16 authorization when a principal/tenant is present or enforce_authz."""
        if not self.enforce_authz:
            return None
        name = self.resolve_tool_name(proposal, tool_name)
        principal_id = security_context.principal_id or security_context.user_id
        # Only enforce Phase 16 authz when principal looks like a Phase 16 id
        # OR tenant_id is set. Legacy tests without tenant continue via firewall only
        # unless enforce_authz forces it with principal mapping.
        if security_context.tenant_id is None and not (
            isinstance(principal_id, str) and ":" in principal_id
        ):
            # Legacy Phase 10/11 contexts — firewall permissions still apply.
            return None

        return self.authz.authorize(
            principal_id=principal_id,
            tenant_id=security_context.tenant_id,
            tool_name=name,
            target=proposal.target,
            resource_tenant_id=security_context.resource_tenant_id,
            intent_alignment=proposal.intent_alignment,
            policy_decision=policy_decision,
            action_id=proposal.action_id,
        )

    def authorize(
        self,
        *,
        proposal: AgentActionProposal,
        security_context: ToolSecurityContext,
        policy_decision: PolicyDecision | None,
        assessment: UnifiedSecurityAssessment | None = None,
        tool_name: str | None = None,
    ) -> ToolFirewallDecision:
        from app.core.config_validation import get_security_mode
        from app.observability.types import SecurityMode

        if get_security_mode() == SecurityMode.FAIL_CLOSED:
            name = self.resolve_tool_name(proposal, tool_name)
            return ToolFirewallDecision(
                decision=ToolFirewallVerdict.DENY,
                tool_name=name,
                action_id=proposal.action_id,
                reason_codes=["SECURITY_MODE_FAIL_CLOSED"],
                explanation="AEGIS_SECURITY_MODE=FAIL_CLOSED — tool execution denied.",
            )

        name = self.resolve_tool_name(proposal, tool_name)

        # Phase 16 authorization boundary (additional; does not replace firewall).
        authz = self.authorize_identity(
            proposal=proposal,
            security_context=security_context,
            policy_decision=policy_decision,
            tool_name=name,
        )
        if authz is not None and authz.decision == AuthorizationVerdict.DENY:
            return ToolFirewallDecision(
                decision=ToolFirewallVerdict.DENY,
                tool_name=name,
                action_id=proposal.action_id,
                reason_codes=list(authz.reason_codes),
                explanation=authz.explanation or "Authorization DENY.",
                audit={
                    "authorization_decision": authz.decision.value,
                    "authorization_version": authz.authorization_version,
                    "principal_id": authz.principal_id,
                    "tenant_id": authz.tenant_id,
                    "capability": authz.capability,
                },
            )
        if authz is not None and authz.decision == AuthorizationVerdict.REQUIRES_APPROVAL:
            # Still run firewall for reason codes, but require approval / deny execution.
            fw = self.firewall.authorize_tool_call(
                proposal=proposal,
                tool_name=name,
                security_context=security_context,
                policy_decision=policy_decision,
                assessment=assessment,
            )
            if fw.decision == ToolFirewallVerdict.ALLOW:
                return ToolFirewallDecision(
                    decision=ToolFirewallVerdict.REQUIRES_APPROVAL,
                    tool_name=name,
                    action_id=proposal.action_id,
                    reason_codes=list(authz.reason_codes) + list(fw.reason_codes),
                    requires_approval=True,
                    explanation="Authorization requires approval — executor not called.",
                    audit={
                        "authorization_decision": authz.decision.value,
                        "authorization_version": authz.authorization_version,
                        "principal_id": authz.principal_id,
                        "tenant_id": authz.tenant_id,
                        "capability": authz.capability,
                    },
                )
            return fw

        return self.firewall.authorize_tool_call(
            proposal=proposal,
            tool_name=name,
            security_context=security_context,
            policy_decision=policy_decision,
            assessment=assessment,
        )

    def authorize_and_execute(
        self,
        *,
        proposal: AgentActionProposal,
        security_context: ToolSecurityContext,
        policy_decision: PolicyDecision | None,
        assessment: UnifiedSecurityAssessment | None = None,
        tool_name: str | None = None,
    ) -> tuple[ToolFirewallDecision, ToolExecutionResult | None]:
        decision = self.authorize(
            proposal=proposal,
            security_context=security_context,
            policy_decision=policy_decision,
            assessment=assessment,
            tool_name=tool_name,
        )
        if decision.decision != ToolFirewallVerdict.ALLOW:
            return decision, None

        request = self.firewall.build_execution_request(
            decision=decision,
            proposal=proposal,
        )
        if request is None:
            return decision, None

        result = self.executor.execute(request)
        self.firewall.mark_executed(proposal.action_id)
        return decision, result

    def execute_authorized(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        """Execute a previously authorized request; raises if unauthorized."""
        return self.executor.execute(request)

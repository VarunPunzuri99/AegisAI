"""MCP-ready tool transport abstraction — mock only in Phase 16.

Future:
  Agent Runtime → Authz → Tool Firewall → MCP Adapter → MCP Server

Phase 16 stops at MockToolTransport. No real MCP communication.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.agents.types import AgentActionProposal
from app.auth.resolver import AuthorizationService
from app.auth.types import AuthorizationDecision, AuthorizationVerdict
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision
from app.services.tool_guard import ToolGuardService
from app.tools.types import (
    ToolExecutionResult,
    ToolFirewallDecision,
    ToolFirewallVerdict,
    ToolSecurityContext,
)


class ToolRequest(BaseModel):
    """Validated tool request envelope (no secrets)."""

    model_config = ConfigDict(frozen=True)

    action_id: UUID
    tool_name: str
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    principal_id: str
    tenant_id: str
    capability: Optional[str] = None
    resource_tenant_id: Optional[str] = None
    intent_alignment: bool = True


class ToolTransport(ABC):
    """Future-compatible transport interface."""

    @abstractmethod
    def validate_tool_request(self, request: ToolRequest) -> list[str]:
        """Return reason codes if invalid; empty list if structurally valid."""

    @abstractmethod
    def authorize_tool_request(
        self,
        request: ToolRequest,
        *,
        policy_decision: PolicyDecision | None,
        assessment: UnifiedSecurityAssessment | None = None,
        security_context: ToolSecurityContext | None = None,
        proposal: AgentActionProposal | None = None,
    ) -> tuple[AuthorizationDecision, ToolFirewallDecision | None]:
        ...

    @abstractmethod
    def execute_tool_request(
        self,
        request: ToolRequest,
        *,
        firewall_decision: ToolFirewallDecision,
        proposal: AgentActionProposal,
    ) -> ToolExecutionResult | None:
        ...


class MockToolTransport(ToolTransport):
    """
    Phase 16 transport: Authz → existing Tool Firewall → Mock Executor.

    No MCP, no real side effects.
    """

    def __init__(
        self,
        *,
        authz: AuthorizationService | None = None,
        tool_guard: ToolGuardService | None = None,
    ) -> None:
        self.authz = authz or AuthorizationService()
        self.tool_guard = tool_guard or ToolGuardService()

    def validate_tool_request(self, request: ToolRequest) -> list[str]:
        codes: list[str] = []
        if not request.principal_id:
            codes.append("PRINCIPAL_MISSING")
        if not request.tenant_id:
            codes.append("TENANT_MISSING")
        if not request.tool_name:
            codes.append("MALFORMED_REQUEST")
        if request.target == "*":
            codes.append("TARGET_WILDCARD_FORBIDDEN")
        return codes

    def authorize_tool_request(
        self,
        request: ToolRequest,
        *,
        policy_decision: PolicyDecision | None,
        assessment: UnifiedSecurityAssessment | None = None,
        security_context: ToolSecurityContext | None = None,
        proposal: AgentActionProposal | None = None,
    ) -> tuple[AuthorizationDecision, ToolFirewallDecision | None]:
        invalid = self.validate_tool_request(request)
        if invalid:
            authz = self.authz.authorize(
                principal_id=request.principal_id or None,
                tenant_id=request.tenant_id or None,
                tool_name=request.tool_name or None,
                capability=request.capability,
                target=request.target,
                resource_tenant_id=request.resource_tenant_id,
                intent_alignment=request.intent_alignment,
                policy_decision=policy_decision,
                action_id=request.action_id,
            )
            # Force DENY if validate found issues and authz somehow allowed
            if authz.decision == AuthorizationVerdict.ALLOW:
                from app.auth.types import AUTHORIZATION_VERSION

                authz = AuthorizationDecision(
                    decision=AuthorizationVerdict.DENY,
                    principal_id=request.principal_id,
                    tenant_id=request.tenant_id,
                    tool_name=request.tool_name,
                    capability=request.capability,
                    target=request.target,
                    reason_codes=invalid,
                    authorization_version=AUTHORIZATION_VERSION,
                    explanation="Request validation failed.",
                )
            return authz, None

        authz = self.authz.authorize(
            principal_id=request.principal_id,
            tenant_id=request.tenant_id,
            tool_name=request.tool_name,
            capability=request.capability,
            target=request.target,
            resource_tenant_id=request.resource_tenant_id,
            intent_alignment=request.intent_alignment,
            policy_decision=policy_decision,
            action_id=request.action_id,
        )

        # Authorization DENY / REQUIRES_APPROVAL → never call executor via firewall ALLOW path
        if authz.decision == AuthorizationVerdict.DENY:
            return authz, None
        if authz.decision == AuthorizationVerdict.REQUIRES_APPROVAL:
            return authz, None

        if proposal is None or security_context is None:
            return authz, None

        # Existing Tool Firewall remains the execution boundary.
        fw = self.tool_guard.authorize(
            proposal=proposal,
            security_context=security_context,
            policy_decision=policy_decision,
            assessment=assessment,
            tool_name=request.tool_name,
        )
        return authz, fw

    def execute_tool_request(
        self,
        request: ToolRequest,
        *,
        firewall_decision: ToolFirewallDecision,
        proposal: AgentActionProposal,
    ) -> ToolExecutionResult | None:
        if firewall_decision.decision != ToolFirewallVerdict.ALLOW:
            return None
        exec_req = self.tool_guard.firewall.build_execution_request(
            decision=firewall_decision,
            proposal=proposal,
        )
        if exec_req is None:
            return None
        result = self.tool_guard.executor.execute(exec_req)
        self.tool_guard.firewall.mark_executed(proposal.action_id)
        return result

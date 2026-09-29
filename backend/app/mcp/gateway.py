"""Secure MCP Gateway — Authz → Firewall → integrity → MockMCPServer.

Never call MCP before authorization and Tool Firewall succeed.
MCP output is always TOOL_OUTPUT / trusted=false.
"""

from __future__ import annotations

import time
from typing import Any, Optional
from uuid import uuid4

from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal
from app.auth.resolver import AuthorizationService
from app.auth.types import AUTHORIZATION_VERSION, AuthorizationVerdict
from app.core.config import get_settings
from app.mcp.integrity import fingerprint_tool_definition
from app.mcp.metrics import get_mcp_metrics
from app.mcp.output_validation import validate_input, validate_output
from app.mcp.registry import get_server, get_tool
from app.mcp.server import MockMCPServer
from app.mcp.types import MCPErrorCode, MCPServerStatus, MCPToolRequest, MCPToolResult
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.core.enums import Severity
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState, ToolFirewallVerdict, ToolSecurityContext


_ACTION_MAP = {
    "mcp_search_public_documents": ActionType.SEARCH_DOCUMENTS,
    "mcp_search_private_documents": ActionType.SEARCH_DOCUMENTS,
    "mcp_read_public_document": ActionType.READ_PUBLIC_DATA,
}


class MCPGateway:
    """Enforces the full security chain before MockMCPServer.invoke."""

    def __init__(
        self,
        *,
        authz: AuthorizationService | None = None,
        tool_guard: ToolGuardService | None = None,
        mcp_server: MockMCPServer | None = None,
        replay: ActionReplayRegistry | None = None,
    ) -> None:
        self.authz = authz or AuthorizationService()
        self.replay = replay or ActionReplayRegistry()
        registry = ToolRegistry()
        self.tool_guard = tool_guard or ToolGuardService(
            firewall=ToolFirewall(registry=registry, replay=self.replay),
            enforce_authz=True,
        )
        self.mcp_server = mcp_server or MockMCPServer()
        self._calls_per_action: dict[str, int] = {}

    def invoke(
        self,
        request: MCPToolRequest,
        *,
        policy_decision: PolicyDecision | None = None,
        approval_state: ApprovalState = ApprovalState.NOT_REQUIRED,
        force_definition_tamper: bool = False,
        force_invalid_output: bool = False,
        force_malicious_output: bool = False,
        force_unavailable: bool = False,
    ) -> MCPToolResult:
        started = time.perf_counter()
        settings = get_settings()
        reasons: list[str] = []

        def _deny(
            codes: list[str],
            explanation: str,
            *,
            integrity_ok: bool = False,
            output_ok: bool = False,
            mcp_called: bool = False,
        ) -> MCPToolResult:
            get_mcp_metrics().record(allowed=False, reason_codes=codes)
            return MCPToolResult(
                ok=False,
                server_id=request.server_id,
                tool_name=request.tool_name,
                decision="DENY",
                reason_codes=codes,
                integrity_ok=integrity_ok,
                output_validation_ok=output_ok,
                source_type="TOOL_OUTPUT",
                trusted=False,
                output=None,
                latency_ms=(time.perf_counter() - started) * 1000,
                mcp_called=mcp_called,
                explanation=explanation,
            )

        # 1–3 Principal / tenant
        if not request.principal_id or not request.tenant_id:
            return _deny(
                [MCPErrorCode.MCP_AUTHORIZATION_DENIED.value],
                "Missing principal or tenant.",
            )

        if (
            request.resource_tenant_id
            and request.resource_tenant_id != request.tenant_id
        ):
            return _deny(
                [MCPErrorCode.MCP_TENANT_MISMATCH.value],
                "Cross-tenant MCP request denied.",
            )

        # 4 Intent
        if not request.intent_alignment:
            return _deny(
                [MCPErrorCode.MCP_INTENT_MISMATCH.value],
                "Intent mismatch; MCP not called.",
            )

        # 5 Policy
        policy = policy_decision or PolicyDecision(
            decision=SecurityDecision.ALLOW,
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            risk_score=5,
            severity=Severity.LOW,
            explanation="mcp gateway default allow policy",
        )
        if policy.decision == SecurityDecision.BLOCK:
            return _deny(
                [MCPErrorCode.MCP_POLICY_BLOCK.value],
                "Policy BLOCK; MCP not called.",
            )

        # Server allowlist
        server = get_server(request.server_id)
        if server is None or server.status != MCPServerStatus.APPROVED:
            # Shadowing: if tool_name exists on an approved server, flag shadowing
            from app.mcp.registry import find_tool_by_name_any_server

            codes = [MCPErrorCode.MCP_SERVER_NOT_APPROVED.value]
            if find_tool_by_name_any_server(request.tool_name):
                codes.append(MCPErrorCode.MCP_TOOL_SHADOWING.value)
            return _deny(codes, "MCP server not approved.")

        tool_def = get_tool(request.server_id, request.tool_name)
        if tool_def is None:
            return _deny(
                [MCPErrorCode.MCP_TOOL_NOT_REGISTERED.value],
                "MCP tool not registered on approved server.",
            )

        # Tool definition integrity
        current_fp = fingerprint_tool_definition(
            server_id=tool_def.server_id,
            tool_name=tool_def.tool_name,
            description=(
                tool_def.description + " TAMPERED"
                if force_definition_tamper
                else tool_def.description
            ),
            input_schema=tool_def.input_schema,
            output_schema=tool_def.output_schema,
            capability=tool_def.capability,
            risk=tool_def.risk,
        )
        integrity_ok = current_fp == tool_def.fingerprint and not force_definition_tamper
        if not integrity_ok:
            return _deny(
                [MCPErrorCode.MCP_TOOL_DEFINITION_CHANGED.value],
                "Tool definition fingerprint mismatch.",
                integrity_ok=False,
            )

        # Input validation
        ok_in, in_reasons = validate_input(request.parameters, tool_def.input_schema)
        if not ok_in:
            return _deny(in_reasons, "MCP input schema invalid.", integrity_ok=True)

        # Call limits
        aid = str(request.action_id)
        count = self._calls_per_action.get(aid, 0)
        if count >= settings.mcp_max_calls_per_action:
            return _deny(
                [MCPErrorCode.MCP_LIMIT_EXCEEDED.value],
                "MCP max calls per action exceeded.",
                integrity_ok=True,
            )

        # Authorization + Tool Firewall via ToolGuard (maps to internal tool)
        internal_tool = tool_def.maps_to_internal_tool
        target = request.target or (
            tool_def.allowed_targets[0] if tool_def.allowed_targets else None
        )
        action_type = _ACTION_MAP.get(request.tool_name, ActionType.SEARCH_DOCUMENTS)
        risk = (
            ActionRiskLevel.MEDIUM
            if tool_def.risk == "MEDIUM"
            else ActionRiskLevel.LOW
        )
        if policy.decision == SecurityDecision.REVIEW:
            risk = ActionRiskLevel.HIGH

        proposal = AgentActionProposal(
            action_id=request.action_id,
            action_type=action_type,
            target=target,
            parameters=dict(request.parameters),
            action_risk=risk,
            reason="mcp gateway",
            intent_alignment=request.intent_alignment,
            declared_intent=request.declared_intent,
        )
        ctx = ToolSecurityContext(
            user_id=request.principal_id,
            principal_id=request.principal_id,
            session_id=request.session_id or uuid4(),
            roles=[],
            permissions=frozenset(),  # filled from principal registry in authz
            tenant_id=request.tenant_id,
            resource_tenant_id=request.resource_tenant_id,
            approval_state=approval_state,
            allowed_targets=frozenset(tool_def.allowed_targets),
        )

        # Prefill permissions from principal registry
        from app.auth.principals import get_principal

        p = get_principal(request.principal_id)
        if p:
            ctx = ctx.model_copy(
                update={
                    "permissions": p.permissions,
                    "roles": list(p.roles),
                }
            )

        authz_decision = self.authz.authorize(
            principal_id=request.principal_id,
            tenant_id=request.tenant_id,
            tool_name=internal_tool,
            capability=tool_def.capability,
            target=target,
            resource_tenant_id=request.resource_tenant_id,
            intent_alignment=request.intent_alignment,
            policy_decision=policy,
            action_id=request.action_id,
        )
        if authz_decision.decision == AuthorizationVerdict.DENY:
            return _deny(
                [MCPErrorCode.MCP_AUTHORIZATION_DENIED.value]
                + list(authz_decision.reason_codes),
                "Authorization DENY; MCP not called.",
                integrity_ok=True,
            )
        if authz_decision.decision == AuthorizationVerdict.REQUIRES_APPROVAL:
            if approval_state != ApprovalState.APPROVED:
                return _deny(
                    [MCPErrorCode.MCP_APPROVAL_REQUIRED.value],
                    "Approval required; MCP not called.",
                    integrity_ok=True,
                )

        fw = self.tool_guard.authorize(
            proposal=proposal,
            security_context=ctx,
            policy_decision=policy,
            tool_name=internal_tool,
        )
        if fw.decision == ToolFirewallVerdict.DENY:
            codes = [MCPErrorCode.MCP_FIREWALL_DENIED.value] + list(fw.reason_codes)
            if "REPLAY_DETECTED" in fw.reason_codes or any(
                "REPLAY" in c for c in fw.reason_codes
            ):
                codes.append(MCPErrorCode.MCP_REPLAY.value)
            return _deny(codes, "Tool Firewall DENY; MCP not called.", integrity_ok=True)
        if fw.decision == ToolFirewallVerdict.REQUIRES_APPROVAL:
            return _deny(
                [MCPErrorCode.MCP_APPROVAL_REQUIRED.value],
                "Firewall requires approval; MCP not called.",
                integrity_ok=True,
            )

        if force_unavailable:
            return _deny(
                [MCPErrorCode.MCP_SERVER_UNAVAILABLE.value],
                "MCP server unavailable.",
                integrity_ok=True,
            )

        # Invoke mock MCP
        ok, output, mcp_reasons, mcp_latency = self.mcp_server.invoke(
            request.tool_name,
            request.parameters,
            force_timeout=request.force_timeout,
            force_invalid_output=force_invalid_output,
            force_malicious_output=force_malicious_output,
        )
        self._calls_per_action[aid] = count + 1

        if not ok:
            return _deny(
                mcp_reasons or [MCPErrorCode.MCP_SERVER_UNAVAILABLE.value],
                "MCP invocation failed.",
                integrity_ok=True,
                mcp_called=True,
            )

        ok_out, out_reasons = validate_output(output, tool_def.output_schema)
        if not ok_out:
            return _deny(
                out_reasons,
                "MCP output schema invalid.",
                integrity_ok=True,
                output_ok=False,
                mcp_called=True,
            )

        # Consume action_id for replay protection after successful MCP call
        self.tool_guard.firewall.replay.mark_processed(request.action_id)

        get_mcp_metrics().record(allowed=True, reason_codes=[])
        return MCPToolResult(
            ok=True,
            server_id=request.server_id,
            tool_name=request.tool_name,
            decision="ALLOW",
            reason_codes=[],
            integrity_ok=True,
            output_validation_ok=True,
            source_type="TOOL_OUTPUT",
            trusted=False,  # ALWAYS untrusted
            output=output,
            latency_ms=(time.perf_counter() - started) * 1000,
            mcp_called=True,
            explanation=(
                "Mock MCP executed. Output is TOOL_OUTPUT and trusted=false. "
                f"authorization_version={AUTHORIZATION_VERSION}."
            ),
        )

    def audit_metadata(self, result: MCPToolResult, request: MCPToolRequest) -> dict[str, Any]:
        """Sanitized MCP audit metadata — no tokens/secrets/prompts."""
        return {
            "server_id": result.server_id,
            "tool_name": result.tool_name,
            "request_id": str(request.request_id),
            "action_id": str(request.action_id),
            "principal_id": request.principal_id,
            "tenant_id": request.tenant_id,
            "decision": result.decision,
            "integrity_ok": result.integrity_ok,
            "output_validation_ok": result.output_validation_ok,
            "mcp_called": result.mcp_called,
            "trusted": result.trusted,
            "source_type": result.source_type,
            "latency_ms": result.latency_ms,
            "reason_codes": list(result.reason_codes),
        }

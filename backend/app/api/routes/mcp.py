"""MCP inspection / simulate API — MockMCPServer only; no registration endpoints."""

from __future__ import annotations

from typing import Annotated, Any, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.authentication.dependencies import require_capability
from app.authentication.types import AuthenticatedPrincipal
from app.core.database import get_db
from app.core.enums import Severity
from app.mcp.gateway import MCPGateway
from app.mcp.metrics import get_mcp_metrics
from app.mcp.registry import list_servers, list_tools
from app.mcp.types import MCPToolRequest
from app.schemas.errors import ErrorResponse
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.tools.types import ApprovalState

RequireMcpRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("mcp:read")),
]
RequireMcpSimulate = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("mcp:simulate")),
]

router = APIRouter(prefix="/mcp", tags=["mcp"])


class MCPSimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server_id: str = Field(..., min_length=1, max_length=128)
    tool_name: str = Field(..., min_length=1, max_length=128)
    target: Optional[str] = Field(default="public_documents", max_length=256)
    parameters: dict[str, Any] = Field(default_factory=dict)
    action_id: Optional[UUID] = None
    resource_tenant_id: Optional[str] = Field(default=None, max_length=128)
    intent_alignment: bool = True
    declared_intent: Optional[str] = Field(default=None, max_length=512)
    policy_decision: Optional[str] = Field(default="ALLOW", max_length=16)
    force_timeout: bool = False
    force_definition_tamper: bool = False
    force_invalid_output: bool = False
    force_malicious_output: bool = False
    # Client-supplied principal/tenant are IGNORED — derived from auth
    principal_id: Optional[str] = Field(default=None, max_length=128)
    tenant_id: Optional[str] = Field(default=None, max_length=128)


@router.get(
    "/servers",
    summary="List approved MCP servers (read-only)",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def get_servers(_principal: RequireMcpRead) -> list[dict[str, Any]]:
    return [
        {
            "server_id": s.server_id,
            "status": s.status.value,
            "trust": s.trust.value,
            "tools": list(s.tools),
            "description": s.description,
        }
        for s in list_servers()
    ]


@router.get(
    "/tools",
    summary="List registered MCP tools with fingerprints (read-only)",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
def get_tools(_principal: RequireMcpRead) -> list[dict[str, Any]]:
    return [
        {
            "server_id": t.server_id,
            "tool_name": t.tool_name,
            "description": t.description,
            "capability": t.capability,
            "risk": t.risk,
            "target_scope": t.target_scope,
            "fingerprint": t.fingerprint,
            "maps_to_internal_tool": t.maps_to_internal_tool,
            "allowed_targets": list(t.allowed_targets),
        }
        for t in list_tools()
    ]


@router.get(
    "/metrics",
    summary="In-process MCP gateway metrics",
)
def mcp_metrics(_principal: RequireMcpRead) -> dict[str, int]:
    return get_mcp_metrics().snapshot()


@router.post(
    "/simulate",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
    summary="Simulate MCP tool via MockMCPServer (no real MCP)",
)
def simulate_mcp(
    body: MCPSimulateRequest,
    principal: RequireMcpSimulate,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    # Identity is ALWAYS from authentication — ignore client overrides
    _ = body.principal_id
    _ = body.tenant_id

    policy_decision = SecurityDecision.ALLOW
    if body.policy_decision:
        try:
            policy_decision = SecurityDecision(body.policy_decision.upper())
        except ValueError:
            policy_decision = SecurityDecision.ALLOW

    policy = PolicyDecision(
        decision=policy_decision,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=90 if policy_decision == SecurityDecision.BLOCK else 5,
        severity=(
            Severity.CRITICAL
            if policy_decision == SecurityDecision.BLOCK
            else Severity.LOW
        ),
        explanation="mcp simulate",
    )

    req = MCPToolRequest(
        principal_id=principal.principal_id,
        tenant_id=principal.tenant_id,
        server_id=body.server_id,
        tool_name=body.tool_name,
        target=body.target,
        parameters=body.parameters,
        action_id=body.action_id or uuid4(),
        resource_tenant_id=body.resource_tenant_id,
        intent_alignment=body.intent_alignment,
        declared_intent=body.declared_intent,
        force_timeout=body.force_timeout,
        authorization_version="aegis-authz-v1",
        policy_version=POLICY_VERSION,
    )

    gateway = MCPGateway()
    result = gateway.invoke(
        req,
        policy_decision=policy,
        approval_state=ApprovalState.NOT_REQUIRED,
        force_definition_tamper=body.force_definition_tamper,
        force_invalid_output=body.force_invalid_output,
        force_malicious_output=body.force_malicious_output,
    )

    # Optional lightweight audit metadata attach via SecurityEvent if useful —
    # keep tokens out. Persist a minimal note in DB only when we have a session.
    _ = db

    return {
        "ok": result.ok,
        "decision": result.decision,
        "server_id": result.server_id,
        "tool_name": result.tool_name,
        "reason_codes": list(result.reason_codes),
        "integrity_ok": result.integrity_ok,
        "output_validation_ok": result.output_validation_ok,
        "source_type": result.source_type,
        "trusted": result.trusted,
        "output": result.output,
        "mcp_called": result.mcp_called,
        "latency_ms": result.latency_ms,
        "explanation": result.explanation,
        "principal_id": principal.principal_id,
        "tenant_id": principal.tenant_id,
        "audit": gateway.audit_metadata(result, req),
        "note": (
            "Mock MCP only. Output is always TOOL_OUTPUT / trusted=false. "
            "No real MCP networking. AegisAI is NOT production-ready."
        ),
    }

"""Phase 17B MCP types — mock protocol only; no real MCP transport."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class MCPServerStatus(StrEnum):
    APPROVED = "APPROVED"
    UNAPPROVED = "UNAPPROVED"
    REVOKED = "REVOKED"


class MCPTrustLevel(StrEnum):
    DEMO_TRUSTED = "DEMO_TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class MCPErrorCode(StrEnum):
    MCP_SERVER_NOT_APPROVED = "MCP_SERVER_NOT_APPROVED"
    MCP_TOOL_NOT_REGISTERED = "MCP_TOOL_NOT_REGISTERED"
    MCP_TOOL_DEFINITION_CHANGED = "MCP_TOOL_DEFINITION_CHANGED"
    MCP_TOOL_SHADOWING = "MCP_TOOL_SHADOWING"
    MCP_INPUT_INVALID = "MCP_INPUT_INVALID"
    MCP_OUTPUT_INVALID = "MCP_OUTPUT_INVALID"
    MCP_TIMEOUT = "MCP_TIMEOUT"
    MCP_SERVER_UNAVAILABLE = "MCP_SERVER_UNAVAILABLE"
    MCP_TENANT_MISMATCH = "MCP_TENANT_MISMATCH"
    MCP_AUTHORIZATION_DENIED = "MCP_AUTHORIZATION_DENIED"
    MCP_FIREWALL_DENIED = "MCP_FIREWALL_DENIED"
    MCP_POLICY_BLOCK = "MCP_POLICY_BLOCK"
    MCP_REPLAY = "MCP_REPLAY"
    MCP_INTENT_MISMATCH = "MCP_INTENT_MISMATCH"
    MCP_APPROVAL_REQUIRED = "MCP_APPROVAL_REQUIRED"
    MCP_LIMIT_EXCEEDED = "MCP_LIMIT_EXCEEDED"


class MCPToolRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: UUID = Field(default_factory=uuid4)
    session_id: Optional[UUID] = None
    principal_id: str
    tenant_id: str
    server_id: str
    tool_name: str
    capability: Optional[str] = None
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    action_id: UUID = Field(default_factory=uuid4)
    policy_version: Optional[str] = None
    authorization_version: Optional[str] = None
    resource_tenant_id: Optional[str] = None
    intent_alignment: bool = True
    declared_intent: Optional[str] = None
    # Force timeout path for tests (never from untrusted content in production)
    force_timeout: bool = False
    # Inject tampered fingerprint check by altering expected (test only via gateway flag)
    skip_integrity: bool = False


class MCPToolResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    server_id: str
    tool_name: str
    decision: str  # ALLOW | DENY | FAILED
    reason_codes: list[str] = Field(default_factory=list)
    integrity_ok: bool = False
    output_validation_ok: bool = False
    source_type: str = "TOOL_OUTPUT"
    trusted: bool = False
    output: Optional[dict[str, Any]] = None
    latency_ms: Optional[float] = None
    mcp_called: bool = False
    explanation: str = ""

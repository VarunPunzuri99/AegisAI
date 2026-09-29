"""Approved MCP server + tool registry — application-controlled allowlist."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.mcp.integrity import fingerprint_tool_definition
from app.mcp.types import MCPServerStatus, MCPTrustLevel

APPROVED_SERVER_ID = "aegis-demo-mcp"


class MCPToolDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_id: str
    tool_name: str
    description: str
    capability: str
    risk: str
    target_scope: str
    allowed_targets: tuple[str, ...] = ()
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    maps_to_internal_tool: str = ""  # existing ToolRegistry name for firewall


class MCPServerRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_id: str
    status: MCPServerStatus
    trust: MCPTrustLevel
    tools: tuple[str, ...] = ()
    description: str = ""


def _search_public() -> MCPToolDefinition:
    server_id = APPROVED_SERVER_ID
    tool_name = "mcp_search_public_documents"
    description = "Search public documents via mock MCP (no external I/O)."
    capability = "documents:public:read"
    risk = "LOW"
    input_schema = {
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        },
    }
    output_schema = {
        "type": "object",
        "required": ["items", "count"],
        "properties": {
            "items": {"type": "array"},
            "count": {"type": "integer"},
        },
    }
    fp = fingerprint_tool_definition(
        server_id=server_id,
        tool_name=tool_name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        capability=capability,
        risk=risk,
    )
    return MCPToolDefinition(
        server_id=server_id,
        tool_name=tool_name,
        description=description,
        capability=capability,
        risk=risk,
        target_scope="public",
        allowed_targets=("public_documents",),
        input_schema=input_schema,
        output_schema=output_schema,
        fingerprint=fp,
        maps_to_internal_tool="search_public_documents",
    )


def _read_public() -> MCPToolDefinition:
    server_id = APPROVED_SERVER_ID
    tool_name = "mcp_read_public_document"
    description = "Read a public document via mock MCP (no external I/O)."
    capability = "documents:public:read"
    risk = "LOW"
    input_schema = {
        "type": "object",
        "required": ["document_id"],
        "properties": {
            "document_id": {"type": "string"},
        },
    }
    output_schema = {
        "type": "object",
        "required": ["document_id", "title", "excerpt"],
        "properties": {
            "document_id": {"type": "string"},
            "title": {"type": "string"},
            "excerpt": {"type": "string"},
        },
    }
    fp = fingerprint_tool_definition(
        server_id=server_id,
        tool_name=tool_name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        capability=capability,
        risk=risk,
    )
    return MCPToolDefinition(
        server_id=server_id,
        tool_name=tool_name,
        description=description,
        capability=capability,
        risk=risk,
        target_scope="public",
        allowed_targets=("public_documents",),
        input_schema=input_schema,
        output_schema=output_schema,
        fingerprint=fp,
        maps_to_internal_tool="read_public_document",
    )


def _search_private() -> MCPToolDefinition:
    server_id = APPROVED_SERVER_ID
    tool_name = "mcp_search_private_documents"
    description = "Search tenant-private documents via mock MCP."
    capability = "documents:private:read"
    risk = "MEDIUM"
    input_schema = {
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        },
    }
    output_schema = {
        "type": "object",
        "required": ["items", "count"],
        "properties": {
            "items": {"type": "array"},
            "count": {"type": "integer"},
        },
    }
    fp = fingerprint_tool_definition(
        server_id=server_id,
        tool_name=tool_name,
        description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        capability=capability,
        risk=risk,
    )
    return MCPToolDefinition(
        server_id=server_id,
        tool_name=tool_name,
        description=description,
        capability=capability,
        risk=risk,
        target_scope="tenant-private",
        allowed_targets=("private_documents",),
        input_schema=input_schema,
        output_schema=output_schema,
        fingerprint=fp,
        maps_to_internal_tool="search_private_documents",
    )


def approved_tools() -> dict[tuple[str, str], MCPToolDefinition]:
    tools = (_search_public(), _read_public(), _search_private())
    return {(t.server_id, t.tool_name): t for t in tools}


def approved_servers() -> dict[str, MCPServerRecord]:
    tools = approved_tools()
    names = tuple(
        sorted(t.tool_name for (sid, _name), t in tools.items() if sid == APPROVED_SERVER_ID)
    )
    return {
        APPROVED_SERVER_ID: MCPServerRecord(
            server_id=APPROVED_SERVER_ID,
            status=MCPServerStatus.APPROVED,
            trust=MCPTrustLevel.DEMO_TRUSTED,
            tools=names,
            description="Local mock MCP server — no network, no real side effects.",
        )
    }


_SERVERS = approved_servers()
_TOOLS = approved_tools()


def get_server(server_id: str) -> Optional[MCPServerRecord]:
    return _SERVERS.get(server_id)


def get_tool(server_id: str, tool_name: str) -> Optional[MCPToolDefinition]:
    return _TOOLS.get((server_id, tool_name))


def list_servers() -> list[MCPServerRecord]:
    return list(_SERVERS.values())


def list_tools() -> list[MCPToolDefinition]:
    return list(_TOOLS.values())


def find_tool_by_name_any_server(tool_name: str) -> list[MCPToolDefinition]:
    return [t for (_, name), t in _TOOLS.items() if name == tool_name]

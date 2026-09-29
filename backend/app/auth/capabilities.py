"""Tool capability map — extends registry metadata without mutating thresholds."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict

from app.tools.registry import ToolRegistry, default_tool_definitions


class ToolCapability(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool_name: str
    capability: str
    target_scope: str
    risk_level: str
    requires_approval: bool
    allowed_targets: tuple[str, ...] = ()


# Explicit capability descriptions (no wildcards).
_CAPABILITIES: dict[str, ToolCapability] = {
    "search_public_documents": ToolCapability(
        tool_name="search_public_documents",
        capability="documents:public:read",
        target_scope="public",
        risk_level="LOW",
        requires_approval=False,
        allowed_targets=("public_documents",),
    ),
    "read_public_document": ToolCapability(
        tool_name="read_public_document",
        capability="documents:public:read",
        target_scope="public",
        risk_level="LOW",
        requires_approval=False,
        allowed_targets=("public_documents",),
    ),
    "search_private_documents": ToolCapability(
        tool_name="search_private_documents",
        capability="documents:private:read",
        target_scope="tenant-private",
        risk_level="MEDIUM",
        requires_approval=False,
        allowed_targets=("private_documents",),
    ),
    "read_private_document": ToolCapability(
        tool_name="read_private_document",
        capability="documents:private:read",
        target_scope="tenant-private",
        risk_level="MEDIUM",
        requires_approval=False,
        allowed_targets=("private_documents", "employee_records"),
    ),
    "write_record": ToolCapability(
        tool_name="write_record",
        capability="records:write",
        target_scope="explicit-record",
        risk_level="MEDIUM",
        requires_approval=False,
        allowed_targets=("employee_records", "notes"),
    ),
    "send_email": ToolCapability(
        tool_name="send_email",
        capability="email:send",
        target_scope="approved-recipient",
        risk_level="HIGH",
        requires_approval=True,
        allowed_targets=("email",),
    ),
    "delete_record": ToolCapability(
        tool_name="delete_record",
        capability="records:delete",
        target_scope="explicit-record",
        risk_level="CRITICAL",
        requires_approval=True,
        allowed_targets=("employee_records", "notes"),
    ),
}


def get_tool_capability(tool_name: str) -> ToolCapability | None:
    return _CAPABILITIES.get(tool_name)


def list_tool_capabilities(registry: ToolRegistry | None = None) -> list[ToolCapability]:
    reg = registry or ToolRegistry(default_tool_definitions())
    out: list[ToolCapability] = []
    for tool in reg.all_tools():
        cap = _CAPABILITIES.get(tool.tool_name)
        if cap:
            out.append(cap)
    return out


def capability_for_tool(tool_name: str) -> Optional[str]:
    cap = _CAPABILITIES.get(tool_name)
    return cap.capability if cap else None

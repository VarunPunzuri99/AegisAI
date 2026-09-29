"""Static application-controlled tool registry (explicit allowlist)."""

from __future__ import annotations

from app.agents.types import ActionRiskLevel, ActionType
from app.tools.types import ToolDefinition, ToolOperationType

# Map Phase 9 action types → Phase 10 tool names (deterministic).
ACTION_TYPE_TO_TOOL: dict[ActionType, str] = {
    ActionType.SEARCH_DOCUMENTS: "search_public_documents",
    ActionType.READ_PUBLIC_DATA: "read_public_document",
    ActionType.READ_PRIVATE_DATA: "read_private_document",
    ActionType.WRITE_DATA: "write_record",
    ActionType.SEND_EMAIL: "send_email",
    ActionType.DELETE_DATA: "delete_record",
}


def default_tool_definitions() -> dict[str, ToolDefinition]:
    """Fixed allowlist — never populated from untrusted input."""
    tools = [
        ToolDefinition(
            tool_name="search_public_documents",
            description="Search public document catalog (sandbox).",
            operation_type=ToolOperationType.READ,
            risk_level=ActionRiskLevel.LOW,
            allowed_operations=["search"],
            allowed_targets=["public_documents"],
            required_permissions=["documents:public:read"],
            allowed_parameters=frozenset({"query", "limit"}),
            required_parameters=frozenset({"query"}),
            requires_approval=False,
            enabled=True,
        ),
        ToolDefinition(
            tool_name="read_public_document",
            description="Read a public document by id (sandbox).",
            operation_type=ToolOperationType.READ,
            risk_level=ActionRiskLevel.LOW,
            allowed_operations=["read"],
            allowed_targets=["public_documents"],
            required_permissions=["documents:public:read"],
            allowed_parameters=frozenset({"document_id"}),
            required_parameters=frozenset({"document_id"}),
            requires_approval=False,
            enabled=True,
        ),
        ToolDefinition(
            tool_name="search_private_documents",
            description="Search private document catalog (sandbox).",
            operation_type=ToolOperationType.READ,
            risk_level=ActionRiskLevel.MEDIUM,
            allowed_operations=["search"],
            allowed_targets=["private_documents"],
            required_permissions=["documents:private:read"],
            allowed_parameters=frozenset({"query", "limit"}),
            required_parameters=frozenset({"query"}),
            requires_approval=False,
            enabled=True,
        ),
        ToolDefinition(
            tool_name="read_private_document",
            description="Read a private document by id (sandbox).",
            operation_type=ToolOperationType.READ,
            risk_level=ActionRiskLevel.MEDIUM,
            allowed_operations=["read"],
            allowed_targets=["private_documents", "employee_records"],
            required_permissions=["documents:private:read"],
            allowed_parameters=frozenset({"document_id"}),
            required_parameters=frozenset({"document_id"}),
            requires_approval=False,
            enabled=True,
        ),
        ToolDefinition(
            tool_name="write_record",
            description="Write a sandbox record (simulated).",
            operation_type=ToolOperationType.WRITE,
            risk_level=ActionRiskLevel.MEDIUM,
            allowed_operations=["write"],
            allowed_targets=["employee_records", "notes"],
            required_permissions=["records:write"],
            allowed_parameters=frozenset({"record_id", "content"}),
            required_parameters=frozenset({"record_id", "content"}),
            requires_approval=False,
            enabled=True,
        ),
        ToolDefinition(
            tool_name="send_email",
            description="Simulate sending an email (no SMTP).",
            operation_type=ToolOperationType.EXTERNAL,
            risk_level=ActionRiskLevel.HIGH,
            allowed_operations=["send"],
            allowed_targets=["email"],
            required_permissions=["email:send"],
            allowed_parameters=frozenset(
                {"recipient", "subject", "body", "attachment_ids"}
            ),
            required_parameters=frozenset({"recipient", "subject", "body"}),
            requires_approval=True,
            enabled=True,
        ),
        ToolDefinition(
            tool_name="delete_record",
            description="Simulate deleting a record (no real delete).",
            operation_type=ToolOperationType.DELETE,
            risk_level=ActionRiskLevel.CRITICAL,
            allowed_operations=["delete"],
            allowed_targets=["employee_records", "notes"],
            required_permissions=["records:delete"],
            allowed_parameters=frozenset({"record_id"}),
            required_parameters=frozenset({"record_id"}),
            requires_approval=True,
            enabled=True,
        ),
    ]
    return {t.tool_name: t for t in tools}


class ToolRegistry:
    """Explicit tool allowlist. Unknown tools are denied by the firewall."""

    def __init__(self, tools: dict[str, ToolDefinition] | None = None) -> None:
        self._tools = dict(tools) if tools is not None else default_tool_definitions()

    def get(self, tool_name: str) -> ToolDefinition | None:
        return self._tools.get(tool_name)

    def contains(self, tool_name: str) -> bool:
        return tool_name in self._tools

    def all_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def resolve_tool_name(self, action_type: ActionType) -> str | None:
        return ACTION_TYPE_TO_TOOL.get(action_type)


DEFAULT_REGISTRY = ToolRegistry()

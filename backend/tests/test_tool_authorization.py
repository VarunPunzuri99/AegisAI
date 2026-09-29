"""Tool authorization permission/target tests."""

from __future__ import annotations

from uuid import uuid4

from app.tools.authorization import has_required_permissions, target_allowed
from app.tools.registry import default_tool_definitions
from app.tools.types import ApprovalState, ToolSecurityContext


def _ctx(perms: set[str], targets: set[str] | None = None) -> ToolSecurityContext:
    return ToolSecurityContext(
        user_id="u1",
        session_id=uuid4(),
        permissions=frozenset(perms),
        allowed_targets=frozenset(targets or set()),
        approval_state=ApprovalState.NOT_REQUIRED,
    )


def test_public_read_permission() -> None:
    tool = default_tool_definitions()["search_public_documents"]
    assert has_required_permissions(_ctx({"documents:public:read"}), tool) is True
    assert has_required_permissions(_ctx({"documents:private:read"}), tool) is False


def test_delete_permission() -> None:
    tool = default_tool_definitions()["delete_record"]
    assert has_required_permissions(_ctx({"records:delete"}), tool) is True
    assert has_required_permissions(_ctx({"records:write"}), tool) is False


def test_no_star_permission() -> None:
    tool = default_tool_definitions()["delete_record"]
    assert has_required_permissions(_ctx({"*"}), tool) is False


def test_target_allowed_for_tool() -> None:
    tool = default_tool_definitions()["read_private_document"]
    ctx = _ctx({"documents:private:read"})
    assert target_allowed(ctx, tool, "private_documents") is True
    assert target_allowed(ctx, tool, "public_documents") is False
    assert target_allowed(ctx, tool, None) is False


def test_session_target_grants() -> None:
    tool = default_tool_definitions()["read_private_document"]
    ctx = _ctx(
        {"documents:private:read"},
        targets={"private_documents"},
    )
    assert target_allowed(ctx, tool, "private_documents") is True
    assert target_allowed(ctx, tool, "employee_records") is False

"""Permission and target-scope checks for the tool firewall."""

from __future__ import annotations

from app.tools.types import ToolDefinition, ToolSecurityContext


def has_required_permissions(
    context: ToolSecurityContext,
    tool: ToolDefinition,
) -> bool:
    """True if context holds every permission required by the tool."""
    required = set(tool.required_permissions)
    if not required:
        return False  # fail-closed: tools must declare permissions
    return required.issubset(set(context.permissions))


def target_allowed(
    context: ToolSecurityContext,
    tool: ToolDefinition,
    target: str | None,
) -> bool:
    """
    Validate resource target against tool allowlist and session grants.

    If tool has allowed_targets and a target is provided, it must be in both
    the tool's allowlist and (when session grants exist) the session allowlist.
    """
    if not tool.allowed_targets:
        return target is None

    if target is None:
        # Target required when tool defines allowed_targets
        return False

    if target not in tool.allowed_targets:
        return False

    # If session specifies allowed_targets, enforce intersection
    if context.allowed_targets:
        return target in context.allowed_targets

    return True

"""Demo principals for authorization + Phase 17 API capabilities.

Static, application-controlled — never populated from untrusted content.
No wildcard permissions.
"""

from __future__ import annotations

from app.auth.types import Principal, PrincipalStatus, PrincipalType

# Tool capabilities (Phase 16)
_TOOL_FULL = frozenset(
    {
        "documents:public:read",
        "documents:private:read",
        "records:write",
        "email:send",
        "records:delete",
    }
)
_TOOL_PUBLIC = frozenset({"documents:public:read"})
_TOOL_AGENT = frozenset({"documents:public:read", "documents:private:read"})

# API capabilities (Phase 17A) — explicit only
_API_FULL = frozenset(
    {
        "audit:read:own-tenant",
        "dashboard:read",
        "authz:read",
        "authorization:check",
        "agent:simulate",
        "scan:inspect",
        "mcp:read",
        "mcp:simulate",
    }
)
_API_READONLY = frozenset(
    {
        "audit:read:own-tenant",
        "dashboard:read",
        "authz:read",
        "scan:inspect",
        "mcp:read",
    }
)
_API_AGENT = frozenset(
    {
        "agent:simulate",
        "scan:inspect",
        "mcp:read",
        "mcp:simulate",
        "authz:read",
        "authorization:check",
        # deliberately NO audit:read
    }
)
_API_SERVICE = frozenset(_API_FULL)


def demo_principals() -> dict[str, Principal]:
    return {
        "user:demo": Principal(
            principal_id="user:demo",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-a",
            roles=("analyst",),
            permissions=_TOOL_FULL | _API_FULL,
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Demo user (tenant-a)"},
        ),
        "user:readonly": Principal(
            principal_id="user:readonly",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-a",
            roles=("viewer",),
            permissions=_TOOL_PUBLIC | _API_READONLY,
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Read-only user (tenant-a)"},
        ),
        "user:limited": Principal(
            principal_id="user:limited",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-a",
            roles=("viewer",),
            permissions=_TOOL_PUBLIC,
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Limited user (public read only; no API caps)"},
        ),
        "user:tenant-b": Principal(
            principal_id="user:tenant-b",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-b",
            roles=("analyst",),
            permissions=_TOOL_FULL | _API_FULL,
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Demo user (tenant-b)"},
        ),
        "user:disabled": Principal(
            principal_id="user:disabled",
            principal_type=PrincipalType.USER,
            tenant_id="tenant-a",
            roles=("analyst",),
            permissions=_TOOL_FULL | _API_FULL,
            status=PrincipalStatus.DISABLED,
            metadata={"label": "Disabled principal"},
        ),
        "agent:aegis-demo": Principal(
            principal_id="agent:aegis-demo",
            principal_type=PrincipalType.AGENT,
            tenant_id="tenant-a",
            roles=("agent",),
            permissions=_TOOL_AGENT | _API_AGENT,
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Demo agent (no audit access)"},
        ),
        "service:aegis-runtime": Principal(
            principal_id="service:aegis-runtime",
            principal_type=PrincipalType.SERVICE,
            tenant_id="tenant-a",
            roles=("runtime",),
            permissions=_TOOL_FULL | _API_SERVICE,
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Aegis runtime service"},
        ),
        "tool:search-public": Principal(
            principal_id="tool:search-public",
            principal_type=PrincipalType.TOOL,
            tenant_id="tenant-a",
            roles=("tool",),
            permissions=frozenset({"documents:public:read"}),
            status=PrincipalStatus.ACTIVE,
            metadata={"label": "Tool identity (not an authorizer)"},
        ),
    }


_REGISTRY = demo_principals()


def get_principal(principal_id: str | None) -> Principal | None:
    if not principal_id:
        return None
    return _REGISTRY.get(principal_id)


def list_principals() -> list[Principal]:
    return list(_REGISTRY.values())

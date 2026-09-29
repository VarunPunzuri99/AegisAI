"""Central endpoint access classification — Phase 17A.

PUBLIC endpoints need no credentials.
AUTHENTICATED require a valid principal.
AUTHORIZED require authentication + an explicit capability.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.authentication.types import AccessClass


@dataclass(frozen=True)
class EndpointAccess:
    path_prefix: str
    access: AccessClass
    capability: str | None = None
    description: str = ""


# Explicit matrix — order matters for prefix matching (longest first).
ENDPOINT_ACCESS_MATRIX: tuple[EndpointAccess, ...] = (
    EndpointAccess("/health", AccessClass.PUBLIC, description="Liveness"),
    EndpointAccess("/readiness", AccessClass.PUBLIC, description="Readiness"),
    EndpointAccess("/", AccessClass.PUBLIC, description="Root info"),
    EndpointAccess("/docs", AccessClass.PUBLIC, description="OpenAPI UI"),
    EndpointAccess("/openapi.json", AccessClass.PUBLIC, description="OpenAPI schema"),
    EndpointAccess("/redoc", AccessClass.PUBLIC, description="ReDoc"),
    # Protected API surface under /api/v1
    EndpointAccess(
        "/api/v1/audit",
        AccessClass.AUTHORIZED,
        capability="audit:read:own-tenant",
        description="Audit list/detail — tenant-scoped",
    ),
    EndpointAccess(
        "/api/v1/dashboard",
        AccessClass.AUTHORIZED,
        capability="dashboard:read",
        description="Dashboard security APIs",
    ),
    EndpointAccess(
        "/api/v1/auth/principals",
        AccessClass.AUTHORIZED,
        capability="authz:read",
        description="List demo principals",
    ),
    EndpointAccess(
        "/api/v1/auth/capabilities",
        AccessClass.AUTHORIZED,
        capability="authz:read",
        description="List tool capabilities",
    ),
    EndpointAccess(
        "/api/v1/auth/metrics",
        AccessClass.AUTHORIZED,
        capability="authz:read",
        description="Authz metrics",
    ),
    EndpointAccess(
        "/api/v1/auth/version",
        AccessClass.AUTHORIZED,
        capability="authz:read",
        description="Authz version",
    ),
    EndpointAccess(
        "/api/v1/auth/authorize",
        AccessClass.AUTHORIZED,
        capability="authorization:check",
        description="Authorization simulator",
    ),
    EndpointAccess(
        "/api/v1/auth/session",
        AccessClass.AUTHENTICATED,
        description="Current authenticated session (no capability)",
    ),
    EndpointAccess(
        "/api/v1/agent",
        AccessClass.AUTHORIZED,
        capability="agent:simulate",
        description="Agent runtime simulation",
    ),
    EndpointAccess(
        "/api/v1/inspect",
        AccessClass.AUTHORIZED,
        capability="scan:inspect",
        description="Security inspect pipeline",
    ),
    EndpointAccess(
        "/api/v1/scans",
        AccessClass.AUTHORIZED,
        capability="scan:inspect",
        description="Scan metadata API",
    ),
    EndpointAccess(
        "/api/v1/mcp",
        AccessClass.AUTHORIZED,
        capability="mcp:read",
        description="MCP inspection / simulate (simulate also needs mcp:simulate)",
    ),
)


def classify_path(path: str) -> EndpointAccess:
    """Return access rule for a request path. Unknown API paths → AUTHORIZED fail-closed."""
    normalized = path.split("?")[0].rstrip("/") or "/"
    # Longest prefix match
    matches = [
        rule
        for rule in ENDPOINT_ACCESS_MATRIX
        if normalized == rule.path_prefix
        or normalized.startswith(rule.path_prefix.rstrip("/") + "/")
        or (
            rule.path_prefix != "/"
            and normalized.startswith(rule.path_prefix)
        )
    ]
    if matches:
        return max(matches, key=lambda r: len(r.path_prefix))
    if normalized.startswith("/api/"):
        return EndpointAccess(
            normalized,
            AccessClass.AUTHORIZED,
            capability="api:default",
            description="Unlisted API — fail-closed require capability",
        )
    return EndpointAccess(normalized, AccessClass.PUBLIC, description="Unlisted non-API")


def list_access_matrix() -> list[dict[str, str | None]]:
    return [
        {
            "path_prefix": r.path_prefix,
            "access": r.access.value,
            "capability": r.capability,
            "description": r.description,
        }
        for r in ENDPOINT_ACCESS_MATRIX
    ]

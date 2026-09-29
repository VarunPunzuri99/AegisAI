"""FastAPI dependencies for authentication and capability authorization."""

from __future__ import annotations

from typing import Annotated, Callable

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.authentication.access_matrix import classify_path
from app.authentication.authenticator import authenticate_bearer
from app.authentication.errors import AuthenticationError, AuthorizationDeniedError
from app.authentication.types import (
    AccessClass,
    AuthenticatedPrincipal,
    AuthenticationResult,
)


# Swagger UI drops a raw Authorization header parameter. It only sends that
# header after the user clicks Authorize on an HTTP bearer security scheme.
bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description=(
        "Paste the demo token only. Swagger adds the Bearer prefix. "
        "Example: aegis-demo-user-token"
    ),
)


def get_authentication_result(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> AuthenticationResult:
    if credentials is not None:
        return authenticate_bearer(f"{credentials.scheme} {credentials.credentials}")
    # Non-Bearer values never become credentials; keep the raw header so
    # malformed input still fails closed with the existing reason code.
    return authenticate_bearer(request.headers.get("authorization"))


def require_authenticated(
    result: Annotated[AuthenticationResult, Depends(get_authentication_result)],
) -> AuthenticatedPrincipal:
    if not result.authenticated or not result.principal_id or not result.tenant_id:
        code = (
            result.reason_codes[0]
            if result.reason_codes
            else "AUTHENTICATION_REQUIRED"
        )
        raise AuthenticationError(
            code=code,
            message="Authentication required.",
        )
    return AuthenticatedPrincipal(
        principal_id=result.principal_id,
        principal_type=result.principal_type or "USER",
        tenant_id=result.tenant_id,
        permissions=result.permissions,
        roles=result.roles,
        authentication_method=result.authentication_method,
    )


def require_capability(capability: str) -> Callable:
    """Dependency factory: authenticate + require an explicit capability."""

    def _dep(
        principal: Annotated[AuthenticatedPrincipal, Depends(require_authenticated)],
    ) -> AuthenticatedPrincipal:
        if capability not in principal.permissions:
            # Accept audit:read:all as a broader grant for audit:read:own-tenant
            if not (
                capability == "audit:read:own-tenant"
                and "audit:read:all" in principal.permissions
            ):
                raise AuthorizationDeniedError(
                    code="CAPABILITY_MISSING",
                    message=f"Missing required capability '{capability}'.",
                )
        return principal

    return _dep


def enforce_request_access(request: Request, authorization: str | None) -> AuthenticatedPrincipal | None:
    """
    Optional middleware-style helper: classify path and enforce access.

    Returns AuthenticatedPrincipal for AUTHENTICATED/AUTHORIZED routes,
    None for PUBLIC. Raises AppError subclasses on failure.
    """
    rule = classify_path(request.url.path)
    if rule.access == AccessClass.PUBLIC:
        return None

    result = authenticate_bearer(authorization)
    if not result.authenticated or not result.principal_id or not result.tenant_id:
        code = (
            result.reason_codes[0]
            if result.reason_codes
            else "AUTHENTICATION_REQUIRED"
        )
        raise AuthenticationError(code=code, message="Authentication required.")

    principal = AuthenticatedPrincipal(
        principal_id=result.principal_id,
        principal_type=result.principal_type or "USER",
        tenant_id=result.tenant_id,
        permissions=result.permissions,
        roles=result.roles,
        authentication_method=result.authentication_method,
    )

    if rule.access == AccessClass.AUTHORIZED and rule.capability:
        if rule.capability not in principal.permissions:
            if not (
                rule.capability == "audit:read:own-tenant"
                and "audit:read:all" in principal.permissions
            ):
                # mcp:simulate is checked on the simulate route itself
                if rule.capability == "mcp:read" and request.url.path.rstrip("/").endswith(
                    "/simulate"
                ):
                    if "mcp:simulate" not in principal.permissions:
                        raise AuthorizationDeniedError(
                            code="CAPABILITY_MISSING",
                            message="Missing required capability 'mcp:simulate'.",
                        )
                elif rule.capability != "mcp:read":
                    raise AuthorizationDeniedError(
                        code="CAPABILITY_MISSING",
                        message=f"Missing required capability '{rule.capability}'.",
                    )
                elif "mcp:read" not in principal.permissions:
                    raise AuthorizationDeniedError(
                        code="CAPABILITY_MISSING",
                        message="Missing required capability 'mcp:read'.",
                    )
    return principal


RequireAuth = Annotated[AuthenticatedPrincipal, Depends(require_authenticated)]

"""Phase 16 authorization simulator API + Phase 17A authentication.

Read/authorize only; no permission grants. Identity for /session comes from
the bearer token — client cannot override principal/tenant for the session.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.api.errors import AppError
from app.auth.capabilities import list_tool_capabilities
from app.auth.metrics import get_authz_metrics
from app.auth.principals import list_principals
from app.auth.resolver import AuthorizationService
from app.auth.types import AUTHORIZATION_VERSION, AuthorizationDecision
from app.authentication.access_matrix import list_access_matrix
from app.authentication.dependencies import RequireAuth, require_capability
from app.authentication.types import AuthenticatedPrincipal
from app.core.enums import Severity
from app.schemas.errors import ErrorResponse
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION

router = APIRouter(prefix="/auth", tags=["authorization"])

RequireAuthzRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("authz:read")),
]
RequireAuthzCheck = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("authorization:check")),
]


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Simulation target identity (for the authz simulator only).
    # Does NOT override the caller's AuthenticatedPrincipal.
    principal_id: str = Field(..., min_length=1, max_length=128)
    tenant_id: str = Field(..., min_length=1, max_length=128)
    tool_name: str = Field(..., min_length=1, max_length=128)
    capability: Optional[str] = Field(default=None, max_length=128)
    target: Optional[str] = Field(default=None, max_length=256)
    action_id: Optional[UUID] = None
    resource_tenant_id: Optional[str] = Field(default=None, max_length=128)
    intent_alignment: bool = True
    policy_decision: Optional[str] = Field(default=None, max_length=16)


@router.get(
    "/session",
    summary="Current authenticated session (identity from token only)",
)
def get_session(principal: RequireAuth) -> dict[str, Any]:
    return {
        "authenticated": True,
        "principal_id": principal.principal_id,
        "principal_type": principal.principal_type,
        "tenant_id": principal.tenant_id,
        "roles": list(principal.roles),
        "permissions": sorted(principal.permissions),
        "authentication_method": principal.authentication_method.value,
        "note": (
            "Development authentication. Not a production IdP. "
            "Client cannot override principal_id or tenant_id."
        ),
    }


@router.get(
    "/access-matrix",
    summary="Endpoint access classification (read-only)",
)
def get_access_matrix(_principal: RequireAuthzRead) -> list[dict[str, Any]]:
    return list_access_matrix()


@router.get(
    "/principals",
    summary="List demo principals (read-only)",
)
def get_principals(_principal: RequireAuthzRead) -> list[dict[str, Any]]:
    out = []
    for p in list_principals():
        out.append(
            {
                "principal_id": p.principal_id,
                "principal_type": p.principal_type.value,
                "tenant_id": p.tenant_id,
                "roles": list(p.roles),
                "permissions": sorted(p.permissions),
                "status": p.status.value,
                "metadata": p.metadata,
            }
        )
    return out


@router.get(
    "/capabilities",
    summary="List tool capabilities (read-only)",
)
def get_capabilities(_principal: RequireAuthzRead) -> list[dict[str, Any]]:
    return [c.model_dump() for c in list_tool_capabilities()]


@router.get(
    "/metrics",
    summary="In-process authorization metrics",
)
def get_metrics(_principal: RequireAuthzRead) -> dict[str, Any]:
    return get_authz_metrics().snapshot()


@router.post(
    "/authorize",
    response_model=AuthorizationDecision,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
    summary="Simulate authorization decision (no permission mutation)",
)
def authorize(
    body: AuthorizeRequest,
    caller: RequireAuthzCheck,
) -> AuthorizationDecision:
    _ = caller  # caller must be authenticated; body is simulation target only
    policy = None
    if body.policy_decision:
        try:
            decision = SecurityDecision(body.policy_decision.upper())
        except ValueError as exc:
            raise AppError(
                "INVALID_POLICY_HINT",
                "policy_decision must be ALLOW, REVIEW, or BLOCK",
                status_code=400,
            ) from exc
        policy = PolicyDecision(
            decision=decision,
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            risk_score=90 if decision == SecurityDecision.BLOCK else 10,
            severity=Severity.CRITICAL if decision == SecurityDecision.BLOCK else Severity.LOW,
            explanation="auth simulator policy hint",
        )

    return AuthorizationService().authorize(
        principal_id=body.principal_id,
        tenant_id=body.tenant_id,
        tool_name=body.tool_name,
        capability=body.capability,
        target=body.target,
        resource_tenant_id=body.resource_tenant_id,
        intent_alignment=body.intent_alignment,
        policy_decision=policy,
        action_id=body.action_id or uuid4(),
    )


@router.get(
    "/version",
    summary="Authorization model version",
)
def auth_version(_principal: RequireAuthzRead) -> dict[str, str]:
    return {
        "authorization_version": AUTHORIZATION_VERSION,
        "note": (
            "Phase 16/17 authorization boundary with development authentication. "
            "Does NOT implement real MCP or production IdP. No permission grant APIs."
        ),
    }

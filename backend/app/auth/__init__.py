"""Phase 16 identity + authorization — deterministic, fail-closed, no LLM authz."""

from app.auth.types import (
    AUTHORIZATION_VERSION,
    AuthorizationDecision,
    AuthorizationVerdict,
    Principal,
    PrincipalStatus,
    PrincipalType,
    SecurityContext,
)
from app.auth.resolver import AuthorizationService
from app.auth.principals import demo_principals, get_principal, list_principals
from app.auth.metrics import get_authz_metrics

__all__ = [
    "AUTHORIZATION_VERSION",
    "AuthorizationDecision",
    "AuthorizationService",
    "AuthorizationVerdict",
    "Principal",
    "PrincipalStatus",
    "PrincipalType",
    "SecurityContext",
    "demo_principals",
    "get_authz_metrics",
    "get_principal",
    "list_principals",
]

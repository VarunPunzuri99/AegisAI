"""Phase 17A authentication — development bearer tokens, not a real IdP."""

from app.authentication.access_matrix import list_access_matrix
from app.authentication.authenticator import authenticate_bearer
from app.authentication.dependencies import (
    RequireAuth,
    require_authenticated,
    require_capability,
)
from app.authentication.types import (
    AccessClass,
    AuthenticatedPrincipal,
    AuthenticationResult,
)

__all__ = [
    "AccessClass",
    "AuthenticatedPrincipal",
    "AuthenticationResult",
    "RequireAuth",
    "authenticate_bearer",
    "list_access_matrix",
    "require_authenticated",
    "require_capability",
]

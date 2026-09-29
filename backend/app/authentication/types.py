"""Phase 17A authentication domain types — no secrets in results/logs."""

from __future__ import annotations

from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AuthenticationMethod(StrEnum):
    DEVELOPMENT_BEARER = "DEVELOPMENT_BEARER"
    NONE = "NONE"


class AccessClass(StrEnum):
    PUBLIC = "PUBLIC"
    AUTHENTICATED = "AUTHENTICATED"
    AUTHORIZED = "AUTHORIZED"


class AuthnReasonCode(StrEnum):
    MISSING_AUTHORIZATION_HEADER = "MISSING_AUTHORIZATION_HEADER"
    MALFORMED_AUTHORIZATION_HEADER = "MALFORMED_AUTHORIZATION_HEADER"
    INVALID_TOKEN = "INVALID_TOKEN"
    EXPIRED_TOKEN = "EXPIRED_TOKEN"
    PRINCIPAL_UNKNOWN = "PRINCIPAL_UNKNOWN"
    PRINCIPAL_DISABLED = "PRINCIPAL_DISABLED"
    TENANT_MISSING = "TENANT_MISSING"
    AUTH_MODE_DISABLED = "AUTH_MODE_DISABLED"
    AUTHENTICATED = "AUTHENTICATED"


class AuthenticationResult(BaseModel):
    """Sanitized authentication outcome — never includes raw tokens."""

    model_config = ConfigDict(frozen=True)

    authenticated: bool
    principal_id: Optional[str] = None
    principal_type: Optional[str] = None
    tenant_id: Optional[str] = None
    authentication_method: AuthenticationMethod = AuthenticationMethod.NONE
    reason_codes: list[str] = Field(default_factory=list)
    permissions: frozenset[str] = Field(default_factory=frozenset)
    roles: tuple[str, ...] = ()


class AuthenticatedPrincipal(BaseModel):
    """Request-scoped identity derived solely from authentication."""

    model_config = ConfigDict(frozen=True)

    principal_id: str
    principal_type: str
    tenant_id: str
    permissions: frozenset[str]
    roles: tuple[str, ...] = ()
    authentication_method: AuthenticationMethod = AuthenticationMethod.DEVELOPMENT_BEARER

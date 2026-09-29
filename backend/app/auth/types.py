"""Phase 16 authorization domain types — no secrets, no raw prompts."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

AUTHORIZATION_VERSION = "aegis-authz-v1"


class PrincipalType(StrEnum):
    USER = "USER"
    AGENT = "AGENT"
    SERVICE = "SERVICE"
    TOOL = "TOOL"


class PrincipalStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class AuthorizationVerdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class AuthzReasonCode(StrEnum):
    PRINCIPAL_MISSING = "PRINCIPAL_MISSING"
    PRINCIPAL_UNKNOWN = "PRINCIPAL_UNKNOWN"
    PRINCIPAL_DISABLED = "PRINCIPAL_DISABLED"
    TENANT_MISSING = "TENANT_MISSING"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    PERMISSION_MISSING = "PERMISSION_MISSING"
    CAPABILITY_UNKNOWN = "CAPABILITY_UNKNOWN"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    TOOL_UNKNOWN = "TOOL_UNKNOWN"
    TARGET_MISSING = "TARGET_MISSING"
    TARGET_NOT_ALLOWED = "TARGET_NOT_ALLOWED"
    TARGET_WILDCARD_FORBIDDEN = "TARGET_WILDCARD_FORBIDDEN"
    INTENT_MISMATCH = "INTENT_MISMATCH"
    POLICY_BLOCK = "POLICY_BLOCK"
    POLICY_REVIEW = "POLICY_REVIEW"
    AUTHORIZATION_ALLOW = "AUTHORIZATION_ALLOW"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    UNTRUSTED_CANNOT_GRANT = "UNTRUSTED_CANNOT_GRANT"


class Principal(BaseModel):
    """Internal simulator identity — not a real IdP subject."""

    model_config = ConfigDict(frozen=True)

    principal_id: str
    principal_type: PrincipalType
    tenant_id: str
    roles: tuple[str, ...] = ()
    permissions: frozenset[str] = Field(default_factory=frozenset)
    status: PrincipalStatus = PrincipalStatus.ACTIVE
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthorizationDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: AuthorizationVerdict
    principal_id: Optional[str] = None
    tenant_id: Optional[str] = None
    tool_name: Optional[str] = None
    capability: Optional[str] = None
    target: Optional[str] = None
    reason_codes: list[str] = Field(default_factory=list)
    policy_version: Optional[str] = None
    authorization_version: str = AUTHORIZATION_VERSION
    explanation: str = ""


class SecurityContext(BaseModel):
    """Sanitized security metadata for runtime — never secrets or raw prompts."""

    model_config = ConfigDict(frozen=True)

    request_id: UUID = Field(default_factory=uuid4)
    session_id: Optional[UUID] = None
    principal_id: Optional[str] = None
    tenant_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    authorization_version: str = AUTHORIZATION_VERSION
    action_id: Optional[UUID] = None
    tool_name: Optional[str] = None
    risk: Optional[str] = None
    approval_state: Optional[str] = None
    trust_metadata: dict[str, Any] = Field(default_factory=dict)

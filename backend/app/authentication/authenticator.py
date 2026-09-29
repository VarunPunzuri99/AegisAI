"""Deterministic development authenticator — not a real IdP."""

from __future__ import annotations

import time

from app.auth.principals import get_principal
from app.auth.types import PrincipalStatus
from app.authentication.tokens import resolve_development_token
from app.authentication.types import (
    AuthenticationMethod,
    AuthenticationResult,
    AuthnReasonCode,
)
from app.core.config import get_settings


def authenticate_bearer(authorization_header: str | None) -> AuthenticationResult:
    """
    Authenticate an Authorization: Bearer <token> header.

    Fail-closed. Never returns anonymous access for protected flows.
    Never echoes the token in the result.
    """
    settings = get_settings()
    mode = (settings.aegis_auth_mode or "development").strip().lower()

    if mode not in {"development", "dev"}:
        # Unknown modes fail closed for protected endpoints (caller enforces).
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.AUTH_MODE_DISABLED.value],
        )

    if not authorization_header or not str(authorization_header).strip():
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.MISSING_AUTHORIZATION_HEADER.value],
        )

    parts = authorization_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.MALFORMED_AUTHORIZATION_HEADER.value],
        )

    token = parts[1].strip()
    binding = resolve_development_token(token)
    if binding is None:
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.INVALID_TOKEN.value],
        )

    if binding.expires_at is not None and time.time() > binding.expires_at:
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.EXPIRED_TOKEN.value],
        )

    principal = get_principal(binding.principal_id)
    if principal is None:
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.PRINCIPAL_UNKNOWN.value],
        )

    if principal.status != PrincipalStatus.ACTIVE:
        return AuthenticationResult(
            authenticated=False,
            reason_codes=[AuthnReasonCode.PRINCIPAL_DISABLED.value],
        )

    if not principal.tenant_id:
        return AuthenticationResult(
            authenticated=False,
            principal_id=principal.principal_id,
            reason_codes=[AuthnReasonCode.TENANT_MISSING.value],
        )

    return AuthenticationResult(
        authenticated=True,
        principal_id=principal.principal_id,
        principal_type=principal.principal_type.value,
        tenant_id=principal.tenant_id,
        authentication_method=AuthenticationMethod.DEVELOPMENT_BEARER,
        reason_codes=[AuthnReasonCode.AUTHENTICATED.value],
        permissions=principal.permissions,
        roles=principal.roles,
    )

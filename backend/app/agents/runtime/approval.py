"""Trusted approval binding — agent cannot approve itself.

Approvals are bound to action_id + principal + tenant + tool + target + parameters.
Expired, mismatched, or reused approvals are rejected.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def normalize_parameters(parameters: dict[str, Any]) -> str:
    """Canonical JSON fingerprint of parameters (stable key order)."""
    return json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)


def approval_fingerprint(
    *,
    action_id: UUID,
    tool_name: str,
    target: str | None,
    parameters: dict[str, Any],
    principal_id: str | None = None,
    tenant_id: str | None = None,
) -> str:
    payload = "|".join(
        [
            str(action_id),
            principal_id or "",
            tenant_id or "",
            tool_name,
            target or "",
            normalize_parameters(parameters),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class BoundApproval(BaseModel):
    """Application-issued approval token (never from model/untrusted text)."""

    model_config = ConfigDict(frozen=True)

    approval_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    tool_name: str
    target: Optional[str] = None
    principal_id: Optional[str] = None
    tenant_id: Optional[str] = None
    param_fingerprint: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    consumed: bool = False
    approval_state: str = "APPROVED"


class ApprovalValidationError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def issue_approval(
    *,
    action_id: UUID,
    tool_name: str,
    target: str | None,
    parameters: dict[str, Any],
    principal_id: str | None = None,
    tenant_id: str | None = None,
    ttl_seconds: int = 300,
) -> BoundApproval:
    now = datetime.now(timezone.utc)
    return BoundApproval(
        action_id=action_id,
        tool_name=tool_name,
        target=target,
        principal_id=principal_id,
        tenant_id=tenant_id,
        param_fingerprint=approval_fingerprint(
            action_id=action_id,
            tool_name=tool_name,
            target=target,
            parameters=parameters,
            principal_id=principal_id,
            tenant_id=tenant_id,
        ),
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        consumed=False,
        approval_state="APPROVED",
    )


def validate_approval(
    approval: BoundApproval | None,
    *,
    action_id: UUID,
    tool_name: str,
    target: str | None,
    parameters: dict[str, Any],
    principal_id: str | None = None,
    tenant_id: str | None = None,
    now: datetime | None = None,
) -> BoundApproval:
    """
    Validate a bound approval against the exact proposed action.

    Rejects expired, wrong action/tool/target/params/principal/tenant,
    and already-consumed tokens.
    """
    if approval is None:
        raise ApprovalValidationError("APPROVAL_MISSING")

    clock = now or datetime.now(timezone.utc)
    if approval.consumed:
        raise ApprovalValidationError("APPROVAL_ALREADY_USED")
    if clock > approval.expires_at:
        raise ApprovalValidationError("APPROVAL_EXPIRED")
    if approval.action_id != action_id:
        raise ApprovalValidationError("APPROVAL_ACTION_MISMATCH")
    if approval.tool_name != tool_name:
        raise ApprovalValidationError("APPROVAL_TOOL_MISMATCH")
    if (approval.target or "") != (target or ""):
        raise ApprovalValidationError("APPROVAL_TARGET_MISMATCH")
    if (approval.principal_id or "") != (principal_id or ""):
        raise ApprovalValidationError("APPROVAL_PRINCIPAL_MISMATCH")
    if (approval.tenant_id or "") != (tenant_id or ""):
        raise ApprovalValidationError("APPROVAL_TENANT_MISMATCH")

    expected = approval_fingerprint(
        action_id=action_id,
        tool_name=tool_name,
        target=target,
        parameters=parameters,
        principal_id=principal_id,
        tenant_id=tenant_id,
    )
    if approval.param_fingerprint != expected:
        raise ApprovalValidationError("APPROVAL_PARAMETERS_CHANGED")

    return approval


def consume_approval(approval: BoundApproval) -> BoundApproval:
    """Mark approval consumed (one-shot). Returns a new immutable copy."""
    return approval.model_copy(update={"consumed": True})

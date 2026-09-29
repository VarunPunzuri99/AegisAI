"""Audit API — list/detail for persisted security events (Phase 17A protected)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.authentication.dependencies import require_capability
from app.authentication.errors import AuthorizationDeniedError
from app.authentication.types import AuthenticatedPrincipal
from app.core.database import get_db
from app.models import SecurityEvent
from app.schemas.audit import AuditDetailResponse, AuditListItem, AuditListResponse
from app.schemas.errors import ErrorResponse
from app.services.security_event_service import SecurityEventService

router = APIRouter(prefix="/audit", tags=["audit"])

RequireAuditRead = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("audit:read:own-tenant")),
]


def _event_tenant(event: SecurityEvent) -> str | None:
    meta = event.event_metadata or {}
    tid = meta.get("tenant_id")
    return str(tid) if tid else None


def _assert_tenant_access(principal: AuthenticatedPrincipal, event: SecurityEvent) -> None:
    if "audit:read:all" in principal.permissions:
        return
    event_tenant = _event_tenant(event)
    # Legacy events without tenant_id: visible only within caller's tenant filter
    # for list; for detail, deny if explicit mismatch, allow legacy null.
    if event_tenant is not None and event_tenant != principal.tenant_id:
        raise AuthorizationDeniedError(
            code="TENANT_MISMATCH",
            message="Cross-tenant audit access denied.",
        )


def _to_list_item(event: SecurityEvent) -> AuditListItem:
    return AuditListItem(
        event_id=event.id,
        created_at=event.created_at,
        scan_id=event.scan_id,
        detection_label=event.detection_label,
        attack_types=list(event.attack_types or []),
        risk_score=event.risk_score,
        severity=event.severity,
        policy_decision=event.policy_decision,
        agent_state=event.agent_state,
        tool_name=event.tool_name,
        tool_decision=event.tool_decision,
        conflict=bool(event.conflict),
        uncertainty=bool(event.uncertainty),
        simulated=bool(event.simulated),
    )


def _to_detail(event: SecurityEvent) -> AuditDetailResponse:
    return AuditDetailResponse(
        event_id=event.id,
        created_at=event.created_at,
        scan_id=event.scan_id,
        source_type=event.source_type,
        content_hash=event.content_hash,
        content_length=event.content_length,
        detection={
            "label": event.detection_label,
            "attack_types": list(event.attack_types or []),
            "conflict": event.conflict,
            "uncertainty": event.uncertainty,
        },
        risk={
            "score": event.risk_score,
            "severity": event.severity,
            "factors": list(event.risk_factors or []),
        },
        policy={
            "decision": event.policy_decision,
            "id": event.policy_id,
            "version": event.policy_version,
        },
        agent={"state": event.agent_state},
        tool={
            "name": event.tool_name,
            "decision": event.tool_decision,
            "approval_state": event.approval_state,
        },
        evidence=dict(event.detector_summary or {}),
        pipeline_stages=list(event.pipeline_stages or []),
        risk_factors=list(event.risk_factors or []),
        reason_codes=list(event.reason_codes or []),
        conflict=bool(event.conflict),
        uncertainty=bool(event.uncertainty),
        simulated=bool(event.simulated),
        latency_ms=event.latency_ms,
        metadata=dict(event.event_metadata or {}),
        note=event.note,
    )


@router.get(
    "",
    response_model=AuditListResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="List persisted security events (authenticated, tenant-scoped)",
)
def list_audit_events(
    principal: RequireAuditRead,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    decision: Optional[str] = Query(None, description="Policy decision filter"),
    severity: Optional[str] = Query(None),
    detection_label: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    tool_name: Optional[str] = Query(None),
    tool_decision: Optional[str] = Query(None),
    agent_state: Optional[str] = Query(None),
    policy_version: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    # Client-supplied tenant_id is IGNORED — authenticated tenant is authoritative
    tenant_id: Optional[str] = Query(None, description="Ignored; derived from auth"),
    db: Session = Depends(get_db),
) -> AuditListResponse:
    _ = tenant_id  # never trust client tenant override
    service = SecurityEventService(db)
    items, total = service.list_events(
        page=page,
        page_size=page_size,
        decision=decision,
        severity=severity,
        detection_label=detection_label,
        attack_type=attack_type,
        tool_name=tool_name,
        tool_decision=tool_decision,
        agent_state=agent_state,
        policy_version=policy_version,
        start_date=start_date,
        end_date=end_date,
    )
    # Tenant filter: drop explicit cross-tenant events
    if "audit:read:all" not in principal.permissions:
        filtered: list[SecurityEvent] = []
        for e in items:
            et = _event_tenant(e)
            if et is None or et == principal.tenant_id:
                filtered.append(e)
        items = filtered
        total = len(filtered)

    return AuditListResponse(
        items=[_to_list_item(e) for e in items],
        page=page,
        page_size=page_size,
        total=total,
        summary=service.summary_counts(),
    )


@router.get(
    "/{event_id}",
    response_model=AuditDetailResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get a security event by ID (authenticated, tenant-scoped)",
)
def get_audit_event(
    event_id: UUID,
    principal: RequireAuditRead,
    db: Session = Depends(get_db),
) -> AuditDetailResponse:
    service = SecurityEventService(db)
    event = service.get_event(event_id)
    _assert_tenant_access(principal, event)
    return _to_detail(event)

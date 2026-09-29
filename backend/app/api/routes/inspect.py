"""Inspect API — runs the existing security pipeline and persists a security event."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.authentication.dependencies import require_capability
from app.authentication.types import AuthenticatedPrincipal
from app.core.database import get_db
from app.schemas.errors import ErrorResponse
from app.schemas.inspect import InspectRequest, InspectResponse
from app.services.inspect_service import InspectService
from app.services.security_event_service import SecurityEventService

RequireInspect = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("scan:inspect")),
]

router = APIRouter(prefix="/inspect", tags=["inspect"])


@router.post(
    "",
    response_model=InspectResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Inspect content through the AegisAI security pipeline",
    description=(
        "Runs the existing SecurityDetectionService (normalize → detectors → fusion → "
        "risk → policy) and optionally demonstrates Tool Firewall authorization. "
        "Persists a structured security event (hash + decision metadata; no raw content). "
        "Does not modify thresholds. Does not execute real external tools. "
        "Requires authentication; identity is derived from the bearer token."
    ),
)
def inspect_content(
    body: InspectRequest,
    principal: RequireInspect,
    db: Session = Depends(get_db),
) -> InspectResponse:
    result = InspectService().inspect(
        body.content,
        body.source_type,
        demo_tool=body.demo_tool,
    )
    scan, event = SecurityEventService(db).persist_inspect(
        content=body.content,
        source_type=body.source_type,
        result=result,
        principal_id=principal.principal_id,
        tenant_id=principal.tenant_id,
    )
    return result.model_copy(
        update={
            "event_id": event.id,
            "scan_id": scan.id,
            "content_hash": event.content_hash,
            "persisted": True,
            "note": (
                result.note
                + " Security event persisted (content hash only; no raw prompt stored)."
            ),
        }
    )

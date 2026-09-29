"""Scan API routes — Phase 17A requires scan:inspect."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.authentication.dependencies import require_capability
from app.authentication.types import AuthenticatedPrincipal
from app.core.database import get_db
from app.schemas.errors import ErrorResponse
from app.schemas.scan import ScanCreateRequest, ScanListResponse, ScanResponse
from app.services.scan_service import ScanService

RequireScan = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("scan:inspect")),
]

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    dependencies=[Depends(require_capability("scan:inspect"))],
)


def _to_response(scan) -> ScanResponse:
    return ScanResponse.model_validate(scan).model_copy(
        update={"detection_implemented": False},
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Create a scan",
    description=(
        "Create a scan metadata record for untrusted content. "
        "Phase 2 does **not** run detectors, risk scoring, or policy. "
        "Raw content is hashed and not stored."
    ),
)
def create_scan(
    body: ScanCreateRequest,
    _principal: RequireScan,
    db: Session = Depends(get_db),
) -> ScanResponse:
    service = ScanService(db)
    scan = service.create_scan(content=body.content, source_type=body.source_type)
    return _to_response(scan)


@router.get(
    "",
    response_model=ScanListResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
    summary="List scans",
)
def list_scans(
    _principal: RequireScan,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> ScanListResponse:
    service = ScanService(db)
    items, total = service.list_scans(page=page, page_size=page_size)
    return ScanListResponse(
        items=[_to_response(scan) for scan in items],
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get a scan by ID",
)
def get_scan(
    scan_id: UUID,
    _principal: RequireScan,
    db: Session = Depends(get_db),
) -> ScanResponse:
    service = ScanService(db)
    scan = service.get_scan(scan_id)
    return _to_response(scan)

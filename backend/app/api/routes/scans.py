"""Scan API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.errors import ErrorResponse
from app.schemas.scan import ScanCreateRequest, ScanListResponse, ScanResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])


def _to_response(scan) -> ScanResponse:
    return ScanResponse.model_validate(scan).model_copy(
        update={"detection_implemented": False},
    )


@router.post(
    "",
    response_model=ScanResponse,
    status_code=201,
    responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Create a scan",
    description=(
        "Create a scan metadata record for untrusted content. "
        "Phase 2 does **not** run detectors, risk scoring, or policy. "
        "Raw content is hashed and not stored."
    ),
)
def create_scan(
    body: ScanCreateRequest,
    db: Session = Depends(get_db),
) -> ScanResponse:
    service = ScanService(db)
    scan = service.create_scan(content=body.content, source_type=body.source_type)
    return _to_response(scan)


@router.get(
    "",
    response_model=ScanListResponse,
    responses={422: {"model": ErrorResponse}},
    summary="List scans",
)
def list_scans(
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
    responses={404: {"model": ErrorResponse}},
    summary="Get a scan by ID",
)
def get_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
) -> ScanResponse:
    service = ScanService(db)
    scan = service.get_scan(scan_id)
    return _to_response(scan)

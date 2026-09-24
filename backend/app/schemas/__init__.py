"""Pydantic schema package."""

from app.schemas.errors import ErrorDetail, ErrorResponse
from app.schemas.scan import (
    DetectionResultResponse,
    ScanCreateRequest,
    ScanListResponse,
    ScanResponse,
)

__all__ = [
    "ErrorDetail",
    "ErrorResponse",
    "ScanCreateRequest",
    "ScanResponse",
    "ScanListResponse",
    "DetectionResultResponse",
]

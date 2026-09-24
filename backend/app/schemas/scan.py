"""Pydantic schemas for the scan API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import ScanDecision, ScanStatus, Severity, SourceType

# Reasonable Phase 2 limit; do not silently truncate — reject oversized payloads.
MAX_CONTENT_LENGTH = 100_000


class ScanCreateRequest(BaseModel):
    """Request body for creating a scan (detection not run in Phase 2)."""

    content: str = Field(..., min_length=1, max_length=MAX_CONTENT_LENGTH)
    source_type: SourceType

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be empty or whitespace-only")
        return value


class DetectionResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    detector_name: str
    detector_version: Optional[str] = None
    is_attack: Optional[bool] = None
    confidence: Optional[float] = None
    attack_types: Optional[list[Any]] = None
    raw_result: Optional[dict[str, Any]] = None
    created_at: datetime


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: ScanStatus
    source_type: SourceType
    content_hash: str
    content_length: int
    created_at: datetime
    updated_at: datetime
    decision: Optional[ScanDecision] = None
    risk_score: Optional[float] = None
    severity: Optional[Severity] = None
    detection_results: list[DetectionResultResponse] = Field(default_factory=list)
    error_message: Optional[str] = None
    detection_implemented: bool = Field(
        default=False,
        description=(
            "Phase 2 records scans only. Detection engines are not implemented yet; "
            "this flag is always false until a later phase."
        ),
    )


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    page: int
    page_size: int
    total: int

"""Scan domain service — CRUD and lifecycle helpers (no detection yet)."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.enums import AuditEventType, ScanStatus, SourceType
from app.models import AuditEvent, DetectionResult, Scan
from app.api.errors import AppError
from app.services.hashing import sha256_hex


class ScanService:
    """Application service for scan persistence and retrieval."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create_scan(self, *, content: str, source_type: SourceType) -> Scan:
        """Persist a new scan metadata record. Does not run detectors."""
        content_hash = sha256_hex(content)
        scan = Scan(
            source_type=source_type,
            content_hash=content_hash,
            content_length=len(content),
            status=ScanStatus.PENDING,
            decision=None,
            risk_score=None,
            severity=None,
            error_message=None,
        )
        self.db.add(scan)
        self.db.flush()

        audit = AuditEvent(
            scan_id=scan.id,
            event_type=AuditEventType.SCAN_CREATED.value,
            actor="system",
            message=(
                "Scan record created. Detection engines are not implemented in Phase 2."
            ),
            event_metadata={
                "source_type": source_type.value,
                "content_length": len(content),
                "detection_implemented": False,
            },
        )
        self.db.add(audit)
        self.db.commit()
        return self.get_scan(scan.id)

    def get_scan(self, scan_id: uuid.UUID) -> Scan:
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.detection_results),
                selectinload(Scan.audit_events),
            )
            .execution_options(populate_existing=True)
        )
        scan = self.db.scalars(stmt).first()
        if scan is None:
            raise AppError(
                "SCAN_NOT_FOUND",
                "Scan was not found.",
                status_code=404,
            )
        return scan

    def list_scans(self, *, page: int, page_size: int) -> tuple[Sequence[Scan], int]:
        if page < 1:
            raise AppError("INVALID_PAGE", "page must be >= 1", status_code=422)
        if page_size < 1 or page_size > 100:
            raise AppError(
                "INVALID_PAGE_SIZE",
                "page_size must be between 1 and 100.",
                status_code=422,
            )

        total = self.db.scalar(select(func.count()).select_from(Scan)) or 0
        offset = (page - 1) * page_size
        stmt = (
            select(Scan)
            .options(selectinload(Scan.detection_results))
            .order_by(Scan.created_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        items = self.db.scalars(stmt).all()
        return items, total

    def update_status(
        self,
        scan_id: uuid.UUID,
        status: ScanStatus,
        *,
        error_message: str | None = None,
    ) -> Scan:
        """Update scan status (used by future pipeline stages)."""
        scan = self.get_scan(scan_id)
        scan.status = status
        if error_message is not None:
            scan.error_message = error_message
        self.db.commit()
        return self.get_scan(scan_id)

    def add_detection_result(
        self,
        scan_id: uuid.UUID,
        *,
        detector_name: str,
        detector_version: str | None = None,
        is_attack: bool | None = None,
        confidence: float | None = None,
        attack_types: list | None = None,
        raw_result: dict | None = None,
    ) -> DetectionResult:
        """Persist a detector result (available for later phases; unused in Phase 2)."""
        self.get_scan(scan_id)
        result = DetectionResult(
            scan_id=scan_id,
            detector_name=detector_name,
            detector_version=detector_version,
            is_attack=is_attack,
            confidence=confidence,
            attack_types=attack_types,
            raw_result=raw_result,
        )
        self.db.add(result)
        self.db.commit()
        self.db.refresh(result)
        return result

    def add_audit_event(
        self,
        scan_id: uuid.UUID,
        *,
        event_type: str,
        message: str,
        actor: str | None = None,
        metadata: dict | None = None,
    ) -> AuditEvent:
        """Persist an audit event (pipeline instrumentation for later phases)."""
        self.get_scan(scan_id)
        event = AuditEvent(
            scan_id=scan_id,
            event_type=event_type,
            actor=actor,
            message=message,
            event_metadata=metadata,
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

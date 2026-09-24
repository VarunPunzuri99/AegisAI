"""ORM models for scans, detection results, and audit events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.core.enums import ScanDecision, ScanStatus, Severity, SourceType
from app.models.base import Base

# JSON on SQLite / JSONB on PostgreSQL
JsonType = JSON().with_variant(JSONB(), "postgresql")


def _str_enum(enum_cls: type, name: str, length: int = 32) -> Enum:
    """Store enums as strings for SQLite test compatibility and Postgres simplicity."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        length=length,
        values_callable=lambda members: [m.value for m in members],
    )


class Scan(Base):
    """One security inspection request (metadata only; raw content is not stored)."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_created_at", "created_at"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_decision", "decision"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    source_type: Mapped[SourceType] = mapped_column(
        _str_enum(SourceType, "source_type", length=32),
        nullable=False,
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_length: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        _str_enum(ScanStatus, "scan_status", length=32),
        nullable=False,
        default=ScanStatus.PENDING,
    )
    decision: Mapped[Optional[ScanDecision]] = mapped_column(
        _str_enum(ScanDecision, "scan_decision", length=32),
        nullable=True,
    )
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[Optional[Severity]] = mapped_column(
        _str_enum(Severity, "severity", length=32),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    detection_results: Mapped[list[DetectionResult]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class DetectionResult(Base):
    """Output from a single detector for a scan (populated in later phases)."""

    __tablename__ = "detection_results"
    __table_args__ = (Index("ix_detection_results_scan_id", "scan_id"),)

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    detector_name: Mapped[str] = mapped_column(String(128), nullable=False)
    detector_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_attack: Mapped[Optional[bool]] = mapped_column(nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    attack_types: Mapped[Optional[list[Any]]] = mapped_column(JsonType, nullable=True)
    raw_result: Mapped[Optional[dict[str, Any]]] = mapped_column(JsonType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan: Mapped[Scan] = relationship(back_populates="detection_results")


class AuditEvent(Base):
    """Auditable security/pipeline event linked to a scan."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_scan_id", "scan_id"),
        Index("ix_audit_events_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    # ``metadata`` is reserved on Declarative API; map column name explicitly.
    event_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        "metadata",
        JsonType,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    scan: Mapped[Scan] = relationship(back_populates="audit_events")

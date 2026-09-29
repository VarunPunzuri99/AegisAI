"""ORM model for Phase 13 structured security events (no raw prompts/secrets)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.scan import JsonType


class SecurityEvent(Base):
    """
    Append-oriented record of one inspect/pipeline decision.

    Stores fingerprints and structured summaries only — never raw content,
    API keys, or full tool parameter payloads.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_created_at", "created_at"),
        Index("ix_security_events_policy_decision", "policy_decision"),
        Index("ix_security_events_severity", "severity"),
        Index("ix_security_events_detection_label", "detection_label"),
        Index("ix_security_events_tool_name", "tool_name"),
        Index("ix_security_events_tool_decision", "tool_decision"),
        Index("ix_security_events_scan_id", "scan_id"),
        Index("ix_security_events_content_hash", "content_hash"),
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

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_length: Mapped[int] = mapped_column(Integer, nullable=False)

    detection_label: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    attack_types: Mapped[list[Any]] = mapped_column(JsonType, nullable=False, default=list)

    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    policy_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    policy_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    conflict: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    uncertainty: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    agent_state: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    action_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), nullable=True)
    action_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    tool_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tool_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    approval_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    intent: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    reason_codes: Mapped[list[Any]] = mapped_column(JsonType, nullable=False, default=list)
    detector_summary: Mapped[dict[str, Any]] = mapped_column(
        JsonType, nullable=False, default=dict
    )
    pipeline_stages: Mapped[list[Any]] = mapped_column(JsonType, nullable=False, default=list)
    risk_factors: Mapped[list[Any]] = mapped_column(JsonType, nullable=False, default=list)

    simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    latency_ms: Mapped[Optional[float]] = mapped_column(nullable=True)
    event_metadata: Mapped[Optional[dict[str, Any]]] = mapped_column(
        "metadata",
        JsonType,
        nullable=True,
    )
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan = relationship("Scan", backref="security_events")

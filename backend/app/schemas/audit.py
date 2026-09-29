"""Schemas for the Phase 13 audit API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AuditListItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID
    created_at: datetime
    scan_id: Optional[UUID] = None
    detection_label: Optional[str] = None
    attack_types: list[str] = Field(default_factory=list)
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    policy_decision: Optional[str] = None
    agent_state: Optional[str] = None
    tool_name: Optional[str] = None
    tool_decision: Optional[str] = None
    conflict: bool = False
    uncertainty: bool = False
    simulated: bool = True


class AuditListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[AuditListItem]
    page: int
    page_size: int
    total: int
    summary: dict[str, int] = Field(default_factory=dict)
    note: str = (
        "Application-level structured security events. "
        "Not a tamper-evident compliance ledger or SIEM."
    )


class AuditDetailResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID
    created_at: datetime
    scan_id: Optional[UUID] = None
    source_type: str
    content_hash: str
    content_length: int
    detection: dict[str, Any]
    risk: dict[str, Any]
    policy: dict[str, Any]
    agent: dict[str, Any]
    tool: dict[str, Any]
    evidence: dict[str, Any]
    pipeline_stages: list[dict[str, Any]] = Field(default_factory=list)
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    conflict: bool = False
    uncertainty: bool = False
    simulated: bool = True
    latency_ms: Optional[float] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    note: Optional[str] = None

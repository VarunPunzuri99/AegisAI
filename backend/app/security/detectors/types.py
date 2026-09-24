"""Detection finding and report domain types (in-memory; not persisted in Phase 4)."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType


class Finding(BaseModel):
    """One explainable detector finding. Does not include full raw input."""

    model_config = ConfigDict(frozen=True)

    attack_type: AttackType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    detector_name: str
    rule_id: str
    evidence_type: str
    description: str
    location: Optional[str] = None
    signals: list[str] = Field(default_factory=list)


class DetectionReport(BaseModel):
    """Aggregated deterministic detection output (not a final ALLOW/BLOCK)."""

    model_config = ConfigDict(frozen=True)

    is_attack: bool
    confidence: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    detectors_run: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

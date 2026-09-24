"""Fusion and unified assessment types (evidence only — no ALLOW/BLOCK)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import DetectionReport
from app.security.prompt_guard_types import PromptGuardResult
from app.security.semantic_types import SemanticSecurityAssessment


class EvidenceSource(StrEnum):
    RULES = "RULES"
    PROMPT_GUARD = "PROMPT_GUARD"
    SEMANTIC = "SEMANTIC"


class EvidenceLabel(StrEnum):
    """Normalized detector state for fusion (distinct from policy decisions)."""

    ATTACK = "ATTACK"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"
    UNAVAILABLE = "UNAVAILABLE"


class DetectionEvidence(BaseModel):
    """Normalized single-source evidence with provenance."""

    model_config = ConfigDict(frozen=True)

    source: EvidenceSource
    available: bool
    label: EvidenceLabel
    attack_types: list[AttackType] = Field(default_factory=list)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    severity: Optional[Severity] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error_code: Optional[str] = None


class RiskFactor(BaseModel):
    """Explainable contribution to the AegisAI risk score."""

    model_config = ConfigDict(frozen=True)

    factor: str
    points: int
    reason: str


class UnifiedSecurityAssessment(BaseModel):
    """Fused evidence + deterministic risk — not a policy action."""

    model_config = ConfigDict(frozen=True)

    label: EvidenceLabel
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    attack_types: list[AttackType] = Field(default_factory=list)
    conflict: bool = False
    uncertainty: bool = False
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    sources: list[DetectionEvidence] = Field(default_factory=list)
    # Source-specific values preserved (never averaged into one confidence).
    rule_evidence_strength: Optional[float] = None
    prompt_guard_score: Optional[float] = None
    semantic_confidence: Optional[float] = None
    detector_results: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PipelineInputs(BaseModel):
    """Optional container for typed detector outputs fed into fusion."""

    model_config = ConfigDict(frozen=True)

    deterministic: DetectionReport
    prompt_guard: Optional[PromptGuardResult] = None
    prompt_guard_invoked: bool = False
    semantic: Optional[SemanticSecurityAssessment] = None
    semantic_invoked: bool = False

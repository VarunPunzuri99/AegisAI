"""Policy decision types (ALLOW / REVIEW / BLOCK) — separate from detection/risk."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.security.risk_config import HIGH_IMPACT_ATTACK_TYPES


class SecurityDecision(StrEnum):
    """Phase 8 security action (decision only — not enforcement)."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    ERROR = "ERROR"  # policy infrastructure failure; fail-closed


class PolicyReasonCode(StrEnum):
    """Stable machine-readable reason codes (deterministic, not LLM-generated)."""

    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL_RISK = "CRITICAL_RISK"

    DETECTOR_CONFLICT = "DETECTOR_CONFLICT"
    DETECTOR_UNCERTAIN = "DETECTOR_UNCERTAIN"
    AI_PROVIDER_UNAVAILABLE = "AI_PROVIDER_UNAVAILABLE"

    HIGH_IMPACT_ATTACK = "HIGH_IMPACT_ATTACK"
    MULTIPLE_DETECTORS_AGREE = "MULTIPLE_DETECTORS_AGREE"
    MULTIPLE_ATTACK_CATEGORIES = "MULTIPLE_ATTACK_CATEGORIES"

    POLICY_DISABLED = "POLICY_DISABLED"
    POLICY_INVALID = "POLICY_INVALID"
    ASSESSMENT_INVALID = "ASSESSMENT_INVALID"


class EnforcementPolicy(BaseModel):
    """
    Application-controlled enforcement policy.

    Untrusted content and model output must never mutate these fields.
    """

    model_config = ConfigDict(frozen=True)

    policy_id: str = POLICY_ID
    version: str = POLICY_VERSION
    enabled: bool = True

    # Risk score bands (inclusive): ALLOW if score <= allow_max;
    # REVIEW if allow_max < score <= review_max; BLOCK if score >= block_min.
    allow_max: int = Field(default=19, ge=0, le=100)
    review_max: int = Field(default=74, ge=0, le=100)
    block_min: int = Field(default=75, ge=0, le=100)

    # Uncertainty / conflict: never silently ALLOW.
    uncertain_forces_review: bool = True
    conflict_upgrades_allow_to_review: bool = True

    # High-impact elevation (explicit — not a hidden exception).
    high_impact_attack_types: frozenset[AttackType] = Field(
        default_factory=lambda: frozenset(HIGH_IMPACT_ATTACK_TYPES)
    )
    high_impact_block_min_risk: int = Field(default=50, ge=0, le=100)

    @model_validator(mode="after")
    def _bands_ordered(self) -> EnforcementPolicy:
        if not (self.allow_max < self.review_max < self.block_min):
            raise ValueError(
                "Risk bands must satisfy allow_max < review_max < block_min"
            )
        return self


def default_enforcement_policy() -> EnforcementPolicy:
    """Canonical AEGIS-PROMPT-INJECTION v1.0 enforcement thresholds."""
    return EnforcementPolicy()


class PolicyDecision(BaseModel):
    """Deterministic policy outcome with audit-ready metadata."""

    model_config = ConfigDict(frozen=True)

    decision: SecurityDecision
    policy_id: str
    policy_version: str
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    attack_types: list[AttackType] = Field(default_factory=list)
    conflict: bool = False
    uncertainty: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    explanation: str
    # Structured audit payload (no raw prompts / secrets).
    audit: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyError(Exception):
    """Fail-closed policy infrastructure or assessment validation failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)

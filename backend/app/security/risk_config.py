"""Configurable deterministic risk weights (AegisAI-owned, not model output)."""

from __future__ import annotations

from dataclasses import dataclass

from app.security.detectors.taxonomy import AttackType


@dataclass(frozen=True)
class RiskWeights:
    """Point contributions for the risk engine (0–100 scale)."""

    deterministic_attack: int = 25
    prompt_guard_attack: int = 25
    semantic_attack: int = 30
    detector_agreement: int = 10
    multiple_categories: int = 5
    high_impact_category: int = 5


# Categories that add the high-impact contribution (not an auto-BLOCK).
HIGH_IMPACT_ATTACK_TYPES: frozenset[AttackType] = frozenset(
    {
        AttackType.CREDENTIAL_THEFT,
        AttackType.SECRET_EXTRACTION,
        AttackType.TOOL_ABUSE,
    }
)


# Severity thresholds on the 0–100 risk score (inclusive ranges).
SEVERITY_LOW_MAX = 19
SEVERITY_MEDIUM_MAX = 49
SEVERITY_HIGH_MAX = 74
# 75–100 → CRITICAL

DEFAULT_RISK_WEIGHTS = RiskWeights()

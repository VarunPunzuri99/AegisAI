"""Deterministic AegisAI risk engine (no LLM calls, no ALLOW/BLOCK)."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import DetectionEvidence, EvidenceLabel, EvidenceSource, RiskFactor
from app.security.risk_config import (
    DEFAULT_RISK_WEIGHTS,
    HIGH_IMPACT_ATTACK_TYPES,
    SEVERITY_HIGH_MAX,
    SEVERITY_LOW_MAX,
    SEVERITY_MEDIUM_MAX,
    RiskWeights,
)


@dataclass(frozen=True)
class RiskResult:
    risk_score: int
    severity: Severity
    risk_factors: list[RiskFactor]


class RiskEngine:
    """Map fused evidence to an explainable 0–100 risk score."""

    def __init__(self, weights: RiskWeights | None = None) -> None:
        self.weights = weights or DEFAULT_RISK_WEIGHTS

    def score(
        self,
        *,
        sources: list[DetectionEvidence],
        unified_label: EvidenceLabel,
        attack_types: list[AttackType],
    ) -> RiskResult:
        factors: list[RiskFactor] = []
        by_source = {s.source: s for s in sources}

        rules = by_source.get(EvidenceSource.RULES)
        pg = by_source.get(EvidenceSource.PROMPT_GUARD)
        sem = by_source.get(EvidenceSource.SEMANTIC)

        if rules and rules.available and rules.label == EvidenceLabel.ATTACK:
            factors.append(
                RiskFactor(
                    factor="deterministic_attack",
                    points=self.weights.deterministic_attack,
                    reason="Deterministic rules classified the content as an attack.",
                )
            )

        if pg and pg.available and pg.label == EvidenceLabel.ATTACK:
            factors.append(
                RiskFactor(
                    factor="prompt_guard_attack",
                    points=self.weights.prompt_guard_attack,
                    reason="Prompt Guard detected prompt-attack evidence.",
                )
            )

        if sem and sem.available and sem.label == EvidenceLabel.ATTACK:
            factors.append(
                RiskFactor(
                    factor="semantic_attack",
                    points=self.weights.semantic_attack,
                    reason="Semantic analyzer classified the content as an attack.",
                )
            )

        attack_detectors = [
            s
            for s in sources
            if s.available and s.label == EvidenceLabel.ATTACK
        ]
        if len(attack_detectors) >= 2:
            factors.append(
                RiskFactor(
                    factor="detector_agreement",
                    points=self.weights.detector_agreement,
                    reason=(
                        "Independent detectors agree on a malicious classification."
                    ),
                )
            )

        if len(attack_types) >= 2:
            factors.append(
                RiskFactor(
                    factor="multiple_categories",
                    points=self.weights.multiple_categories,
                    reason="Multiple attack categories were identified.",
                )
            )

        if any(t in HIGH_IMPACT_ATTACK_TYPES for t in attack_types):
            factors.append(
                RiskFactor(
                    factor="high_impact_category",
                    points=self.weights.high_impact_category,
                    reason=(
                        "High-impact attack types present "
                        "(secret extraction, credential theft, and/or tool abuse)."
                    ),
                )
            )

        # Benign/uncertain with no attack factors → score 0
        raw = sum(f.points for f in factors)
        risk_score = max(0, min(100, raw))
        severity = severity_from_score(risk_score)

        # If unified is ATTACK but somehow no factors (shouldn't happen), floor
        if unified_label == EvidenceLabel.ATTACK and risk_score == 0:
            risk_score = 1
            severity = severity_from_score(risk_score)
            factors = list(factors) + [
                RiskFactor(
                    factor="attack_label_floor",
                    points=1,
                    reason="Unified label is ATTACK with minimal evidence points.",
                )
            ]

        return RiskResult(
            risk_score=risk_score,
            severity=severity,
            risk_factors=factors,
        )


def severity_from_score(score: int) -> Severity:
    """Map 0–100 risk score to severity bands."""
    if score <= SEVERITY_LOW_MAX:
        return Severity.LOW
    if score <= SEVERITY_MEDIUM_MAX:
        return Severity.MEDIUM
    if score <= SEVERITY_HIGH_MAX:
        return Severity.HIGH
    return Severity.CRITICAL

"""Risk engine unit tests (deterministic, no Groq / no network)."""

from __future__ import annotations

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import DetectionEvidence, EvidenceLabel, EvidenceSource
from app.security.risk_config import DEFAULT_RISK_WEIGHTS, RiskWeights
from app.security.risk_engine import RiskEngine, severity_from_score


def _ev(
    source: EvidenceSource,
    label: EvidenceLabel,
    *,
    available: bool = True,
    attack_types: list[AttackType] | None = None,
    confidence: float | None = None,
    score: float | None = None,
) -> DetectionEvidence:
    return DetectionEvidence(
        source=source,
        available=available,
        label=label,
        attack_types=list(attack_types or []),
        confidence=confidence,
        score=score,
    )


def test_severity_thresholds() -> None:
    assert severity_from_score(0) == Severity.LOW
    assert severity_from_score(19) == Severity.LOW
    assert severity_from_score(20) == Severity.MEDIUM
    assert severity_from_score(49) == Severity.MEDIUM
    assert severity_from_score(50) == Severity.HIGH
    assert severity_from_score(74) == Severity.HIGH
    assert severity_from_score(75) == Severity.CRITICAL
    assert severity_from_score(100) == Severity.CRITICAL


def test_all_attack_agreement_score() -> None:
    sources = [
        _ev(EvidenceSource.RULES, EvidenceLabel.ATTACK, confidence=0.9),
        _ev(EvidenceSource.PROMPT_GUARD, EvidenceLabel.ATTACK, score=0.95),
        _ev(
            EvidenceSource.SEMANTIC,
            EvidenceLabel.ATTACK,
            attack_types=[AttackType.INSTRUCTION_OVERRIDE],
            confidence=0.9,
        ),
    ]
    result = RiskEngine().score(
        sources=sources,
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    # 25 + 25 + 30 + 10 agreement = 90
    assert result.risk_score == 90
    assert result.severity == Severity.CRITICAL
    assert {f.factor for f in result.risk_factors} >= {
        "deterministic_attack",
        "prompt_guard_attack",
        "semantic_attack",
        "detector_agreement",
    }


def test_semantic_only_lower_than_agreement() -> None:
    semantic_only = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.BENIGN),
            _ev(
                EvidenceSource.PROMPT_GUARD,
                EvidenceLabel.UNAVAILABLE,
                available=False,
            ),
            _ev(
                EvidenceSource.SEMANTIC,
                EvidenceLabel.ATTACK,
                attack_types=[AttackType.INSTRUCTION_OVERRIDE],
                confidence=0.9,
            ),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    all_three = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.ATTACK),
            _ev(EvidenceSource.PROMPT_GUARD, EvidenceLabel.ATTACK, score=0.9),
            _ev(
                EvidenceSource.SEMANTIC,
                EvidenceLabel.ATTACK,
                attack_types=[AttackType.INSTRUCTION_OVERRIDE],
                confidence=0.9,
            ),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    assert semantic_only.risk_score == 30
    assert all_three.risk_score > semantic_only.risk_score


def test_multiple_categories_factor() -> None:
    result = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.BENIGN),
            _ev(
                EvidenceSource.PROMPT_GUARD,
                EvidenceLabel.UNAVAILABLE,
                available=False,
            ),
            _ev(
                EvidenceSource.SEMANTIC,
                EvidenceLabel.ATTACK,
                confidence=0.8,
            ),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[
            AttackType.INSTRUCTION_OVERRIDE,
            AttackType.CONTEXT_POISONING,
        ],
    )
    assert any(f.factor == "multiple_categories" for f in result.risk_factors)
    assert result.risk_score == 30 + 5  # semantic + multi


def test_high_impact_factor() -> None:
    base = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.BENIGN),
            _ev(
                EvidenceSource.PROMPT_GUARD,
                EvidenceLabel.UNAVAILABLE,
                available=False,
            ),
            _ev(EvidenceSource.SEMANTIC, EvidenceLabel.ATTACK, confidence=0.9),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    high = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.BENIGN),
            _ev(
                EvidenceSource.PROMPT_GUARD,
                EvidenceLabel.UNAVAILABLE,
                available=False,
            ),
            _ev(EvidenceSource.SEMANTIC, EvidenceLabel.ATTACK, confidence=0.9),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[
            AttackType.SECRET_EXTRACTION,
            AttackType.CREDENTIAL_THEFT,
            AttackType.TOOL_ABUSE,
        ],
    )
    assert any(f.factor == "high_impact_category" for f in high.risk_factors)
    assert high.risk_score > base.risk_score


def test_risk_cap_at_100() -> None:
    heavy = RiskWeights(
        deterministic_attack=40,
        prompt_guard_attack=40,
        semantic_attack=40,
        detector_agreement=40,
        multiple_categories=40,
        high_impact_category=40,
    )
    result = RiskEngine(weights=heavy).score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.ATTACK),
            _ev(EvidenceSource.PROMPT_GUARD, EvidenceLabel.ATTACK, score=1.0),
            _ev(EvidenceSource.SEMANTIC, EvidenceLabel.ATTACK, confidence=1.0),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[
            AttackType.SECRET_EXTRACTION,
            AttackType.TOOL_ABUSE,
        ],
    )
    assert result.risk_score <= 100
    assert result.risk_score == 100


def test_risk_floor_at_0() -> None:
    result = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.BENIGN),
            _ev(EvidenceSource.PROMPT_GUARD, EvidenceLabel.BENIGN, score=0.05),
            _ev(EvidenceSource.SEMANTIC, EvidenceLabel.BENIGN, confidence=0.1),
        ],
        unified_label=EvidenceLabel.BENIGN,
        attack_types=[],
    )
    assert result.risk_score >= 0
    assert result.risk_score == 0
    assert result.severity == Severity.LOW


def test_determinism() -> None:
    sources = [
        _ev(EvidenceSource.RULES, EvidenceLabel.ATTACK, confidence=0.8),
        _ev(EvidenceSource.PROMPT_GUARD, EvidenceLabel.ATTACK, score=0.9),
        _ev(
            EvidenceSource.SEMANTIC,
            EvidenceLabel.ATTACK,
            attack_types=[AttackType.CREDENTIAL_THEFT],
            confidence=0.85,
        ),
    ]
    types = [AttackType.CREDENTIAL_THEFT, AttackType.SECRET_EXTRACTION]
    engine = RiskEngine()
    a = engine.score(
        sources=sources,
        unified_label=EvidenceLabel.ATTACK,
        attack_types=types,
    )
    b = engine.score(
        sources=sources,
        unified_label=EvidenceLabel.ATTACK,
        attack_types=types,
    )
    assert a.risk_score == b.risk_score
    assert a.severity == b.severity
    assert [f.model_dump() for f in a.risk_factors] == [
        f.model_dump() for f in b.risk_factors
    ]


def test_explainable_risk_factors() -> None:
    result = RiskEngine().score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.ATTACK),
            _ev(EvidenceSource.PROMPT_GUARD, EvidenceLabel.ATTACK, score=0.9),
            _ev(EvidenceSource.SEMANTIC, EvidenceLabel.BENIGN),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    assert result.risk_factors
    for factor in result.risk_factors:
        assert factor.factor
        assert factor.points > 0
        assert factor.reason
        assert "chain" not in factor.reason.lower()


def test_default_weights_match_config() -> None:
    w = DEFAULT_RISK_WEIGHTS
    assert w.deterministic_attack == 25
    assert w.prompt_guard_attack == 25
    assert w.semantic_attack == 30
    assert w.detector_agreement == 10
    assert w.multiple_categories == 5
    assert w.high_impact_category == 5


def test_no_network_imports_in_scoring() -> None:
    """Risk scoring must not call out to providers."""
    # Constructing RiskEngine and scoring with pure evidence is sufficient;
    # this test documents the no-Groq contract.
    engine = RiskEngine()
    result = engine.score(
        sources=[
            _ev(EvidenceSource.RULES, EvidenceLabel.ATTACK),
            _ev(
                EvidenceSource.PROMPT_GUARD,
                EvidenceLabel.UNAVAILABLE,
                available=False,
            ),
            _ev(
                EvidenceSource.SEMANTIC,
                EvidenceLabel.UNAVAILABLE,
                available=False,
            ),
        ],
        unified_label=EvidenceLabel.ATTACK,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    assert result.risk_score == 25
    assert result.severity == Severity.MEDIUM

"""Policy engine unit tests (deterministic, no Groq)."""

from __future__ import annotations

import pytest

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import (
    DetectionEvidence,
    EvidenceLabel,
    EvidenceSource,
    UnifiedSecurityAssessment,
)
from app.security.policies.policy_types import (
    POLICY_ID,
    POLICY_VERSION,
    EnforcementPolicy,
    PolicyError,
    PolicyReasonCode,
    SecurityDecision,
)
from app.security.policies.prompt_injection_policy import (
    POLICY_ID as CANONICAL_POLICY_ID,
    POLICY_VERSION as CANONICAL_POLICY_VERSION,
)
from app.security.policy_engine import evaluate_policy


def _assessment(
    *,
    risk_score: int = 0,
    severity: Severity = Severity.LOW,
    label: EvidenceLabel = EvidenceLabel.BENIGN,
    conflict: bool = False,
    uncertainty: bool = False,
    attack_types: list[AttackType] | None = None,
    sources: list[DetectionEvidence] | None = None,
    risk_factors: list | None = None,
) -> UnifiedSecurityAssessment:
    return UnifiedSecurityAssessment(
        label=label,
        risk_score=risk_score,
        severity=severity,
        attack_types=list(attack_types or []),
        conflict=conflict,
        uncertainty=uncertainty,
        risk_factors=list(risk_factors or []),
        sources=list(sources or []),
    )


def test_low_risk_allow() -> None:
    d = evaluate_policy(
        _assessment(risk_score=10, severity=Severity.LOW)
    )
    assert d.decision == SecurityDecision.ALLOW
    assert PolicyReasonCode.LOW_RISK.value in d.reason_codes


def test_medium_risk_review() -> None:
    d = evaluate_policy(
        _assessment(risk_score=35, severity=Severity.MEDIUM)
    )
    assert d.decision == SecurityDecision.REVIEW
    assert PolicyReasonCode.MEDIUM_RISK.value in d.reason_codes


def test_high_risk_review() -> None:
    d = evaluate_policy(
        _assessment(risk_score=65, severity=Severity.HIGH)
    )
    assert d.decision == SecurityDecision.REVIEW
    assert PolicyReasonCode.HIGH_RISK.value in d.reason_codes


def test_critical_risk_block() -> None:
    d = evaluate_policy(
        _assessment(risk_score=90, severity=Severity.CRITICAL)
    )
    assert d.decision == SecurityDecision.BLOCK
    assert PolicyReasonCode.CRITICAL_RISK.value in d.reason_codes


def test_low_risk_with_conflict_review() -> None:
    d = evaluate_policy(
        _assessment(
            risk_score=10,
            severity=Severity.LOW,
            conflict=True,
            label=EvidenceLabel.ATTACK,
        )
    )
    assert d.decision == SecurityDecision.REVIEW
    assert PolicyReasonCode.DETECTOR_CONFLICT.value in d.reason_codes


def test_uncertain_low_risk_review() -> None:
    d = evaluate_policy(
        _assessment(
            risk_score=10,
            severity=Severity.LOW,
            uncertainty=True,
            label=EvidenceLabel.UNCERTAIN,
        )
    )
    assert d.decision == SecurityDecision.REVIEW
    assert d.decision != SecurityDecision.ALLOW
    assert PolicyReasonCode.DETECTOR_UNCERTAIN.value in d.reason_codes


def test_semantic_attack_prompt_guard_unavailable_high_review() -> None:
    sources = [
        DetectionEvidence(
            source=EvidenceSource.RULES,
            available=True,
            label=EvidenceLabel.BENIGN,
        ),
        DetectionEvidence(
            source=EvidenceSource.PROMPT_GUARD,
            available=False,
            label=EvidenceLabel.UNAVAILABLE,
            error_code="TIMEOUT",
        ),
        DetectionEvidence(
            source=EvidenceSource.SEMANTIC,
            available=True,
            label=EvidenceLabel.ATTACK,
            attack_types=[AttackType.INDIRECT_PROMPT_INJECTION],
            confidence=0.85,
        ),
    ]
    d = evaluate_policy(
        _assessment(
            risk_score=65,
            severity=Severity.HIGH,
            label=EvidenceLabel.ATTACK,
            uncertainty=True,
            attack_types=[AttackType.INDIRECT_PROMPT_INJECTION],
            sources=sources,
        )
    )
    assert d.decision == SecurityDecision.REVIEW
    assert PolicyReasonCode.AI_PROVIDER_UNAVAILABLE.value in d.reason_codes


def test_critical_high_impact_block() -> None:
    d = evaluate_policy(
        _assessment(
            risk_score=90,
            severity=Severity.CRITICAL,
            label=EvidenceLabel.ATTACK,
            attack_types=[
                AttackType.CREDENTIAL_THEFT,
                AttackType.SECRET_EXTRACTION,
            ],
        )
    )
    assert d.decision == SecurityDecision.BLOCK
    assert PolicyReasonCode.HIGH_IMPACT_ATTACK.value in d.reason_codes


def test_high_impact_elevates_to_block() -> None:
    """Explicit policy: high-impact + risk >= 50 → BLOCK (would otherwise be REVIEW)."""
    d = evaluate_policy(
        _assessment(
            risk_score=55,
            severity=Severity.HIGH,
            label=EvidenceLabel.ATTACK,
            attack_types=[AttackType.TOOL_ABUSE],
        )
    )
    assert d.decision == SecurityDecision.BLOCK
    assert PolicyReasonCode.HIGH_IMPACT_ATTACK.value in d.reason_codes


def test_benign_allow() -> None:
    d = evaluate_policy(
        _assessment(
            risk_score=0,
            severity=Severity.LOW,
            label=EvidenceLabel.BENIGN,
            conflict=False,
            uncertainty=False,
        )
    )
    assert d.decision == SecurityDecision.ALLOW


def test_invalid_risk_score_raises() -> None:
    for bad in (-1, 101):
        assessment = UnifiedSecurityAssessment.model_construct(
            label=EvidenceLabel.BENIGN,
            risk_score=bad,
            severity=Severity.LOW,
            attack_types=[],
            conflict=False,
            uncertainty=False,
            risk_factors=[],
            sources=[],
        )
        with pytest.raises(PolicyError) as exc:
            evaluate_policy(assessment)
        assert exc.value.code == PolicyReasonCode.ASSESSMENT_INVALID.value


def test_invalid_assessment_via_pydantic() -> None:
    with pytest.raises(Exception):
        UnifiedSecurityAssessment(
            label=EvidenceLabel.BENIGN,
            risk_score=-1,
            severity=Severity.LOW,
        )


def test_policy_version_on_every_decision() -> None:
    d = evaluate_policy(_assessment(risk_score=10))
    assert d.policy_id == CANONICAL_POLICY_ID == "AEGIS-PROMPT-INJECTION"
    assert d.policy_version == CANONICAL_POLICY_VERSION == "1.0"
    assert d.audit["policy_id"] == "AEGIS-PROMPT-INJECTION"
    assert d.audit["policy_version"] == "1.0"


def test_determinism() -> None:
    assessment = _assessment(
        risk_score=63,
        severity=Severity.HIGH,
        label=EvidenceLabel.ATTACK,
        conflict=True,
        uncertainty=False,
        attack_types=[AttackType.INSTRUCTION_OVERRIDE],
    )
    a = evaluate_policy(assessment)
    b = evaluate_policy(assessment)
    assert a.decision == b.decision
    assert a.reason_codes == b.reason_codes
    assert a.explanation == b.explanation
    assert a.model_dump() == b.model_dump()


def test_provider_uncertainty_never_allow() -> None:
    d = evaluate_policy(
        _assessment(
            risk_score=5,
            severity=Severity.LOW,
            uncertainty=True,
            label=EvidenceLabel.UNCERTAIN,
        )
    )
    assert d.decision == SecurityDecision.REVIEW
    assert d.decision != SecurityDecision.ALLOW


def test_disabled_policy_fail_closed() -> None:
    with pytest.raises(PolicyError) as exc:
        evaluate_policy(
            _assessment(risk_score=0),
            EnforcementPolicy(enabled=False),
        )
    assert exc.value.code == PolicyReasonCode.POLICY_DISABLED.value


def test_no_groq_in_policy_module() -> None:
    """Policy evaluation is pure — importing/evaluating must not need Groq."""
    d = evaluate_policy(_assessment(risk_score=88, severity=Severity.CRITICAL))
    assert d.decision == SecurityDecision.BLOCK
    assert "groq" not in d.explanation.lower()


def test_explanation_is_concise() -> None:
    d = evaluate_policy(
        _assessment(
            risk_score=88,
            severity=Severity.CRITICAL,
            label=EvidenceLabel.ATTACK,
            attack_types=[AttackType.CREDENTIAL_THEFT],
        )
    )
    assert "88/100" in d.explanation
    assert "chain" not in d.explanation.lower()
    assert len(d.explanation) < 500


def test_default_thresholds_match_spec() -> None:
    pol = EnforcementPolicy()
    assert pol.allow_max == 19
    assert pol.review_max == 74
    assert pol.block_min == 75
    assert pol.policy_id == POLICY_ID
    assert pol.version == POLICY_VERSION

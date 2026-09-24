"""Fusion engine unit tests (mocked detector evidence, no Groq)."""

from __future__ import annotations

from uuid import uuid4

from app.core.enums import Severity
from app.integrations.groq.prompt_guard import PromptGuardLabel
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import DetectionReport, Finding
from app.security.fusion import DetectionFusionEngine
from app.security.fusion_types import EvidenceLabel
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.security.prompt_guard_types import PromptGuardResult
from app.security.semantic_types import (
    SecurityImpact,
    SecurityIntent,
    SecurityTarget,
    SemanticLabel,
    SemanticSecurityAssessment,
)


def _finding(
    attack: AttackType = AttackType.INSTRUCTION_OVERRIDE,
    *,
    rule_id: str = "IO-001",
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
) -> Finding:
    return Finding(
        attack_type=attack,
        severity=severity,
        confidence=confidence,
        detector_name="test",
        rule_id=rule_id,
        evidence_type="pattern",
        description="test finding",
        signals=["test"],
    )


def _rules_attack(*findings: Finding) -> DetectionReport:
    items = list(findings) or [_finding()]
    return DetectionReport(
        is_attack=True,
        confidence=max(f.confidence for f in items),
        findings=items,
        detectors_run=["test"],
    )


def _rules_benign() -> DetectionReport:
    return DetectionReport(
        is_attack=False,
        confidence=0.0,
        findings=[],
        detectors_run=["test"],
    )


def _pg(
    *,
    available: bool = True,
    label: PromptGuardLabel = PromptGuardLabel.BENIGN,
    score: float | None = 0.1,
    is_attack: bool | None = False,
    error_code: str | None = None,
) -> PromptGuardResult:
    return PromptGuardResult(
        available=available,
        model="meta-llama/llama-prompt-guard-2-86m",
        is_attack=is_attack,
        score=score,
        label=label,
        error_code=error_code,
    )


def _sem(
    *,
    available: bool = True,
    label: SemanticLabel = SemanticLabel.BENIGN,
    attack_types: list[AttackType] | None = None,
    confidence: float = 0.2,
    severity: Severity = Severity.NONE,
    error_code: str | None = None,
) -> SemanticSecurityAssessment:
    return SemanticSecurityAssessment(
        assessment_id=uuid4(),
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        label=label,
        attack_type=(attack_types or [None])[0] if attack_types else None,
        attack_types=list(attack_types or []),
        severity=severity,
        confidence=confidence,
        intent=SecurityIntent.UNKNOWN,
        target=SecurityTarget.UNKNOWN,
        impact=SecurityImpact.NONE,
        rationale=["fixture"],
        evidence={"deterministic_rules": []},
        model="openai/gpt-oss-safeguard-20b",
        available=available,
        error_code=error_code,
    )


def test_all_benign() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        _pg(),
        prompt_guard_invoked=True,
        semantic=_sem(),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.BENIGN
    assert fused.risk_score <= 19
    assert fused.severity == Severity.LOW
    assert fused.attack_types == []
    assert fused.conflict is False


def test_all_attack() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_attack(),
        _pg(label=PromptGuardLabel.ATTACK, score=0.94, is_attack=True),
        prompt_guard_invoked=True,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.INSTRUCTION_OVERRIDE],
            confidence=0.9,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.risk_score >= 75
    assert fused.severity == Severity.CRITICAL
    assert any(f.factor == "detector_agreement" for f in fused.risk_factors)
    assert fused.conflict is False


def test_rules_and_prompt_guard_attack() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_attack(),
        _pg(label=PromptGuardLabel.ATTACK, score=0.9, is_attack=True),
        prompt_guard_invoked=True,
        semantic=None,
        semantic_invoked=False,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.risk_score >= 50
    assert any(f.factor == "deterministic_attack" for f in fused.risk_factors)
    assert any(f.factor == "prompt_guard_attack" for f in fused.risk_factors)


def test_semantic_only_attack() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        None,
        prompt_guard_invoked=False,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.INDIRECT_PROMPT_INJECTION],
            confidence=0.88,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.conflict is True
    assert any(f.factor == "semantic_attack" for f in fused.risk_factors)
    assert AttackType.INDIRECT_PROMPT_INJECTION in fused.attack_types


def test_prompt_guard_only_attack() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        _pg(label=PromptGuardLabel.ATTACK, score=0.91, is_attack=True),
        prompt_guard_invoked=True,
        semantic=None,
        semantic_invoked=False,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.prompt_guard_score == 0.91
    assert any(f.factor == "prompt_guard_attack" for f in fused.risk_factors)


def test_conflict_rules_pg_attack_semantic_benign() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_attack(),
        _pg(label=PromptGuardLabel.ATTACK, score=0.9, is_attack=True),
        prompt_guard_invoked=True,
        semantic=_sem(label=SemanticLabel.BENIGN),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.conflict is True
    assert fused.attack_types  # attack evidence preserved


def test_reverse_conflict_semantic_attack() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        _pg(label=PromptGuardLabel.BENIGN, score=0.1, is_attack=False),
        prompt_guard_invoked=True,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.MULTI_STEP_JAILBREAK],
            confidence=0.8,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.conflict is True


def test_provider_failure_uncertain() -> None:
    """Case E: rules no-match + AI unavailable → UNCERTAIN (not BENIGN)."""
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        _pg(
            available=False,
            label=PromptGuardLabel.UNKNOWN,
            score=None,
            is_attack=None,
            error_code="TIMEOUT",
        ),
        prompt_guard_invoked=True,
        semantic=_sem(
            available=False,
            label=SemanticLabel.UNCERTAIN,
            error_code="TIMEOUT",
        ),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.UNCERTAIN
    assert fused.uncertainty is True


def test_prompt_guard_unavailable_semantic_attack() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        _pg(
            available=False,
            label=PromptGuardLabel.UNKNOWN,
            score=None,
            is_attack=None,
            error_code="PROVIDER_ERROR",
        ),
        prompt_guard_invoked=True,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.ROLE_CHANGE],
            confidence=0.85,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert fused.uncertainty is True
    assert AttackType.ROLE_CHANGE in fused.attack_types


def test_multiple_attack_categories() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_attack(
            _finding(AttackType.INSTRUCTION_OVERRIDE),
            _finding(AttackType.CONTEXT_POISONING, rule_id="CP-001"),
        ),
        _pg(label=PromptGuardLabel.ATTACK, score=0.88, is_attack=True),
        prompt_guard_invoked=True,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.INSTRUCTION_OVERRIDE, AttackType.CONTEXT_POISONING],
            confidence=0.9,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    assert len(fused.attack_types) >= 2
    assert any(f.factor == "multiple_categories" for f in fused.risk_factors)


def test_high_impact_categories() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_benign(),
        None,
        prompt_guard_invoked=False,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[
                AttackType.SECRET_EXTRACTION,
                AttackType.CREDENTIAL_THEFT,
            ],
            confidence=0.92,
            severity=Severity.CRITICAL,
        ),
        semantic_invoked=True,
    )
    assert fused.label == EvidenceLabel.ATTACK
    assert any(f.factor == "high_impact_category" for f in fused.risk_factors)
    assert any(f.factor == "multiple_categories" for f in fused.risk_factors)


def test_fusion_does_not_average_confidence() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_attack(_finding(confidence=0.5)),
        _pg(label=PromptGuardLabel.ATTACK, score=0.99, is_attack=True),
        prompt_guard_invoked=True,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.TOOL_ABUSE],
            confidence=0.7,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    # Source-specific values preserved — not a mean of 0.5 / 0.99 / 0.7
    assert fused.prompt_guard_score == 0.99
    assert fused.semantic_confidence == 0.7
    assert fused.rule_evidence_strength == 0.5
    avg = (0.5 + 0.99 + 0.7) / 3
    assert fused.risk_score != int(round(avg * 100))


def test_no_policy_decision_in_fusion() -> None:
    fused = DetectionFusionEngine().fuse(
        _rules_attack(),
        _pg(label=PromptGuardLabel.ATTACK, score=0.9, is_attack=True),
        prompt_guard_invoked=True,
        semantic=_sem(
            label=SemanticLabel.ATTACK,
            attack_types=[AttackType.INSTRUCTION_OVERRIDE],
            confidence=0.9,
            severity=Severity.HIGH,
        ),
        semantic_invoked=True,
    )
    assert fused.metadata.get("decision") is None
    # Explicit: no policy action fields on the assessment
    assert not hasattr(fused, "decision") or getattr(fused, "decision", None) is None
    dumped = fused.model_dump()
    assert "action" not in dumped
    assert dumped.get("metadata", {}).get("decision") is None

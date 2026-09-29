"""Deterministic detection evidence for Phase 14 scenarios.

Runs real normalization + deterministic rules, then stubs Prompt Guard /
Safeguard responses (same pattern as Phase 11 OfflineChainEvaluator) so demos
are reproducible when the live PG model returns UNKNOWN.

Fusion and policy engines are the production ones — thresholds unchanged.
"""

from __future__ import annotations

from uuid import uuid4

from app.agents.runtime.scenarios import RuntimeScenario
from app.core.enums import Severity, SourceType
from app.integrations.groq.prompt_guard import PromptGuardLabel
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import DetectionReport, Finding
from app.security.fusion import DetectionFusionEngine
from app.security.policy_engine import evaluate_policy
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.security.prompt_guard_types import PromptGuardResult
from app.security.semantic_types import (
    SecurityImpact,
    SecurityIntent,
    SecurityTarget,
    SemanticLabel,
    SemanticSecurityAssessment,
)
from app.security.types import SecurityInput
from app.services.deterministic_detection import DeterministicDetectionService
from app.services.input_normalization import InputNormalizationService
from app.services.security_detection import DetectionPipelineResult


def _rules_attack(category: str = "instruction_override") -> DetectionReport:
    try:
        at = AttackType(category)
    except ValueError:
        at = AttackType.INSTRUCTION_OVERRIDE
    finding = Finding(
        attack_type=at,
        severity=Severity.HIGH,
        confidence=0.9,
        detector_name="runtime_stub",
        rule_id="RUNTIME-001",
        evidence_type="scenario",
        description="Phase 14 scenario attack stub",
        signals=["runtime_scenario"],
    )
    return DetectionReport(
        is_attack=True,
        confidence=0.9,
        findings=[finding],
        detectors_run=["runtime_stub"],
    )


def _pg(stub: str) -> tuple[PromptGuardResult | None, bool]:
    if stub == "NOT_INVOKED":
        return None, False
    if stub == "ATTACK":
        return (
            PromptGuardResult(
                available=True,
                model="runtime-stub",
                is_attack=True,
                score=0.92,
                label=PromptGuardLabel.ATTACK,
            ),
            True,
        )
    return (
        PromptGuardResult(
            available=True,
            model="runtime-stub",
            is_attack=False,
            score=0.08,
            label=PromptGuardLabel.BENIGN,
        ),
        True,
    )


def _sem(stub: str, category: str | None = None) -> tuple[SemanticSecurityAssessment | None, bool]:
    if stub == "NOT_INVOKED":
        return None, False
    attack_types: list[AttackType] = []
    if stub == "ATTACK":
        try:
            attack_types = [AttackType(category or "indirect_prompt_injection")]
        except ValueError:
            attack_types = [AttackType.INDIRECT_PROMPT_INJECTION]
    label = SemanticLabel.ATTACK if stub == "ATTACK" else SemanticLabel.BENIGN
    return (
        SemanticSecurityAssessment(
            assessment_id=uuid4(),
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            label=label,
            attack_types=attack_types,
            severity=Severity.HIGH if label == SemanticLabel.ATTACK else Severity.NONE,
            confidence=0.85 if label == SemanticLabel.ATTACK else 0.2,
            intent=SecurityIntent.UNKNOWN,
            target=SecurityTarget.UNKNOWN,
            impact=SecurityImpact.NONE,
            rationale=["runtime scenario stub"],
            evidence={},
            model="runtime-stub",
            available=True,
        ),
        True,
    )


def analyze_for_scenario(
    scenario: RuntimeScenario,
    *,
    inspect_text: str,
    source_type: SourceType,
    normalizer: InputNormalizationService | None = None,
    deterministic: DeterministicDetectionService | None = None,
    fusion: DetectionFusionEngine | None = None,
) -> DetectionPipelineResult:
    """
    Build DetectionPipelineResult for a scenario.

    Uses real normalize + rules (unless scenario forces attack stub), then
    scenario-declared PG/Semantic stubs, then production fusion + policy.
    """
    normalizer = normalizer or InputNormalizationService()
    deterministic = deterministic or DeterministicDetectionService()
    fusion = fusion or DetectionFusionEngine()

    security_input: SecurityInput = normalizer.normalize(inspect_text, source_type)
    det_real = deterministic.detect(security_input)

    stub = scenario.detection_stub  # BENIGN | ATTACK
    if stub == "ATTACK":
        # Prefer real rule hits; force attack report if rules quiet (indirect cases).
        det = det_real if det_real.is_attack else _rules_attack(
            scenario.attack_category or "indirect_prompt_injection"
        )
        pg, pg_inv = _pg("ATTACK")
        sem, sem_inv = _sem("ATTACK", scenario.attack_category)
    else:
        det = det_real
        # Both PG + Semantic BENIGN so fusion does not mark UNAVAILABLE→uncertainty
        # (same pattern as Phase 11 offline benign stubs). Thresholds unchanged.
        pg, pg_inv = _pg("BENIGN")
        sem, sem_inv = _sem("BENIGN")

    unified = fusion.fuse(
        det,
        pg,
        prompt_guard_invoked=pg_inv,
        semantic=sem,
        semantic_invoked=sem_inv,
    )
    decision = evaluate_policy(unified)

    return DetectionPipelineResult(
        security_input=security_input,
        deterministic=det,
        prompt_guard=pg,
        prompt_guard_invoked=pg_inv,
        semantic=sem,
        semantic_invoked=sem_inv,
        unified=unified,
        policy_decision=decision,
        metadata={
            "runtime_scenario": scenario.scenario_id,
            "detection_stub": stub,
            "note": (
                "Phase 14 scenario detection: real normalize/rules + stubbed "
                "PG/Semantic for determinism; fusion/policy thresholds unchanged."
            ),
            "decision": decision.decision.value,
        },
    )

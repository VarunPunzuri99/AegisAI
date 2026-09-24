"""Deterministic policy engine: UnifiedSecurityAssessment → PolicyDecision.

Pure evaluation — no LLM, HTTP, DB, or side effects.
"""

from __future__ import annotations

from app.core.enums import Severity
from app.security.fusion_types import EvidenceLabel, EvidenceSource, UnifiedSecurityAssessment
from app.security.policies.policy_types import (
    EnforcementPolicy,
    PolicyDecision,
    PolicyError,
    PolicyReasonCode,
    SecurityDecision,
    default_enforcement_policy,
)
from app.security.risk_config import SEVERITY_HIGH_MAX, SEVERITY_LOW_MAX, SEVERITY_MEDIUM_MAX


def evaluate_policy(
    assessment: UnifiedSecurityAssessment,
    policy: EnforcementPolicy | None = None,
) -> PolicyDecision:
    """
    Evaluate enforcement policy against a fused risk assessment.

    Order (deterministic):
      1. Validate policy
      2. Validate assessment risk bounds
      3. Inspect uncertainty / AI availability
      4. Inspect conflict
      5. Map risk score → base decision
      6. Inspect high-impact categories
      7. Finalize decision
      8. Generate reason codes + explanation
    """
    pol = policy if policy is not None else default_enforcement_policy()

    # 1. Validate policy
    _validate_policy(pol)

    # 2. Validate assessment
    _validate_assessment(assessment)

    reason_codes: list[str] = []

    # 3. Uncertainty / detector availability
    uncertainty = bool(assessment.uncertainty) or assessment.label == EvidenceLabel.UNCERTAIN
    ai_unavailable = _ai_provider_unavailable(assessment)
    if uncertainty:
        reason_codes.append(PolicyReasonCode.DETECTOR_UNCERTAIN.value)
    if ai_unavailable:
        reason_codes.append(PolicyReasonCode.AI_PROVIDER_UNAVAILABLE.value)

    # 4. Conflict
    conflict = bool(assessment.conflict)
    if conflict:
        reason_codes.append(PolicyReasonCode.DETECTOR_CONFLICT.value)

    # 5. Risk → base decision + risk reason codes
    score = assessment.risk_score
    base = _decision_from_risk(score, pol)
    reason_codes.extend(_risk_reason_codes(score, pol))

    # Agreement / multi-category from risk factors (evidence only)
    factor_names = {f.factor for f in assessment.risk_factors}
    if "detector_agreement" in factor_names:
        reason_codes.append(PolicyReasonCode.MULTIPLE_DETECTORS_AGREE.value)
    if "multiple_categories" in factor_names or len(assessment.attack_types) >= 2:
        if PolicyReasonCode.MULTIPLE_ATTACK_CATEGORIES.value not in reason_codes:
            reason_codes.append(PolicyReasonCode.MULTIPLE_ATTACK_CATEGORIES.value)

    decision = base

    # 6. High-impact elevation (explicit policy threshold)
    high_impact = [
        t for t in assessment.attack_types if t in pol.high_impact_attack_types
    ]
    if high_impact and score >= pol.high_impact_block_min_risk:
        reason_codes.append(PolicyReasonCode.HIGH_IMPACT_ATTACK.value)
        if decision != SecurityDecision.BLOCK:
            decision = SecurityDecision.BLOCK

    # 7. Uncertainty / conflict never silently ALLOW
    if pol.uncertain_forces_review and uncertainty and decision == SecurityDecision.ALLOW:
        decision = SecurityDecision.REVIEW
    if (
        pol.conflict_upgrades_allow_to_review
        and conflict
        and decision == SecurityDecision.ALLOW
    ):
        decision = SecurityDecision.REVIEW

    # Deduplicate reason codes preserving order
    seen: set[str] = set()
    ordered_codes: list[str] = []
    for code in reason_codes:
        if code not in seen:
            seen.add(code)
            ordered_codes.append(code)

    explanation = _build_explanation(
        decision=decision,
        score=score,
        severity=assessment.severity,
        conflict=conflict,
        uncertainty=uncertainty,
        high_impact=bool(high_impact),
        attack_types=assessment.attack_types,
        agreement="detector_agreement" in factor_names,
    )

    audit = {
        "policy_id": pol.policy_id,
        "policy_version": pol.version,
        "decision": decision.value,
        "risk_score": score,
        "severity": assessment.severity.value,
        "attack_types": [t.value for t in assessment.attack_types],
        "reason_codes": ordered_codes,
        "conflict": conflict,
        "uncertainty": uncertainty,
        "label": assessment.label.value,
        "ai_provider_unavailable": ai_unavailable,
    }

    return PolicyDecision(
        decision=decision,
        policy_id=pol.policy_id,
        policy_version=pol.version,
        risk_score=score,
        severity=assessment.severity,
        attack_types=list(assessment.attack_types),
        conflict=conflict,
        uncertainty=uncertainty,
        reason_codes=ordered_codes,
        explanation=explanation,
        audit=audit,
        metadata={
            "enforcement": True,
            "note": (
                "Policy decision only. No HTTP rejection, agent halt, "
                "or tool denial is performed in Phase 8."
            ),
        },
    )


def _validate_policy(policy: EnforcementPolicy) -> None:
    if not policy.enabled:
        raise PolicyError(
            PolicyReasonCode.POLICY_DISABLED.value,
            "Enforcement policy is disabled; refusing to evaluate (fail-closed).",
        )
    if policy.policy_id != policy.policy_id.strip() or not policy.policy_id:
        raise PolicyError(
            PolicyReasonCode.POLICY_INVALID.value,
            "Policy ID is missing or invalid.",
        )
    if not policy.version:
        raise PolicyError(
            PolicyReasonCode.POLICY_INVALID.value,
            "Policy version is missing.",
        )
    # Band consistency (also enforced by Pydantic on construction)
    if not (0 <= policy.allow_max < policy.review_max < policy.block_min <= 100):
        raise PolicyError(
            PolicyReasonCode.POLICY_INVALID.value,
            "Policy risk thresholds are inconsistent.",
        )


def _validate_assessment(assessment: UnifiedSecurityAssessment) -> None:
    score = assessment.risk_score
    if not isinstance(score, int) or isinstance(score, bool):
        raise PolicyError(
            PolicyReasonCode.ASSESSMENT_INVALID.value,
            f"Invalid risk_score type: {type(score)!r}",
        )
    if score < 0 or score > 100:
        raise PolicyError(
            PolicyReasonCode.ASSESSMENT_INVALID.value,
            f"risk_score must be in 0–100, got {score}",
        )


def _ai_provider_unavailable(assessment: UnifiedSecurityAssessment) -> bool:
    for src in assessment.sources:
        if src.source in {EvidenceSource.PROMPT_GUARD, EvidenceSource.SEMANTIC}:
            if not src.available or src.label == EvidenceLabel.UNAVAILABLE:
                if src.error_code not in {"NOT_INVOKED", None}:
                    return True
    return False


def _decision_from_risk(score: int, policy: EnforcementPolicy) -> SecurityDecision:
    if score <= policy.allow_max:
        return SecurityDecision.ALLOW
    if score < policy.block_min:
        return SecurityDecision.REVIEW
    return SecurityDecision.BLOCK


def _risk_reason_codes(score: int, policy: EnforcementPolicy) -> list[str]:
    if score <= SEVERITY_LOW_MAX:
        return [PolicyReasonCode.LOW_RISK.value]
    if score <= SEVERITY_MEDIUM_MAX:
        return [PolicyReasonCode.MEDIUM_RISK.value]
    if score <= SEVERITY_HIGH_MAX:
        return [PolicyReasonCode.HIGH_RISK.value]
    return [PolicyReasonCode.CRITICAL_RISK.value]


def _build_explanation(
    *,
    decision: SecurityDecision,
    score: int,
    severity: Severity,
    conflict: bool,
    uncertainty: bool,
    high_impact: bool,
    attack_types: list,
    agreement: bool,
) -> str:
    parts: list[str] = [
        f"{decision.value} because the unified risk score was {score}/100 ({severity.value})."
    ]
    if agreement:
        parts.append("Independent detectors agreed on attack evidence.")
    if high_impact and attack_types:
        names = ", ".join(t.value for t in attack_types)
        parts.append(f"High-impact attack types present: {names}.")
    elif attack_types:
        names = ", ".join(t.value for t in attack_types)
        parts.append(f"Attack types: {names}.")
    if conflict:
        parts.append("Detector results conflict.")
    if uncertainty:
        parts.append("Security assessment is uncertain or detectors were unavailable.")
    if decision == SecurityDecision.REVIEW and (conflict or uncertainty):
        parts.append("REVIEW required rather than ALLOW.")
    return " ".join(parts)

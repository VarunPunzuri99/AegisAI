"""Normalize detector outputs into DetectionEvidence and fuse labels."""

from __future__ import annotations

from app.core.enums import Severity
from app.integrations.groq.prompt_guard import PromptGuardLabel
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import DetectionReport
from app.security.fusion_types import (
    DetectionEvidence,
    EvidenceLabel,
    EvidenceSource,
    PipelineInputs,
    UnifiedSecurityAssessment,
)
from app.security.prompt_guard_types import PromptGuardResult
from app.security.risk_engine import RiskEngine
from app.security.semantic_types import SemanticLabel, SemanticSecurityAssessment


class DetectionFusionEngine:
    """Combine RULES + Prompt Guard + Semantic evidence without policy actions."""

    def __init__(self, risk_engine: RiskEngine | None = None) -> None:
        self.risk_engine = risk_engine or RiskEngine()

    def fuse(
        self,
        deterministic: DetectionReport,
        prompt_guard: PromptGuardResult | None = None,
        *,
        prompt_guard_invoked: bool = False,
        semantic: SemanticSecurityAssessment | None = None,
        semantic_invoked: bool = False,
    ) -> UnifiedSecurityAssessment:
        sources = [
            self._from_rules(deterministic),
            self._from_prompt_guard(prompt_guard, invoked=prompt_guard_invoked),
            self._from_semantic(semantic, invoked=semantic_invoked),
        ]
        return self._fuse_sources(sources, deterministic, prompt_guard, semantic)

    def fuse_pipeline(self, inputs: PipelineInputs) -> UnifiedSecurityAssessment:
        return self.fuse(
            inputs.deterministic,
            inputs.prompt_guard,
            prompt_guard_invoked=inputs.prompt_guard_invoked,
            semantic=inputs.semantic,
            semantic_invoked=inputs.semantic_invoked,
        )

    def _fuse_sources(
        self,
        sources: list[DetectionEvidence],
        deterministic: DetectionReport,
        prompt_guard: PromptGuardResult | None,
        semantic: SemanticSecurityAssessment | None,
    ) -> UnifiedSecurityAssessment:
        available = [s for s in sources if s.available]
        attack_sources = [s for s in available if s.label == EvidenceLabel.ATTACK]
        benign_sources = [s for s in available if s.label == EvidenceLabel.BENIGN]
        ai_failed = any(
            s.source in {EvidenceSource.PROMPT_GUARD, EvidenceSource.SEMANTIC}
            and s.label == EvidenceLabel.UNAVAILABLE
            and s.error_code not in {"NOT_INVOKED", None}
            for s in sources
        )

        attack_types = self._merge_attack_types(sources)
        conflict = bool(attack_sources) and bool(benign_sources)

        if attack_sources:
            unified = EvidenceLabel.ATTACK
        elif (
            available
            and all(s.label == EvidenceLabel.BENIGN for s in available)
            and not (
                # Case E: rules no-match alone must not fail-open to BENIGN
                # when invoked AI detectors failed / are unavailable.
                ai_failed
                and all(s.source == EvidenceSource.RULES for s in available)
            )
        ):
            unified = EvidenceLabel.BENIGN
        else:
            # No available detectors, all uncertain, AI failure with no match,
            # or mix of uncertain only.
            unified = EvidenceLabel.UNCERTAIN

        uncertainty = (
            unified == EvidenceLabel.UNCERTAIN
            or any(s.label == EvidenceLabel.UNAVAILABLE for s in sources)
            or any(
                s.available and s.label == EvidenceLabel.UNCERTAIN for s in sources
            )
            or conflict
            or ai_failed
        )

        risk = self.risk_engine.score(
            sources=sources,
            unified_label=unified,
            attack_types=attack_types,
        )

        rules_ev = next(s for s in sources if s.source == EvidenceSource.RULES)
        pg_ev = next(s for s in sources if s.source == EvidenceSource.PROMPT_GUARD)
        sem_ev = next(s for s in sources if s.source == EvidenceSource.SEMANTIC)

        return UnifiedSecurityAssessment(
            label=unified,
            risk_score=risk.risk_score,
            severity=risk.severity,
            attack_types=attack_types,
            conflict=conflict,
            uncertainty=uncertainty,
            risk_factors=risk.risk_factors,
            sources=sources,
            rule_evidence_strength=rules_ev.confidence,
            prompt_guard_score=pg_ev.score,
            semantic_confidence=sem_ev.confidence,
            detector_results={
                "rules": {
                    "label": rules_ev.label.value,
                    "is_attack": deterministic.is_attack,
                    "finding_count": len(deterministic.findings),
                    "confidence": deterministic.confidence,
                },
                "prompt_guard": {
                    "invoked": prompt_guard is not None,
                    "available": pg_ev.available,
                    "label": pg_ev.label.value,
                    "score": pg_ev.score,
                    "error_code": pg_ev.error_code,
                },
                "semantic": {
                    "invoked": semantic is not None,
                    "available": sem_ev.available,
                    "label": sem_ev.label.value,
                    "confidence": sem_ev.confidence,
                    "error_code": sem_ev.error_code,
                },
            },
            metadata={
                "decision": None,
                "note": (
                    "Fusion and risk are evidence layers only. "
                    "No ALLOW/BLOCK/REVIEW decision in Phase 7."
                ),
                "agreement_count": len(attack_sources),
            },
        )

    def _from_rules(self, report: DetectionReport) -> DetectionEvidence:
        attack_types = sorted(
            {f.attack_type for f in report.findings},
            key=lambda a: a.value,
        )
        if report.is_attack or any(
            f.severity in {Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM}
            for f in report.findings
        ):
            label = EvidenceLabel.ATTACK
        elif report.findings:
            # Weak / meta LOW findings only
            label = EvidenceLabel.UNCERTAIN
        else:
            label = EvidenceLabel.BENIGN

        return DetectionEvidence(
            source=EvidenceSource.RULES,
            available=True,
            label=label,
            attack_types=list(attack_types),
            confidence=report.confidence if report.findings else (
                0.1 if label == EvidenceLabel.BENIGN else 0.0
            ),
            score=None,
            severity=max(
                (f.severity for f in report.findings),
                default=Severity.NONE,
                key=lambda s: _sev_rank(s),
            ),
            evidence={
                "rule_ids": [f.rule_id for f in report.findings],
                "finding_count": len(report.findings),
            },
            metadata={"detectors_run": list(report.detectors_run)},
        )

    def _from_prompt_guard(
        self,
        result: PromptGuardResult | None,
        *,
        invoked: bool,
    ) -> DetectionEvidence:
        if result is None or not invoked:
            return DetectionEvidence(
                source=EvidenceSource.PROMPT_GUARD,
                available=False,
                label=EvidenceLabel.UNAVAILABLE,
                evidence={},
                metadata={"invoked": False},
                error_code="NOT_INVOKED" if not invoked else "MISSING_RESULT",
            )
        if not result.available:
            return DetectionEvidence(
                source=EvidenceSource.PROMPT_GUARD,
                available=False,
                label=EvidenceLabel.UNAVAILABLE,
                evidence={},
                metadata={"invoked": True, "model": result.model},
                error_code=result.error_code or "UNAVAILABLE",
            )

        if result.label == PromptGuardLabel.ATTACK or result.is_attack is True:
            label = EvidenceLabel.ATTACK
        elif result.label == PromptGuardLabel.BENIGN or result.is_attack is False:
            label = EvidenceLabel.BENIGN
        else:
            label = EvidenceLabel.UNCERTAIN

        return DetectionEvidence(
            source=EvidenceSource.PROMPT_GUARD,
            available=True,
            label=label,
            attack_types=[],
            confidence=None,
            score=result.score,
            evidence={
                "label": result.label.value,
                "chunk_count": len(result.chunk_results),
            },
            metadata={"model": result.model, "latency_ms": result.latency_ms},
            error_code=result.error_code,
        )

    def _from_semantic(
        self,
        result: SemanticSecurityAssessment | None,
        *,
        invoked: bool,
    ) -> DetectionEvidence:
        if result is None or not invoked:
            return DetectionEvidence(
                source=EvidenceSource.SEMANTIC,
                available=False,
                label=EvidenceLabel.UNAVAILABLE,
                evidence={},
                metadata={"invoked": False},
                error_code="NOT_INVOKED" if not invoked else "MISSING_RESULT",
            )
        if not result.available:
            return DetectionEvidence(
                source=EvidenceSource.SEMANTIC,
                available=False,
                label=EvidenceLabel.UNAVAILABLE,
                attack_types=list(result.attack_types),
                confidence=result.confidence,
                evidence=dict(result.evidence),
                metadata={
                    "invoked": True,
                    "policy_id": result.policy_id,
                    "policy_version": result.policy_version,
                },
                error_code=result.error_code or "UNAVAILABLE",
            )

        if result.label == SemanticLabel.ATTACK:
            label = EvidenceLabel.ATTACK
        elif result.label == SemanticLabel.BENIGN:
            label = EvidenceLabel.BENIGN
        else:
            label = EvidenceLabel.UNCERTAIN

        return DetectionEvidence(
            source=EvidenceSource.SEMANTIC,
            available=True,
            label=label,
            attack_types=list(result.attack_types),
            confidence=result.confidence,
            score=None,
            severity=result.severity,
            evidence={
                "intent": result.intent.value,
                "target": result.target.value,
                "impact": result.impact.value,
                "rationale": list(result.rationale),
                "authoritative": dict(result.evidence),
            },
            metadata={
                "model": result.model,
                "policy_id": result.policy_id,
                "policy_version": result.policy_version,
            },
            error_code=result.error_code,
        )

    @staticmethod
    def _merge_attack_types(sources: list[DetectionEvidence]) -> list[AttackType]:
        merged: list[AttackType] = []
        for src in sources:
            for at in src.attack_types:
                if at not in merged:
                    merged.append(at)
        return sorted(merged, key=lambda a: a.value)


def _sev_rank(severity: Severity) -> int:
    order = {
        Severity.NONE: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return order.get(severity, 0)

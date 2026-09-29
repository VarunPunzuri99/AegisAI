"""Orchestrates normalization → detectors → fusion → risk → policy decision."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import Settings, get_settings
from app.core.enums import SourceType
from app.observability.provider_metrics import get_provider_registry
from app.observability.timing import PipelineTimer, PipelineTiming
from app.observability.types import ProviderName
from app.security.detectors.types import DetectionReport
from app.security.fusion import DetectionFusionEngine
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import EnforcementPolicy, PolicyDecision
from app.security.policy_engine import evaluate_policy
from app.security.prompt_guard_detector import PromptGuardDetector
from app.security.prompt_guard_types import PromptGuardResult
from app.security.semantic_analyzer import SemanticSecurityAnalyzer
from app.security.semantic_types import SemanticSecurityAssessment
from app.security.types import SecurityInput
from app.services.deterministic_detection import DeterministicDetectionService
from app.services.input_normalization import InputNormalizationService


class DetectionPipelineResult(BaseModel):
    """Full detection + risk + policy decision (no external enforcement)."""

    model_config = ConfigDict(frozen=True)

    security_input: SecurityInput
    deterministic: DetectionReport
    prompt_guard: Optional[PromptGuardResult] = None
    prompt_guard_invoked: bool = False
    semantic: Optional[SemanticSecurityAssessment] = None
    semantic_invoked: bool = False
    unified: Optional[UnifiedSecurityAssessment] = None
    policy_decision: Optional[PolicyDecision] = None
    timing: Optional[PipelineTiming] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityDetectionService:
    """Detection pipeline with policy decision; no DB persistence or side effects."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        normalizer: InputNormalizationService | None = None,
        deterministic: DeterministicDetectionService | None = None,
        prompt_guard: PromptGuardDetector | None = None,
        semantic: SemanticSecurityAnalyzer | None = None,
        fusion: DetectionFusionEngine | None = None,
        policy: EnforcementPolicy | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.normalizer = normalizer or InputNormalizationService(settings=self.settings)
        self.deterministic = deterministic or DeterministicDetectionService()
        self.prompt_guard = prompt_guard or PromptGuardDetector(settings=self.settings)
        self.semantic = semantic or SemanticSecurityAnalyzer(settings=self.settings)
        self.fusion = fusion or DetectionFusionEngine()
        self.policy = policy

    def analyze(self, content: str, source_type: SourceType) -> DetectionPipelineResult:
        timer = PipelineTimer()
        registry = get_provider_registry()

        with timer.stage("normalization"):
            security_input = self.normalizer.normalize(content, source_type)

        with timer.stage("deterministic"):
            det = self.deterministic.detect(security_input)

        invoke_pg = self.prompt_guard.should_invoke(det)
        pg: PromptGuardResult | None = None
        if invoke_pg:
            with timer.stage("prompt_guard"):
                pg = self.prompt_guard.detect(security_input)
            # Record sanitized provider observation (no prompt content).
            registry.record_call(
                provider=ProviderName.PROMPT_GUARD,
                model=getattr(pg, "model", None) if pg else self.settings.prompt_guard_model,
                operation="detect",
                success=bool(pg and pg.available and not pg.error_code),
                latency_ms=float(pg.latency_ms) if pg else 0.0,
                error_code=pg.error_code if pg else None,
                response_empty=(pg.error_code == "EMPTY_RESPONSE") if pg else False,
            )
            registry.record_call(
                provider=ProviderName.GROQ,
                model=getattr(pg, "model", None) if pg else self.settings.prompt_guard_model,
                operation="prompt_guard",
                success=bool(pg and pg.available and not pg.error_code),
                latency_ms=float(pg.latency_ms) if pg else 0.0,
                error_code=pg.error_code if pg else None,
                response_empty=(pg.error_code == "EMPTY_RESPONSE") if pg else False,
            )

        invoke_sem = self.semantic.should_invoke(det)
        sem: SemanticSecurityAssessment | None = None
        if invoke_sem:
            with timer.stage("semantic"):
                sem = self.semantic.analyze(security_input, det, pg)
            registry.record_call(
                provider=ProviderName.SAFEGUARD,
                model=getattr(sem, "model", None) if sem else self.settings.safeguard_model,
                operation="analyze",
                success=bool(sem and sem.available and not sem.error_code),
                latency_ms=float(sem.latency_ms) if sem and sem.latency_ms else 0.0,
                error_code=sem.error_code if sem else None,
                response_empty=(sem.error_code == "EMPTY_RESPONSE") if sem else False,
            )
            registry.record_call(
                provider=ProviderName.GROQ,
                model=getattr(sem, "model", None) if sem else self.settings.safeguard_model,
                operation="safeguard",
                success=bool(sem and sem.available and not sem.error_code),
                latency_ms=float(sem.latency_ms) if sem and sem.latency_ms else 0.0,
                error_code=sem.error_code if sem else None,
                response_empty=(sem.error_code == "EMPTY_RESPONSE") if sem else False,
            )

        # Fusion includes deterministic risk scoring (Phase 7). Timing is combined;
        # risk_ms reports 0 with metadata note to avoid double-counting.
        with timer.stage("fusion"):
            unified = self.fusion.fuse(
                det,
                pg,
                prompt_guard_invoked=invoke_pg,
                semantic=sem,
                semantic_invoked=invoke_sem,
            )
        timer.record("risk", 0.0)

        with timer.stage("policy"):
            decision = evaluate_policy(unified, self.policy)

        timing = timer.finish()

        return DetectionPipelineResult(
            security_input=security_input,
            deterministic=det,
            prompt_guard=pg,
            prompt_guard_invoked=invoke_pg,
            semantic=sem,
            semantic_invoked=invoke_sem,
            unified=unified,
            policy_decision=decision,
            timing=timing,
            metadata={
                "prompt_guard_mode": self.settings.prompt_guard_mode,
                "safeguard_mode": self.settings.safeguard_mode,
                "fusion": True,
                "policy": True,
                "decision": decision.decision.value,
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "reason_codes": list(decision.reason_codes),
                "timing": timing.model_dump(),
                "risk_timing_note": "risk scored inside fusion; risk_ms=0 to avoid double-count",
                "note": (
                    "Policy decision computed. "
                    "No external enforcement (HTTP reject / agent / tools) in Phase 8."
                ),
            },
        )

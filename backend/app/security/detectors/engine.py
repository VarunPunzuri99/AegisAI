"""Deterministic detection engine — aggregates modular detectors."""

from __future__ import annotations

from app.core.enums import Severity
from app.security.detectors.context_manipulation import ContextManipulationDetector
from app.security.detectors.data_exfiltration import DataExfiltrationDetector
from app.security.detectors.indirect_injection import IndirectInjectionDetector
from app.security.detectors.instruction_override import InstructionOverrideDetector
from app.security.detectors.jailbreak import JailbreakDetector
from app.security.detectors.obfuscation import ObfuscationDetector
from app.security.detectors.prompt_extraction import PromptExtractionDetector
from app.security.detectors.protocol import Detector
from app.security.detectors.role_manipulation import RoleManipulationDetector
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.tool_manipulation import ToolManipulationDetector
from app.security.detectors.types import DetectionReport, Finding
from app.security.types import SecurityInput

_SEVERITY_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CRITICAL_COMBO = frozenset(
    {
        AttackType.INSTRUCTION_OVERRIDE,
        AttackType.TOOL_ABUSE,
        AttackType.CREDENTIAL_THEFT,
    }
)


def _default_detectors() -> list[Detector]:
    return [
        InstructionOverrideDetector(),
        RoleManipulationDetector(),
        PromptExtractionDetector(),
        JailbreakDetector(),
        IndirectInjectionDetector(),
        ObfuscationDetector(),
        ToolManipulationDetector(),
        DataExfiltrationDetector(),
        ContextManipulationDetector(),
    ]


class DeterministicDetectionEngine:
    """Run all deterministic detectors against a ``SecurityInput``.

    Produces a ``DetectionReport`` with evidence. Does **not** decide
    ALLOW/BLOCK (policy engine is later). Confidence values are heuristics.
    """

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = detectors if detectors is not None else _default_detectors()

    def detect(self, security_input: SecurityInput) -> DetectionReport:
        findings: list[Finding] = []
        ran: list[str] = []

        for detector in self.detectors:
            ran.append(detector.name)
            findings.extend(detector.detect(security_input))

        findings = self._correlate(findings)

        is_attack = self._is_attack(findings)
        confidence = max((f.confidence for f in findings), default=0.0)
        if len({f.attack_type for f in findings}) >= 3:
            confidence = min(1.0, max(confidence, 0.95))

        return DetectionReport(
            is_attack=is_attack,
            confidence=round(confidence, 4),
            findings=findings,
            detectors_run=ran,
            metadata={
                "finding_count": len(findings),
                "attack_types": sorted({f.attack_type.value for f in findings}),
                "confidence_note": (
                    "Heuristic confidence scores, not calibrated probabilities."
                ),
                "decision": None,
                "note": (
                    "Deterministic detection is one security layer and does not "
                    "provide complete prompt-injection prevention. "
                    "It does not make the final ALLOW/BLOCK decision."
                ),
            },
        )

    def _correlate(self, findings: list[Finding]) -> list[Finding]:
        """Boost severity when multiple high-signal categories co-occur."""
        if len(findings) < 2:
            return findings

        types = {f.attack_type for f in findings}

        if _CRITICAL_COMBO.issubset(types):
            upgraded: list[Finding] = []
            for f in findings:
                if f.attack_type in _CRITICAL_COMBO:
                    upgraded.append(
                        f.model_copy(
                            update={
                                "severity": Severity.CRITICAL,
                                "confidence": min(1.0, max(f.confidence, 0.95)),
                                "evidence_type": (
                                    "multiple_correlated_signals"
                                    if f.evidence_type == "pattern"
                                    else f.evidence_type
                                ),
                            }
                        )
                    )
                else:
                    upgraded.append(f)
            return upgraded

        highish = [
            f
            for f in findings
            if _SEVERITY_RANK[f.severity] >= _SEVERITY_RANK[Severity.HIGH]
        ]
        if len(highish) >= 2:
            high_ids = {id(f) for f in highish}
            return [
                f.model_copy(update={"confidence": min(1.0, max(f.confidence, 0.92))})
                if id(f) in high_ids
                else f
                for f in findings
            ]

        return findings

    @staticmethod
    def _is_attack(findings: list[Finding]) -> bool:
        if not findings:
            return False
        for f in findings:
            if _SEVERITY_RANK[f.severity] >= _SEVERITY_RANK[Severity.MEDIUM]:
                return True
            if f.confidence >= 0.75:
                return True
        return False

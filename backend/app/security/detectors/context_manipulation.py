"""Context manipulation / fake boundary detector (taxonomy: context_poisoning)."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, is_meta_discussion, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

_FAKE_BOUNDARY = re.compile(
    r"("
    r"<\s*system\b[^>]*>|"
    r"</\s*system\s*>|"
    r"\[(?:END\s+)?SYSTEM\]|"
    r"\[USER\]|"
    r"^SYSTEM\s*:\s*"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

_BOUNDARY_PLUS_OVERRIDE = re.compile(
    r"(?i)(<\s*system\b[^>]*>|SYSTEM\s*:).{0,120}"
    r"(ignore|unrestricted|no\s+safety|override)"
)


class ContextManipulationDetector:
    name = "context_manipulation_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)
        struct = security_input.structure_flags

        for match in _FAKE_BOUNDARY.finditer(text):
            conf = 0.30 if meta else 0.75
            sev = Severity.LOW if meta else Severity.MEDIUM
            findings.append(
                make_finding(
                    attack_type=AttackType.CONTEXT_POISONING,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="CM-001",
                    evidence_type="role_marker",
                    description="Detected forged system/user message boundary markers.",
                    signals=[match.group(0)],
                )
            )

        for match in _BOUNDARY_PLUS_OVERRIDE.finditer(text):
            conf = 0.35 if meta else 0.93
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.CONTEXT_POISONING,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="CM-002",
                    evidence_type="multiple_correlated_signals",
                    description="Fake system boundary combined with override/jailbreak language.",
                    signals=[match.group(0)],
                )
            )

        if (
            struct.get("role_marker_detected")
            and struct.get("instruction_boundary_detected")
            and not meta
            and not findings
        ):
            findings.append(
                make_finding(
                    attack_type=AttackType.CONTEXT_POISONING,
                    severity=Severity.MEDIUM,
                    confidence=0.60,
                    detector_name=self.name,
                    rule_id="CM-003",
                    evidence_type="role_marker",
                    description="Role and instruction boundary markers co-occur in content.",
                    signals=["role_marker+instruction_boundary"],
                    location="structure_flags",
                )
            )

        return findings

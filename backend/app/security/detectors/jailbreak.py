"""Jailbreak / safety-bypass detector (taxonomy: multi_step_jailbreak)."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, is_meta_discussion, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

_JAILBREAK = re.compile(
    r"(?i)\b("
    r"bypass\s+(?:all\s+)?(?:safety|safeguards?|restrictions?|filters?)|"
    r"disable\s+(?:all\s+)?(?:safety|safeguards?|filters?)|"
    r"unrestricted\s+mode|"
    r"no\s+safety\s+restrictions?|"
    r"ignore\s+(?:your\s+)?safety\s+polic(?:y|ies)|"
    r"dan\s+mode|do\s+anything\s+now|"
    r"jailbreak\s+(?:the\s+)?(?:model|assistant|ai)"
    r")\b"
)


class JailbreakDetector:
    name = "jailbreak_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)

        for match in _JAILBREAK.finditer(text):
            conf = 0.33 if meta else 0.89
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.MULTI_STEP_JAILBREAK,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="JB-001",
                    evidence_type="pattern",
                    description="Detected structural jailbreak / safety-bypass language.",
                    signals=[match.group(0)],
                )
            )
        return findings

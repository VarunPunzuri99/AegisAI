"""System prompt / secret extraction detector (taxonomy: secret_extraction)."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, is_meta_discussion, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

_EXTRACT = re.compile(
    r"(?i)\b("
    r"reveal|show|print|disclose|output|tell\s+me|repeat|dump|"
    r"expose|leak"
    r")\b.{0,48}\b("
    r"system\s+prompt|hidden\s+instructions?|system\s+message|"
    r"developer\s+message|secret\s+prompt|internal\s+instructions?|"
    r"hidden\s+prompt|system\s+instructions?"
    r")\b"
)


class PromptExtractionDetector:
    name = "prompt_extraction_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)

        for match in _EXTRACT.finditer(text):
            conf = 0.34 if meta else 0.92
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.SECRET_EXTRACTION,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="SPE-001",
                    evidence_type="pattern",
                    description="Detected an attempt to extract hidden system/developer instructions.",
                    signals=[match.group(0)],
                )
            )
        return findings

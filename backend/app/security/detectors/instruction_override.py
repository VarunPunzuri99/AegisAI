"""Instruction override deterministic detector."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import (
    analysis_text,
    is_meta_discussion,
    make_finding,
)
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

# Relationship: discard/override + prior/system instructions
_OVERRIDE = re.compile(
    r"(?i)\b("
    r"ignore|disregard|forget|override|replace|discard|cancel|"
    r"do\s+not\s+follow|stop\s+following"
    r")\b.{0,40}\b("
    r"previous|prior|above|earlier|original|system|developer|safety|your"
    r")\b.{0,40}\b("
    r"instructions?|rules?|prompts?|policies|guidelines|constraints"
    r")\b"
)

_INSTEAD = re.compile(
    r"(?i)\b("
    r"(?:follow|obey|use)\s+(?:these|the\s+following|my)\s+instructions?\s+instead|"
    r"instructions?\s+above\s+are\s+(?:invalid|void|cancelled)|"
    r"new\s+instructions?\s+(?:override|supersede)"
    r")\b"
)


class InstructionOverrideDetector:
    name = "instruction_override_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)

        for match in _OVERRIDE.finditer(text):
            conf = 0.35 if meta else 0.88
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.INSTRUCTION_OVERRIDE,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="IO-001",
                    evidence_type="pattern",
                    description=(
                        "Detected an attempt to override or discard prior instructions."
                        if not meta
                        else "Instruction-override phrasing appears in a discursive/meta context."
                    ),
                    signals=[match.group(0)],
                )
            )

        for match in _INSTEAD.finditer(text):
            conf = 0.30 if meta else 0.86
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.INSTRUCTION_OVERRIDE,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="IO-002",
                    evidence_type="pattern",
                    description="Detected replacement of prior rules with new instructions.",
                    signals=[match.group(0)],
                )
            )

        return findings

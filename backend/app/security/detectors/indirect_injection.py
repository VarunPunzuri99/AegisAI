"""Indirect prompt injection detector."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, is_meta_discussion, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

_INDIRECT = re.compile(
    r"(?i)\b("
    r"(?:ai|llm)\s+assistant\s*:|"
    r"when\s+(?:an?\s+)?(?:ai|assistant|llm)\s+(?:reads?|processes?|sees)\s+this|"
    r"to\s+the\s+(?:ai|assistant)\s+reading\s+this|"
    r"assistant[,:]?\s+disregard\s+the|"
    r"hidden\s+instruction\s+for\s+(?:the\s+)?(?:ai|assistant)"
    r")"
)


class IndirectInjectionDetector:
    name = "indirect_injection_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)
        struct = security_input.structure_flags

        for match in _INDIRECT.finditer(text):
            conf = 0.36 if meta else 0.84
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="II-001",
                    evidence_type="pattern",
                    description="Detected instructions aimed at an AI consuming external content.",
                    signals=[match.group(0)],
                )
            )

        # Hidden HTML + instruction-like content → stronger II signal
        hidden = bool(struct.get("hidden_content_detected"))
        comment = bool(struct.get("html_comment_detected"))
        instr = bool(struct.get("instruction_boundary_detected"))
        if (hidden or comment) and instr and not meta:
            findings.append(
                make_finding(
                    attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                    severity=Severity.HIGH,
                    confidence=0.82,
                    detector_name=self.name,
                    rule_id="II-002",
                    evidence_type="hidden_html",
                    description=(
                        "Hidden/comment HTML combined with instruction-boundary markers."
                    ),
                    signals=["hidden_html+instruction_boundary"],
                    location="structure_flags",
                )
            )
        elif comment and not instr and not meta:
            # Ordinary HTML comments alone — weak, not HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.INDIRECT_PROMPT_INJECTION,
                    severity=Severity.LOW,
                    confidence=0.28,
                    detector_name=self.name,
                    rule_id="II-003",
                    evidence_type="hidden_html",
                    description="HTML comments present without clear instruction payload.",
                    signals=["html_comment_only"],
                    location="structure_flags",
                )
            )

        return findings

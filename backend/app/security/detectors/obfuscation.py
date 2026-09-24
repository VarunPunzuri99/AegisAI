"""Obfuscation detector (taxonomy: encoded_instruction) using Phase 3 signals."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

_INSTR_HINT = re.compile(
    r"(?i)\b(ignore|disregard|system\s+prompt|override|jailbreak|"
    r"reveal|api\s+keys?|credentials?|tool_call)\b"
)


class ObfuscationDetector:
    name = "obfuscation_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        norm = security_input.normalization_flags
        enc = security_input.encoding_flags
        obf = security_input.obfuscation_flags

        signals: list[str] = []
        if norm.get("zero_width_detected"):
            signals.append("zero_width")
        if norm.get("bidi_control_detected"):
            signals.append("bidi_control")
        if enc.get("base64_candidate"):
            signals.append("base64_candidate")
        if enc.get("base64_decodable"):
            signals.append("base64_decodable")
        if enc.get("url_encoding_detected"):
            signals.append("url_encoding")
        if enc.get("unicode_escape_detected"):
            signals.append("unicode_escape")
        if enc.get("hex_candidate"):
            signals.append("hex_candidate")

        if not signals and not obf.get("possible_obfuscation"):
            return findings

        instruction_like = bool(_INSTR_HINT.search(text))
        derived = int(obf.get("derived_representation_count") or 0) > 0

        # Stronger when obfuscation coincides with instruction-like content
        if instruction_like or (derived and enc.get("base64_decodable")):
            conf = 0.78 if derived else 0.70
            sev = Severity.MEDIUM
            evidence = "encoded_content"
            desc = (
                "Obfuscation indicators combined with instruction-like content."
            )
            rule = "OB-002"
        else:
            conf = 0.40
            sev = Severity.LOW
            evidence = "unicode_obfuscation" if (
                "zero_width" in signals or "bidi_control" in signals
            ) else "encoded_content"
            desc = "Potentially obfuscated content detected."
            rule = "OB-001"

        if not signals:
            signals = ["possible_obfuscation"]

        findings.append(
            make_finding(
                attack_type=AttackType.ENCODED_INSTRUCTION,
                severity=sev,
                confidence=conf,
                detector_name=self.name,
                rule_id=rule,
                evidence_type=evidence,
                description=desc,
                signals=signals,
                location="normalization_flags",
            )
        )
        return findings

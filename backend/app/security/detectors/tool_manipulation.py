"""Tool manipulation detector (taxonomy: tool_abuse)."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, is_meta_discussion, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

# Override intent near tool/action verbs
_OVERRIDE_NEAR_TOOL = re.compile(
    r"(?i)\b("
    r"ignore|disregard|instead|override|forget\s+your\s+task"
    r").{0,80}\b("
    r"(?:call|execute|invoke|run|use)\s+(?:the\s+)?(?:\w+\s+)?(?:tool|function|command)|"
    r"database\s+tool|send(?:\s+an?)?\s+email|delete\s+(?:the\s+)?records|"
    r"dump\s+all\s+users|admin\s+function|tool_call"
    r")\b"
)

_DIRECT_ABUSE = re.compile(
    r"(?i)\b("
    r"(?:force|compel)\s+(?:the\s+)?(?:assistant|agent)\s+to\s+(?:call|invoke|execute)|"
    r"unauthorized\s+(?:tool|function)\s+call|"
    r"invoke\s+admin\s+function"
    r")\b"
)

# Benign-looking email alone should not match _OVERRIDE_NEAR_TOOL
_BENIGN_EMAIL = re.compile(r"(?i)^(?:please\s+)?send\s+(?:an?\s+)?email\b")


class ToolManipulationDetector:
    name = "tool_manipulation_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)

        if _BENIGN_EMAIL.search(text.strip()) and not re.search(
            r"(?i)\bignore|disregard|override|dump|delete\s+all\b", text
        ):
            # Ordinary request — no finding
            pass
        else:
            for match in _OVERRIDE_NEAR_TOOL.finditer(text):
                conf = 0.35 if meta else 0.90
                sev = Severity.LOW if meta else Severity.HIGH
                findings.append(
                    make_finding(
                        attack_type=AttackType.TOOL_ABUSE,
                        severity=sev,
                        confidence=conf,
                        detector_name=self.name,
                        rule_id="TM-001",
                        evidence_type="tool_action",
                        description=(
                            "Detected tool/action instruction combined with task override."
                        ),
                        signals=[match.group(0)],
                    )
                )

        for match in _DIRECT_ABUSE.finditer(text):
            conf = 0.32 if meta else 0.88
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.TOOL_ABUSE,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="TM-002",
                    evidence_type="tool_action",
                    description="Detected forced/unauthorized tool invocation language.",
                    signals=[match.group(0)],
                )
            )

        if security_input.structure_flags.get("tool_marker_detected") and not meta:
            if not findings:
                findings.append(
                    make_finding(
                        attack_type=AttackType.TOOL_ABUSE,
                        severity=Severity.MEDIUM,
                        confidence=0.55,
                        detector_name=self.name,
                        rule_id="TM-003",
                        evidence_type="tool_marker",
                        description="Tool-call structural markers present in content.",
                        signals=["tool_marker"],
                        location="structure_flags",
                    )
                )

        return findings

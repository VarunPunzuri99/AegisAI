"""Role manipulation / role_change deterministic detector."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import (
    analysis_text,
    is_meta_discussion,
    is_third_person_role_mention,
    make_finding,
)
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

# Imperative role assignment to the model
_ROLE_ASSIGN = re.compile(
    r"(?i)\b("
    r"you\s+are\s+now(?:\s+(?:an?|the))?|"
    r"you\s+are\s+the|"
    r"act\s+as\s+(?:the\s+)?|"
    r"assume\s+(?:the\s+role\s+of\s+)?"
    r")\s*("
    r"system(?:\s+administrator)?|developer|admin(?:istrator)?|"
    r"unrestricted(?:\s+\w+)?|root|superuser"
    r")\b"
)

_DEV_MODE = re.compile(
    r"(?i)\b("
    r"enter\s+developer\s+mode|"
    r"enable\s+developer\s+mode|"
    r"assume\s+unrestricted\s+(?:administrator\s+)?privileges"
    r")\b"
)


class RoleManipulationDetector:
    name = "role_manipulation_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)
        third = is_third_person_role_mention(text)

        for match in _ROLE_ASSIGN.finditer(text):
            # Skip narrative third-person if no imperative "you are"
            if third and not re.search(r"(?i)\byou\s+are\b|\bact\s+as\b|\bassume\b", match.group(0)):
                continue
            conf = 0.32 if meta else 0.87
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.ROLE_CHANGE,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="RM-001",
                    evidence_type="pattern",
                    description="Detected an attempt to assign a privileged role to the model.",
                    signals=[match.group(0)],
                )
            )

        for match in _DEV_MODE.finditer(text):
            conf = 0.30 if meta else 0.90
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.ROLE_CHANGE,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="RM-002",
                    evidence_type="pattern",
                    description="Detected developer/unrestricted mode escalation language.",
                    signals=[match.group(0)],
                )
            )

        return findings

"""Data exfiltration / credential exposure detector (taxonomy: credential_theft)."""

from __future__ import annotations

import re

from app.core.enums import Severity
from app.security.detectors.base import analysis_text, is_meta_discussion, make_finding
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

_EXFIL = re.compile(
    r"(?i)\b("
    r"reveal|expose|print|output|dump|return|leak|show"
    r")\b.{0,40}\b("
    r"secrets?|api\s+keys?|credentials?|environment\s+variables?|"
    r"passwords?|tokens?|private\s+records?|hidden\s+context|"
    r"internal\s+configuration|FAKE_API_KEY|FAKE_SECRET|TEST_DATABASE"
    r")\b"
)


class DataExfiltrationDetector:
    name = "data_exfiltration_rules"

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        text = analysis_text(security_input)
        findings: list[Finding] = []
        meta = is_meta_discussion(text)

        for match in _EXFIL.finditer(text):
            conf = 0.34 if meta else 0.91
            sev = Severity.LOW if meta else Severity.HIGH
            findings.append(
                make_finding(
                    attack_type=AttackType.CREDENTIAL_THEFT,
                    severity=sev,
                    confidence=conf,
                    detector_name=self.name,
                    rule_id="DE-001",
                    evidence_type="pattern",
                    description="Detected a request to expose secrets or sensitive configuration.",
                    signals=[match.group(0)],
                )
            )
        return findings

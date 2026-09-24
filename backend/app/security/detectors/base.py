"""Shared helpers for deterministic detectors (FP guards, matching utilities)."""

from __future__ import annotations

import re
from typing import Iterable

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import Finding
from app.security.types import SecurityInput

# Educational / third-person discussion — reduces false positives
_META_DISCUSSION = re.compile(
    r"(?i)\b("
    r"article|paper|research|researcher|explains?|explained|discusses?|"
    r"example of|common attack|security (?:team|guide|blog)|"
    r"how (?:attackers|adversaries)|documentation (?:says|describes)|"
    r"this (?:tutorial|lesson|course)|"
    r"reviewed the|is a feature"
    r")\b"
)

_THIRD_PERSON_SYSTEM = re.compile(
    r"(?i)\b(the|a|an)\s+(system\s+administrator|developer|admin)\b"
)


def is_meta_discussion(text: str) -> bool:
    """True when text appears to discuss attacks rather than issue them."""
    return bool(_META_DISCUSSION.search(text))


def is_third_person_role_mention(text: str) -> bool:
    """True for narrative mentions like 'the system administrator reviewed...'."""
    return bool(_THIRD_PERSON_SYSTEM.search(text))


def clip_signal(text: str, max_len: int = 80) -> str:
    """Short evidence snippet — never dump full payloads."""
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3] + "..."


def find_pattern(
    text: str,
    pattern: re.Pattern[str],
) -> list[re.Match[str]]:
    return list(pattern.finditer(text))


def make_finding(
    *,
    attack_type: AttackType,
    severity: Severity,
    confidence: float,
    detector_name: str,
    rule_id: str,
    evidence_type: str,
    description: str,
    signals: Iterable[str],
    location: str | None = "normalized_text",
) -> Finding:
    conf = max(0.0, min(1.0, confidence))
    return Finding(
        attack_type=attack_type,
        severity=severity,
        confidence=conf,
        detector_name=detector_name,
        rule_id=rule_id,
        evidence_type=evidence_type,
        description=description,
        location=location,
        signals=[clip_signal(s) for s in signals],
    )


def analysis_text(security_input: SecurityInput) -> str:
    """Primary text used for pattern matching (normalized)."""
    return security_input.normalized_text


def derived_instruction_hint(security_input: SecurityInput) -> bool:
    """True if obfuscation flags suggest derived instruction-like content exists."""
    return bool(security_input.obfuscation_flags.get("derived_representation_count", 0))

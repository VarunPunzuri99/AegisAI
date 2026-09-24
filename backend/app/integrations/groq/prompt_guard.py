"""Prompt Guard response parsing and score/label normalization."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Any


class PromptGuardLabel(StrEnum):
    ATTACK = "ATTACK"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


_ATTACK_TOKENS = frozenset(
    {
        "attack",
        "malicious",
        "jailbreak",
        "injection",
        "unsafe",
        "prompt_injection",
        "prompt-injection",
    }
)
_BENIGN_TOKENS = frozenset(
    {
        "benign",
        "safe",
        "clean",
        "allow",
        "legitimate",
        "non-malicious",
        "non_malicious",
    }
)


def parse_prompt_guard_content(raw: str) -> tuple[PromptGuardLabel, float | None]:
    """Map provider text/JSON into (label, attack_score).

    Score semantics: heuristic ``attack_score`` in [0, 1] when numeric evidence
    exists; otherwise derived from label (ATTACK→0.9, BENIGN→0.1). Not a
    calibrated probability.
    """
    if raw is None or not str(raw).strip():
        return PromptGuardLabel.UNKNOWN, None

    text = str(raw).strip()

    # Try JSON object first
    if text.startswith("{") and text.endswith("}"):
        try:
            data = json.loads(text)
            return _from_mapping(data)
        except json.JSONDecodeError:
            pass

    # Plain label token
    lowered = text.lower().strip().strip("\"'")
    if lowered in _ATTACK_TOKENS:
        return PromptGuardLabel.ATTACK, 0.9
    if lowered in _BENIGN_TOKENS:
        return PromptGuardLabel.BENIGN, 0.1

    # "label: malicious score: 0.97"
    label_match = re.search(
        r"(?i)\b(label|class|prediction)\s*[:=]\s*([A-Za-z_\-]+)",
        text,
    )
    score_match = re.search(
        r"(?i)\b(score|attack_score|probability|prob)\s*[:=]\s*([0-9]*\.?[0-9]+)",
        text,
    )
    label = PromptGuardLabel.UNKNOWN
    score: float | None = None
    if label_match:
        label = _token_to_label(label_match.group(2))
    else:
        # any attack/benign word present
        tokens = set(re.findall(r"[a-z_\-]+", lowered))
        if tokens & _ATTACK_TOKENS:
            label = PromptGuardLabel.ATTACK
        elif tokens & _BENIGN_TOKENS:
            label = PromptGuardLabel.BENIGN

    if score_match:
        try:
            score = _clamp01(float(score_match.group(2)))
        except ValueError:
            score = None

    if score is None:
        score = _default_score_for_label(label)
    elif label == PromptGuardLabel.UNKNOWN:
        # Numeric only — high score suggests attack
        if score >= 0.5:
            label = PromptGuardLabel.ATTACK
        else:
            label = PromptGuardLabel.BENIGN

    return label, score


def _from_mapping(data: dict[str, Any]) -> tuple[PromptGuardLabel, float | None]:
    label_raw = (
        data.get("label")
        or data.get("class")
        or data.get("prediction")
        or data.get("result")
    )
    score_raw = (
        data.get("attack_score")
        or data.get("score")
        or data.get("probability")
        or data.get("malicious_score")
    )
    label = (
        _token_to_label(str(label_raw))
        if label_raw is not None
        else PromptGuardLabel.UNKNOWN
    )
    score: float | None = None
    if score_raw is not None:
        try:
            score = _clamp01(float(score_raw))
        except (TypeError, ValueError):
            score = None
    if score is None:
        score = _default_score_for_label(label)
    elif label == PromptGuardLabel.UNKNOWN:
        label = PromptGuardLabel.ATTACK if score >= 0.5 else PromptGuardLabel.BENIGN
    return label, score


def _token_to_label(token: str) -> PromptGuardLabel:
    t = token.lower().strip()
    if t in _ATTACK_TOKENS:
        return PromptGuardLabel.ATTACK
    if t in _BENIGN_TOKENS:
        return PromptGuardLabel.BENIGN
    return PromptGuardLabel.UNKNOWN


def _default_score_for_label(label: PromptGuardLabel) -> float | None:
    if label == PromptGuardLabel.ATTACK:
        return 0.9
    if label == PromptGuardLabel.BENIGN:
        return 0.1
    return None


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))

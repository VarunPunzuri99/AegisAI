"""Prompt / role / tool boundary indicators (structural only, not verdicts)."""

from __future__ import annotations

import re
from typing import Any

_ROLE_MARKERS = re.compile(
    r"^(?:system|assistant|user|developer|role)\s*:\s+",
    re.IGNORECASE | re.MULTILINE,
)
_INSTRUCTION_MARKERS = re.compile(
    r"\b(?:instructions?|system\s+prompt|ignore\s+previous)\b|"
    r"^(?:instructions?|system)\s*:\s*",
    re.IGNORECASE | re.MULTILINE,
)
_TOOL_MARKERS = re.compile(
    r"\b(?:tool_call|function_call|tool\s*calls?)\b|"
    r"<\s*tool\b|</\s*tool\s*>|"
    r"```(?:json)?\s*\{\s*\"name\"\s*:",
    re.IGNORECASE,
)
_XML_INSTR = re.compile(
    r"<\s*(?:system|instructions?|prompt)\b[^>]*>",
    re.IGNORECASE,
)
_MD_INSTR = re.compile(
    r"^#{1,3}\s+(?:system|instructions?|prompt)\b",
    re.IGNORECASE | re.MULTILINE,
)


def analyze_prompt_boundaries(text: str) -> dict[str, Any]:
    """Detect structural prompt/role/tool markers without classifying attacks."""
    role = bool(_ROLE_MARKERS.search(text))
    instruction = bool(_INSTRUCTION_MARKERS.search(text))
    tool = bool(_TOOL_MARKERS.search(text))
    xml_like = bool(_XML_INSTR.search(text))
    md = bool(_MD_INSTR.search(text))

    return {
        "instruction_boundary_detected": instruction or xml_like or md,
        "role_marker_detected": role,
        "tool_marker_detected": tool,
        "xml_instruction_block_detected": xml_like,
        "markdown_instruction_section_detected": md,
    }

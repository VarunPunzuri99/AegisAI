"""Control-character detection for security preprocessing."""

from __future__ import annotations

from typing import Any

# Allowed structural controls
ALLOWED_CONTROLS = frozenset({"\n", "\r", "\t"})


def analyze_control_characters(text: str) -> dict[str, Any]:
    """Separate expected controls (newline/tab/CR) from unexpected ones."""
    unexpected = 0
    for ch in text:
        code = ord(ch)
        if ch in ALLOWED_CONTROLS:
            continue
        # C0 / C1 controls excluding allowed
        if code < 32 or (127 <= code <= 159):
            unexpected += 1

    return {
        "unexpected_control_chars": unexpected > 0,
        "control_char_count": unexpected,
    }

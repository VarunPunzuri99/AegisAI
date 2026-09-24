"""Whitespace normalization for security analysis (not aggressive cleaning)."""

from __future__ import annotations

import re

from app.security.unicode_analysis import UNUSUAL_WHITESPACE

_MULTI_NEWLINE = re.compile(r"\n{3,}")


def normalize_whitespace(text: str) -> str:
    """Collapse runs of spaces/tabs/unusual whitespace; cap blank lines.

    Preserves line boundaries (single newlines). Does not strip all whitespace.
    """
    mapped = "".join(" " if ch in UNUSUAL_WHITESPACE else ch for ch in text)
    mapped = mapped.replace("\r\n", "\n").replace("\r", "\n")
    mapped = re.sub(r"[ \t]+", " ", mapped)
    mapped = "\n".join(line.rstrip(" ") for line in mapped.split("\n"))
    mapped = _MULTI_NEWLINE.sub("\n\n", mapped)
    return mapped

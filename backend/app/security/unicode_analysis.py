"""Unicode analysis and NFKC normalization for security preprocessing."""

from __future__ import annotations

import unicodedata
from typing import Any

# Zero-width / invisible formatting (non-exhaustive but practical for Phase 3)
ZERO_WIDTH_CHARS = frozenset(
    {
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
        "\u2060",  # WORD JOINER
        "\u180e",  # MONGOLIAN VOWEL SEPARATOR (historic)
    }
)

# Bidirectional controls
BIDI_CONTROL_CHARS = frozenset(
    {
        "\u202a",  # LRE
        "\u202b",  # RLE
        "\u202c",  # PDF
        "\u202d",  # LRO
        "\u202e",  # RLO
        "\u2066",  # LRI
        "\u2067",  # RLI
        "\u2068",  # FSI
        "\u2069",  # PDI
    }
)

# Unusual Unicode whitespace (beyond space / tab / CR / LF)
UNUSUAL_WHITESPACE = frozenset(
    {
        "\u00a0",  # NO-BREAK SPACE
        "\u1680",  # OGHAM SPACE MARK
        "\u2000",  # EN QUAD
        "\u2001",  # EM QUAD
        "\u2002",  # EN SPACE
        "\u2003",  # EM SPACE
        "\u2004",  # THREE-PER-EM SPACE
        "\u2005",  # FOUR-PER-EM SPACE
        "\u2006",  # SIX-PER-EM SPACE
        "\u2007",  # FIGURE SPACE
        "\u2008",  # PUNCTUATION SPACE
        "\u2009",  # THIN SPACE
        "\u200a",  # HAIR SPACE
        "\u202f",  # NARROW NO-BREAK SPACE
        "\u205f",  # MEDIUM MATHEMATICAL SPACE
        "\u3000",  # IDEOGRAPHIC SPACE
    }
)


def normalize_unicode_nfkc(text: str) -> str:
    """Normalize with NFKC.

    NFKC (Compatibility Composition) is used so visually confusable /
    compatibility forms (fullwidth letters, ligatures, etc.) collapse toward
    canonical equivalents before detection. This improves consistency for
    rule and model detectors without claiming attacks are removed.
    """
    return unicodedata.normalize("NFKC", text)


def analyze_unicode(text: str) -> dict[str, Any]:
    """Identify suspicious Unicode categories without stripping evidence."""
    zero_width = 0
    bidi = 0
    unusual_ws = 0
    invisible_format = 0

    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            zero_width += 1
        if ch in BIDI_CONTROL_CHARS:
            bidi += 1
        if ch in UNUSUAL_WHITESPACE:
            unusual_ws += 1
        category = unicodedata.category(ch)
        # Cf = format characters (often invisible)
        if category == "Cf" and ch not in {"\n", "\r", "\t"}:
            invisible_format += 1

    return {
        "unicode_form": "NFKC",
        "zero_width_detected": zero_width > 0,
        "zero_width_count": zero_width,
        "bidi_control_detected": bidi > 0,
        "bidi_control_count": bidi,
        "unusual_whitespace_detected": unusual_ws > 0,
        "unusual_whitespace_count": unusual_ws,
        "invisible_format_detected": invisible_format > 0,
        "invisible_format_count": invisible_format,
    }

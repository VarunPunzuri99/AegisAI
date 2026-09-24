"""Static HTML structure indicators (no execution, no fetching)."""

from __future__ import annotations

import re
from typing import Any

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL | re.IGNORECASE)
_SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
_IFRAME_RE = re.compile(r"<iframe\b", re.IGNORECASE)
_DISPLAY_NONE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|aria-hidden\s*=\s*[\"']?true",
    re.IGNORECASE,
)
_HIDDEN_ATTR_RE = re.compile(r"\bhidden\b", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"</?[a-zA-Z][^>]*>")


def analyze_html(text: str) -> dict[str, Any]:
    """Lightweight HTML/structure flags. Does not execute or fetch."""
    html_detected = bool(_HTML_TAG_RE.search(text)) or bool(_COMMENT_RE.search(text))
    comments = len(_COMMENT_RE.findall(text))
    scripts = len(_SCRIPT_RE.findall(text))
    iframes = len(_IFRAME_RE.findall(text))
    hidden = bool(_DISPLAY_NONE_RE.search(text)) or (
        html_detected and bool(_HIDDEN_ATTR_RE.search(text))
    )

    return {
        "html_detected": html_detected,
        "html_comment_detected": comments > 0,
        "html_comment_count": comments,
        "hidden_content_detected": hidden,
        "script_detected": scripts > 0,
        "script_tag_count": scripts,
        "iframe_detected": iframes > 0,
        "iframe_tag_count": iframes,
    }

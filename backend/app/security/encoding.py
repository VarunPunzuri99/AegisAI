"""Bounded encoding / obfuscation analysis (no recursive explosion)."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any
from urllib.parse import unquote_plus

# Conservative Base64 candidate: long alphabet run, length multiple of 4-ish
_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/_\-])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])"
)
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{24,})(?![0-9A-Fa-f])")
_URL_ENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2})")


def _safe_b64_decode(candidate: str, max_decoded: int) -> tuple[bool, str | None]:
    try:
        # Fix missing padding
        pad = (-len(candidate)) % 4
        raw = base64.b64decode(candidate + ("=" * pad), validate=False)
    except (binascii.Error, ValueError):
        return False, None
    if len(raw) > max_decoded:
        return True, None  # decodable but oversized — do not expand
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True, None
    # Prefer printable / mostly-text payloads
    if not text or sum(1 for c in text if c.isprintable() or c in "\n\r\t") < len(text) * 0.8:
        return True, None
    return True, text


def analyze_encodings(
    text: str,
    *,
    max_decoded_length: int,
    max_decode_depth: int,
    max_encoded_candidates: int,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Detect encoding-like patterns with bounded optional decoding.

    Returns ``(flags, derived_texts, errors)`` where ``derived_texts`` are safe
    decoded snippets for downstream detectors (size-limited, depth-limited).
    """
    flags: dict[str, Any] = {
        "base64_candidate": False,
        "base64_decodable": False,
        "base64_candidate_count": 0,
        "hex_candidate": False,
        "hex_candidate_count": 0,
        "url_encoding_detected": False,
        "url_encoding_count": 0,
        "unicode_escape_detected": False,
        "unicode_escape_count": 0,
        "decode_truncated": False,
        "decode_depth_used": 0,
    }
    derived: list[str] = []
    errors: list[str] = []

    b64_matches = list(_BASE64_RE.finditer(text))[:max_encoded_candidates]
    if len(_BASE64_RE.findall(text)) > max_encoded_candidates:
        flags["decode_truncated"] = True
        errors.append("base64_candidate_limit_reached")

    flags["base64_candidate_count"] = len(b64_matches)
    flags["base64_candidate"] = len(b64_matches) > 0

    depth = 0
    for match in b64_matches:
        if depth >= max_decode_depth:
            flags["decode_truncated"] = True
            break
        ok, decoded = _safe_b64_decode(match.group(1), max_decoded_length)
        if ok:
            flags["base64_decodable"] = True
        if decoded is not None:
            derived.append(decoded[:max_decoded_length])
            depth += 1
    flags["decode_depth_used"] = depth

    hex_matches = list(_HEX_RUN_RE.finditer(text))[:max_encoded_candidates]
    flags["hex_candidate_count"] = len(hex_matches)
    flags["hex_candidate"] = len(hex_matches) > 0

    url_matches = list(_URL_ENC_RE.finditer(text))
    flags["url_encoding_count"] = len(url_matches)
    flags["url_encoding_detected"] = len(url_matches) > 0
    if url_matches and len(derived) < max_encoded_candidates:
        try:
            decoded_url = unquote_plus(text)
            if decoded_url != text and len(decoded_url) <= max_decoded_length:
                derived.append(decoded_url)
        except Exception:
            errors.append("url_decode_failed")

    esc_matches = list(_UNICODE_ESCAPE_RE.finditer(text))
    flags["unicode_escape_count"] = len(esc_matches)
    flags["unicode_escape_detected"] = len(esc_matches) > 0
    if esc_matches and len(derived) < max_encoded_candidates:
        try:
            # Bounded: only unescape \\x and \\u sequences we detect
            sample = text
            if len(sample) > max_decoded_length:
                sample = sample[:max_decoded_length]
                flags["decode_truncated"] = True

            def _repl_u(m: re.Match[str]) -> str:
                return chr(int(m.group(0)[2:], 16))

            unescaped = _UNICODE_ESCAPE_RE.sub(_repl_u, sample)
            if unescaped != sample:
                derived.append(unescaped[:max_decoded_length])
        except Exception:
            errors.append("unicode_escape_decode_failed")

    return flags, derived, errors

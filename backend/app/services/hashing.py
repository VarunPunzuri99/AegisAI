"""Content hashing helpers. Never log raw content."""

import hashlib


def sha256_hex(content: str) -> str:
    """Return the SHA-256 hex digest of UTF-8 encoded content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

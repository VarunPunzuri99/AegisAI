"""Tool definition fingerprinting — detect rug-pull / definition tampering."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def fingerprint_tool_definition(
    *,
    server_id: str,
    tool_name: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any],
    capability: str,
    risk: str,
) -> str:
    """Deterministic SHA-256 over canonical tool definition fields."""
    payload = {
        "server_id": server_id,
        "tool_name": tool_name,
        "description": description,
        "input_schema": input_schema,
        "output_schema": output_schema,
        "capability": capability,
        "risk": risk,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

"""MCP output/input schema validation — constrained formats only."""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.mcp.types import MCPErrorCode


def validate_input(
    parameters: dict[str, Any],
    input_schema: dict[str, Any],
) -> tuple[bool, list[str]]:
    required = input_schema.get("required") or []
    props = input_schema.get("properties") or {}
    reasons: list[str] = []
    if not isinstance(parameters, dict):
        return False, [MCPErrorCode.MCP_INPUT_INVALID.value]
    for key in required:
        if key not in parameters:
            reasons.append(MCPErrorCode.MCP_INPUT_INVALID.value)
            return False, reasons
    for key, value in parameters.items():
        if key not in props:
            reasons.append(MCPErrorCode.MCP_INPUT_INVALID.value)
            return False, reasons
        expected = props[key].get("type")
        if expected == "string" and not isinstance(value, str):
            reasons.append(MCPErrorCode.MCP_INPUT_INVALID.value)
            return False, reasons
        if expected == "integer" and not isinstance(value, int):
            reasons.append(MCPErrorCode.MCP_INPUT_INVALID.value)
            return False, reasons
        if expected == "number" and not isinstance(value, (int, float)):
            reasons.append(MCPErrorCode.MCP_INPUT_INVALID.value)
            return False, reasons
        if expected == "boolean" and not isinstance(value, bool):
            reasons.append(MCPErrorCode.MCP_INPUT_INVALID.value)
            return False, reasons
    return True, []


def validate_output(
    output: Any,
    output_schema: dict[str, Any],
) -> tuple[bool, list[str]]:
    settings = get_settings()
    reasons: list[str] = []
    if not isinstance(output, dict):
        return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]

    # Size bound (rough JSON length)
    encoded = str(output)
    if len(encoded.encode("utf-8")) > settings.mcp_max_response_bytes:
        return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]

    required = output_schema.get("required") or []
    props = output_schema.get("properties") or {}
    for key in required:
        if key not in output:
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]

    # Reject unexpected top-level fields
    for key in output:
        if key not in props:
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]

    # Item count limit for list fields
    for key, value in output.items():
        if isinstance(value, list) and len(value) > settings.mcp_max_output_items:
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]
        expected = (props.get(key) or {}).get("type")
        if expected == "array" and not isinstance(value, list):
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]
        if expected == "integer" and not isinstance(value, int):
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]
        if expected == "string" and not isinstance(value, str):
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]
        if expected == "object" and not isinstance(value, dict):
            return False, [MCPErrorCode.MCP_OUTPUT_INVALID.value]

    _ = reasons
    return True, []

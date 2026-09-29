"""In-process MCP gateway metrics — Phase 15-style counters."""

from __future__ import annotations

from threading import Lock


class MCPMetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self.mcp_requests = 0
        self.mcp_allowed = 0
        self.mcp_denied = 0
        self.mcp_definition_mismatch = 0
        self.mcp_shadowing_denied = 0
        self.mcp_output_invalid = 0
        self.mcp_timeout = 0
        self.mcp_server_unavailable = 0

    def record(self, *, allowed: bool, reason_codes: list[str]) -> None:
        with self._lock:
            self.mcp_requests += 1
            if allowed:
                self.mcp_allowed += 1
            else:
                self.mcp_denied += 1
            codes = set(reason_codes)
            if "MCP_TOOL_DEFINITION_CHANGED" in codes:
                self.mcp_definition_mismatch += 1
            if "MCP_TOOL_SHADOWING" in codes:
                self.mcp_shadowing_denied += 1
            if "MCP_OUTPUT_INVALID" in codes:
                self.mcp_output_invalid += 1
            if "MCP_TIMEOUT" in codes:
                self.mcp_timeout += 1
            if "MCP_SERVER_UNAVAILABLE" in codes:
                self.mcp_server_unavailable += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "mcp_requests": self.mcp_requests,
                "mcp_allowed": self.mcp_allowed,
                "mcp_denied": self.mcp_denied,
                "mcp_definition_mismatch": self.mcp_definition_mismatch,
                "mcp_shadowing_denied": self.mcp_shadowing_denied,
                "mcp_output_invalid": self.mcp_output_invalid,
                "mcp_timeout": self.mcp_timeout,
                "mcp_server_unavailable": self.mcp_server_unavailable,
            }


_REGISTRY = MCPMetricsRegistry()


def get_mcp_metrics() -> MCPMetricsRegistry:
    return _REGISTRY

"""In-process authorization metrics (Phase 15 style — no secrets)."""

from __future__ import annotations

import threading
from typing import Any

from app.auth.types import AuthorizationVerdict


class AuthzMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.allow = 0
        self.deny = 0
        self.requires_approval = 0
        self.cross_tenant_denied = 0
        self.unknown_principal_denied = 0
        self.unknown_tool_denied = 0
        self.latencies_ms: list[float] = []

    def record(self, verdict: AuthorizationVerdict, *, reason_codes: list[str], ms: float = 0.0) -> None:
        with self._lock:
            if verdict == AuthorizationVerdict.ALLOW:
                self.allow += 1
            elif verdict == AuthorizationVerdict.REQUIRES_APPROVAL:
                self.requires_approval += 1
            else:
                self.deny += 1
            if "TENANT_MISMATCH" in reason_codes:
                self.cross_tenant_denied += 1
            if "PRINCIPAL_UNKNOWN" in reason_codes or "PRINCIPAL_MISSING" in reason_codes:
                self.unknown_principal_denied += 1
            if "TOOL_UNKNOWN" in reason_codes:
                self.unknown_tool_denied += 1
            if ms > 0:
                self.latencies_ms.append(ms)
                if len(self.latencies_ms) > 2000:
                    self.latencies_ms = self.latencies_ms[-1000:]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            vals = sorted(self.latencies_ms)
            median = vals[len(vals) // 2] if vals else 0.0
            return {
                "authorization_allow": self.allow,
                "authorization_deny": self.deny,
                "authorization_requires_approval": self.requires_approval,
                "cross_tenant_denied": self.cross_tenant_denied,
                "unknown_principal_denied": self.unknown_principal_denied,
                "unknown_tool_denied": self.unknown_tool_denied,
                "authorization_median_ms": median,
                "note": "In-process Phase 16 authz metrics — not production traffic.",
            }


_METRICS = AuthzMetrics()


def get_authz_metrics() -> AuthzMetrics:
    return _METRICS


def reset_authz_metrics_for_tests() -> None:
    global _METRICS
    _METRICS = AuthzMetrics()

"""In-process provider metrics registry (process lifetime; not durable).

Records sanitized observations only — never prompts, keys, or raw responses.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Optional

from app.observability.metrics import summarize_latencies
from app.observability.types import (
    ObservedHealthStatus,
    ProviderFailureType,
    ProviderName,
    ProviderObservation,
    map_error_code,
)


class _ProviderBucket:
    def __init__(self, name: ProviderName) -> None:
        self.name = name
        self.success_count = 0
        self.failure_count = 0
        self.rate_limit_count = 0
        self.latencies: list[float] = []
        self.last_success_at: datetime | None = None
        self.last_failure_at: datetime | None = None
        self.last_failure_type: ProviderFailureType | None = None
        self.model: str | None = None

    def record(self, obs: ProviderObservation) -> None:
        if obs.model:
            self.model = obs.model
        self.latencies.append(obs.latency_ms)
        # Cap in-memory samples to avoid unbounded growth
        if len(self.latencies) > 2000:
            self.latencies = self.latencies[-1000:]
        if obs.success:
            self.success_count += 1
            self.last_success_at = obs.observed_at
        else:
            self.failure_count += 1
            self.last_failure_at = obs.observed_at
            self.last_failure_type = obs.failure_type
            if obs.rate_limited or obs.failure_type == ProviderFailureType.RATE_LIMITED:
                self.rate_limit_count += 1

    def observed_status(self, *, configured: bool) -> ObservedHealthStatus:
        if not configured:
            return ObservedHealthStatus.NOT_CONFIGURED
        total = self.success_count + self.failure_count
        if total == 0:
            return ObservedHealthStatus.NOT_OBSERVED
        if self.failure_count == 0 and self.success_count > 0:
            return ObservedHealthStatus.OBSERVED_HEALTHY
        if self.success_count == 0 and self.failure_count > 0:
            return ObservedHealthStatus.UNAVAILABLE
        # Mixed outcomes
        fail_rate = self.failure_count / total
        if fail_rate >= 0.5:
            return ObservedHealthStatus.DEGRADED
        if self.rate_limit_count > 0:
            return ObservedHealthStatus.DEGRADED
        return ObservedHealthStatus.OBSERVED_HEALTHY

    def snapshot(self, *, configured: bool) -> dict[str, Any]:
        lat = summarize_latencies(self.latencies)
        return {
            "provider": self.name.value,
            "model": self.model,
            "configured": configured,
            "observed_status": self.observed_status(configured=configured).value,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "rate_limit_count": self.rate_limit_count,
            "last_success_at": (
                self.last_success_at.replace(tzinfo=timezone.utc).isoformat()
                if self.last_success_at
                else None
            ),
            "last_failure_at": (
                self.last_failure_at.replace(tzinfo=timezone.utc).isoformat()
                if self.last_failure_at
                else None
            ),
            "last_failure_type": (
                self.last_failure_type.value if self.last_failure_type else None
            ),
            "median_latency_ms": lat["median_ms"],
            "p95_latency_ms": lat["p95_ms"],
            "p99_latency_ms": lat["p99_ms"],
            "average_latency_ms": lat["mean_ms"],
            "sample_count": int(lat["count"]),
            "note": (
                "Observed from in-process calls only. "
                "CONFIGURED alone does not imply healthy."
            ),
        }


class ProviderMetricsRegistry:
    """Thread-safe process-local provider metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[ProviderName, _ProviderBucket] = {
            p: _ProviderBucket(p) for p in ProviderName
        }

    def record(self, observation: ProviderObservation) -> None:
        with self._lock:
            self._buckets[observation.provider].record(observation)

    def record_call(
        self,
        *,
        provider: ProviderName,
        model: str | None,
        operation: str,
        success: bool,
        latency_ms: float,
        error_code: str | None = None,
        retry_count: int = 0,
        response_empty: bool = False,
        response_malformed: bool = False,
        recovered: bool = False,
    ) -> None:
        failure = map_error_code(error_code) if not success else None
        obs = ProviderObservation(
            provider=provider,
            model=model,
            operation=operation,
            success=success,
            failure_type=failure,
            latency_ms=latency_ms,
            timeout=failure == ProviderFailureType.TIMEOUT,
            retry_count=retry_count,
            response_empty=response_empty,
            response_malformed=response_malformed,
            rate_limited=failure == ProviderFailureType.RATE_LIMITED,
            recovered=recovered,
            observed_at=datetime.now(timezone.utc),
        )
        self.record(obs)

    def snapshot(self, *, groq_configured: bool) -> dict[str, Any]:
        with self._lock:
            cfg = {
                ProviderName.GROQ: groq_configured,
                ProviderName.PROMPT_GUARD: groq_configured,
                ProviderName.SAFEGUARD: groq_configured,
            }
            providers = {
                p.value: self._buckets[p].snapshot(configured=cfg[p]) for p in ProviderName
            }
            return {
                "providers": providers,
                "note": (
                    "In-process observations since process start. "
                    "Do not claim 'Groq healthy' from API key presence alone."
                ),
            }


_REGISTRY = ProviderMetricsRegistry()


def get_provider_registry() -> ProviderMetricsRegistry:
    return _REGISTRY


def reset_provider_registry_for_tests() -> None:
    """Test helper — clear observations."""
    global _REGISTRY
    _REGISTRY = ProviderMetricsRegistry()

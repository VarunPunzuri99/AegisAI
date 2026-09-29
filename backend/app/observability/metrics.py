"""Latency summary helpers (median / p95 / p99)."""

from __future__ import annotations

from typing import Sequence


def percentile(sorted_vals: Sequence[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    idx = min(len(sorted_vals) - 1, max(0, int(len(sorted_vals) * p)))
    return float(sorted_vals[idx])


def summarize_latencies(values: Sequence[float]) -> dict[str, float]:
    if not values:
        return {"median_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "mean_ms": 0.0, "count": 0.0}
    s = sorted(float(v) for v in values)
    return {
        "median_ms": percentile(s, 0.50),
        "p95_ms": percentile(s, 0.95),
        "p99_ms": percentile(s, 0.99),
        "mean_ms": round(sum(s) / len(s), 3),
        "count": float(len(s)),
    }

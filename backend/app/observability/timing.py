"""Monotonic pipeline stage timing — low overhead."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator, Optional

from pydantic import BaseModel, ConfigDict, Field


class PipelineTiming(BaseModel):
    """Sanitized stage timings in milliseconds."""

    model_config = ConfigDict(frozen=True)

    normalization_ms: float = 0.0
    deterministic_ms: float = 0.0
    prompt_guard_ms: float = 0.0
    semantic_ms: float = 0.0
    fusion_ms: float = 0.0
    risk_ms: float = 0.0
    policy_ms: float = 0.0
    agent_workflow_ms: float = 0.0
    tool_firewall_ms: float = 0.0
    persistence_ms: float = 0.0
    total_ms: float = 0.0


class PipelineTimer:
    """Accumulate stage timings with time.perf_counter()."""

    def __init__(self) -> None:
        self._t0 = time.perf_counter()
        self._stages: dict[str, float] = {}

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self._stages[name] = round((time.perf_counter() - start) * 1000.0, 3)

    def record(self, name: str, ms: float) -> None:
        self._stages[name] = round(ms, 3)

    def finish(self) -> PipelineTiming:
        total = round((time.perf_counter() - self._t0) * 1000.0, 3)
        return PipelineTiming(
            normalization_ms=self._stages.get("normalization", 0.0),
            deterministic_ms=self._stages.get("deterministic", 0.0),
            prompt_guard_ms=self._stages.get("prompt_guard", 0.0),
            semantic_ms=self._stages.get("semantic", 0.0),
            fusion_ms=self._stages.get("fusion", 0.0),
            risk_ms=self._stages.get("risk", 0.0),
            policy_ms=self._stages.get("policy", 0.0),
            agent_workflow_ms=self._stages.get("agent_workflow", 0.0),
            tool_firewall_ms=self._stages.get("tool_firewall", 0.0),
            persistence_ms=self._stages.get("persistence", 0.0),
            total_ms=total,
        )


def timing_to_dict(timing: Optional[PipelineTiming]) -> dict[str, float]:
    if timing is None:
        return {}
    return timing.model_dump()

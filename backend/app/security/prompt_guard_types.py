"""Prompt Guard domain results (in-memory)."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.integrations.groq.prompt_guard import PromptGuardLabel


class PromptGuardChunkResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    chunk_index: int
    label: PromptGuardLabel
    attack_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    latency_ms: float = 0.0
    error_code: Optional[str] = None


class PromptGuardResult(BaseModel):
    """Normalized Prompt Guard assessment — not a final ALLOW/BLOCK."""

    model_config = ConfigDict(frozen=True)

    available: bool
    model: str
    is_attack: Optional[bool] = None
    score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    label: PromptGuardLabel = PromptGuardLabel.UNKNOWN
    chunk_results: list[PromptGuardChunkResult] = Field(default_factory=list)
    latency_ms: float = 0.0
    error_code: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

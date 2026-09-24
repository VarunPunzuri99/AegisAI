"""Security preprocessing domain types (in-memory only; not persisted)."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import SourceType


class TextChunk(BaseModel):
    """One analysis segment for downstream detectors (e.g. Prompt Guard)."""

    model_config = ConfigDict(frozen=True)

    index: int
    text: str
    start_offset: int
    end_offset: int


class SecurityInput(BaseModel):
    """Security-normalized representation of untrusted input.

    Distinct from the original raw string. Original content is not stored here
    for persistence — only ``normalized_text`` for in-memory detection use.
    Normalization does **not** decide maliciousness.
    """

    model_config = ConfigDict(frozen=True)

    original_length: int
    normalized_length: int
    normalized_text: str
    normalization_flags: dict[str, Any] = Field(default_factory=dict)
    encoding_flags: dict[str, Any] = Field(default_factory=dict)
    structure_flags: dict[str, Any] = Field(default_factory=dict)
    obfuscation_flags: dict[str, Any] = Field(default_factory=dict)
    chunks: list[TextChunk] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    preprocessing_errors: list[str] = Field(default_factory=list)
    source_type: Optional[SourceType] = None

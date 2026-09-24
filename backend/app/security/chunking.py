"""Tokenizer and text chunking abstractions for future Prompt Guard segmentation.

Character counts are a conservative fallback and are NOT model token counts.
"""

from __future__ import annotations

from typing import Protocol

from app.security.types import TextChunk


class Tokenizer(Protocol):
    """Replaceable tokenizer interface (model-specific tokenizers later)."""

    def count_units(self, text: str) -> int:
        """Return tokenizer units for ``text`` (tokens or char fallback)."""
        ...


class CharacterFallbackTokenizer:
    """Conservative fallback: one unit per Unicode character.

    Documented limitation: this is **not** equal to Prompt Guard / LLM tokens.
    It exists so chunking works offline until a real tokenizer is wired.
    """

    def count_units(self, text: str) -> int:
        return len(text)


class TextChunker:
    """Split text into overlapping windows sized by tokenizer units."""

    def __init__(
        self,
        *,
        tokenizer: Tokenizer | None = None,
        max_units: int = 1500,
        overlap_units: int = 100,
        max_chunks: int = 64,
    ) -> None:
        if max_units < 1:
            raise ValueError("max_units must be >= 1")
        if overlap_units < 0:
            raise ValueError("overlap_units must be >= 0")
        if overlap_units >= max_units:
            raise ValueError("overlap_units must be < max_units")
        self.tokenizer = tokenizer or CharacterFallbackTokenizer()
        self.max_units = max_units
        self.overlap_units = overlap_units
        self.max_chunks = max_chunks

    def chunk_text(self, text: str) -> list[TextChunk]:
        """Chunk ``text`` into segments with character offsets into ``text``."""
        if not text:
            return []

        # Character-fallback path: units == characters, offsets are exact.
        # When a real tokenizer is added, unit-based slicing should map via
        # token spans; until then we intentionally use character windows.
        total = len(text)
        if self.tokenizer.count_units(text) <= self.max_units:
            return [
                TextChunk(index=0, text=text, start_offset=0, end_offset=total),
            ]

        chunks: list[TextChunk] = []
        step = max(1, self.max_units - self.overlap_units)
        start = 0
        index = 0
        truncated = False

        while start < total and index < self.max_chunks:
            end = min(start + self.max_units, total)
            chunks.append(
                TextChunk(
                    index=index,
                    text=text[start:end],
                    start_offset=start,
                    end_offset=end,
                )
            )
            index += 1
            if end >= total:
                break
            start += step
            if index >= self.max_chunks and end < total:
                truncated = True
                break

        if truncated and chunks:
            # Record truncation via a sentinel empty note is avoided; caller
            # inspects len(chunks) vs content. Metadata is attached upstream.
            pass

        return chunks

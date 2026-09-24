"""Prompt Guard detector — SecurityInput → PromptGuardResult via Groq."""

from __future__ import annotations

import logging
import time

from app.core.config import Settings, get_settings
from app.core.enums import Severity
from app.integrations.groq.client import GroqClient
from app.integrations.groq.errors import GroqAuthError, GroqIntegrationError
from app.integrations.groq.prompt_guard import PromptGuardLabel
from app.security.chunking import TextChunker
from app.security.detectors.types import DetectionReport
from app.security.prompt_guard_types import PromptGuardChunkResult, PromptGuardResult
from app.security.types import SecurityInput

logger = logging.getLogger(__name__)


class PromptGuardDetector:
    """Classify normalized SecurityInput chunks with Llama Prompt Guard 2."""

    name = "prompt_guard"

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        client: GroqClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client or GroqClient(
            api_key=self.settings.groq_api_key,
            timeout_seconds=self.settings.prompt_guard_timeout_seconds,
            max_retries=self.settings.prompt_guard_max_retries,
        )
        self.chunker = TextChunker(
            max_units=self.settings.prompt_guard_max_chunk_length,
            overlap_units=self.settings.prompt_guard_chunk_overlap,
            max_chunks=self.settings.max_chunks,
        )
        self.model = self.settings.prompt_guard_model

    def detect(self, security_input: SecurityInput) -> PromptGuardResult:
        started = time.perf_counter()

        if not self.settings.prompt_guard_enabled:
            return self._unavailable(
                "DISABLED",
                started,
                note="PROMPT_GUARD_ENABLED is false",
            )

        if not self.settings.groq_api_key and self.client._transport is None:
            return self._unavailable("MISSING_API_KEY", started)

        text = security_input.normalized_text
        chunks = self.chunker.chunk_text(text)
        if not chunks:
            return PromptGuardResult(
                available=True,
                model=self.model,
                is_attack=False,
                score=0.1,
                label=PromptGuardLabel.BENIGN,
                chunk_results=[],
                latency_ms=_ms(started),
                metadata={"aggregation": "max_score", "chunk_count": 0},
            )

        chunk_results: list[PromptGuardChunkResult] = []
        for chunk in chunks:
            chunk_started = time.perf_counter()
            try:
                raw = self.client.classify_text(model=self.model, content=chunk.text)
                from app.integrations.groq.prompt_guard import parse_prompt_guard_content

                label, score = parse_prompt_guard_content(raw)
                chunk_results.append(
                    PromptGuardChunkResult(
                        chunk_index=chunk.index,
                        label=label,
                        attack_score=score,
                        latency_ms=_ms(chunk_started),
                    )
                )
            except GroqAuthError as exc:
                logger.warning("prompt_guard auth_error code=%s", exc.code)
                return self._unavailable(exc.code, started, partial=chunk_results)
            except GroqIntegrationError as exc:
                logger.warning(
                    "prompt_guard chunk_error code=%s chunk=%s",
                    exc.code,
                    chunk.index,
                )
                chunk_results.append(
                    PromptGuardChunkResult(
                        chunk_index=chunk.index,
                        label=PromptGuardLabel.UNKNOWN,
                        attack_score=None,
                        latency_ms=_ms(chunk_started),
                        error_code=exc.code,
                    )
                )

        return self._aggregate(chunk_results, started)

    def should_invoke(self, deterministic: DetectionReport) -> bool:
        """Decide whether Prompt Guard runs under current PROMPT_GUARD_MODE."""
        mode = (self.settings.prompt_guard_mode or "ALWAYS").strip().upper()
        if not self.settings.prompt_guard_enabled:
            return False
        if mode == "ALWAYS":
            return True
        if mode == "SUSPICIOUS_ONLY":
            return _is_suspicious(deterministic)
        # Unknown mode → safe default ALWAYS for hackathon demos
        return True

    def _aggregate(
        self,
        chunk_results: list[PromptGuardChunkResult],
        started: float,
    ) -> PromptGuardResult:
        scores = [c.attack_score for c in chunk_results if c.attack_score is not None]
        labels = [c.label for c in chunk_results]
        errors = [c.error_code for c in chunk_results if c.error_code]

        if not chunk_results:
            return self._unavailable("EMPTY_RESPONSE", started)

        # If every chunk failed → unavailable
        if errors and len(errors) == len(chunk_results):
            return self._unavailable(errors[0] or "PROVIDER_ERROR", started, partial=chunk_results)

        max_score = max(scores) if scores else None
        if PromptGuardLabel.ATTACK in labels:
            label = PromptGuardLabel.ATTACK
            is_attack = True
        elif all(l == PromptGuardLabel.BENIGN for l in labels if l != PromptGuardLabel.UNKNOWN) and (
            PromptGuardLabel.BENIGN in labels
        ):
            # All non-unknown are benign; unknown chunks don't flip to attack
            if PromptGuardLabel.UNKNOWN in labels and not scores:
                label = PromptGuardLabel.UNKNOWN
                is_attack = None
            else:
                label = PromptGuardLabel.BENIGN
                is_attack = False
        elif PromptGuardLabel.UNKNOWN in labels and PromptGuardLabel.ATTACK not in labels:
            if max_score is not None and max_score >= 0.5:
                label = PromptGuardLabel.ATTACK
                is_attack = True
            elif max_score is not None:
                label = PromptGuardLabel.BENIGN
                is_attack = False
            else:
                label = PromptGuardLabel.UNKNOWN
                is_attack = None
        else:
            label = PromptGuardLabel.UNKNOWN
            is_attack = None

        if max_score is None and label == PromptGuardLabel.ATTACK:
            max_score = 0.9
        if max_score is None and label == PromptGuardLabel.BENIGN:
            max_score = 0.1

        return PromptGuardResult(
            available=True,
            model=self.model,
            is_attack=is_attack,
            score=max_score,
            label=label,
            chunk_results=chunk_results,
            latency_ms=_ms(started),
            error_code=None,
            metadata={
                "aggregation": "max_attack_score_across_chunks",
                "aggregation_note": (
                    "Heuristic max score across chunks; not mathematically optimal."
                ),
                "chunk_count": len(chunk_results),
                "tokenizer": "character_fallback",
            },
        )

    def _unavailable(
        self,
        code: str,
        started: float,
        *,
        note: str | None = None,
        partial: list[PromptGuardChunkResult] | None = None,
    ) -> PromptGuardResult:
        meta: dict = {"chunk_count": len(partial or [])}
        if note:
            meta["note"] = note
        return PromptGuardResult(
            available=False,
            model=self.model,
            is_attack=None,
            score=None,
            label=PromptGuardLabel.UNKNOWN,
            chunk_results=list(partial or []),
            latency_ms=_ms(started),
            error_code=code,
            metadata=meta,
        )


def _is_suspicious(report: DetectionReport) -> bool:
    """SUSPICIOUS_ONLY policy criteria (documented; not a final decision)."""
    if not report.findings:
        return False
    high = {Severity.HIGH, Severity.CRITICAL}
    if any(f.severity in high for f in report.findings):
        return True
    if len(report.findings) >= 2:
        return True
    from app.security.detectors.taxonomy import AttackType

    suspicious_types = {
        AttackType.ENCODED_INSTRUCTION,
        AttackType.INDIRECT_PROMPT_INJECTION,
        AttackType.CONTEXT_POISONING,
    }
    if any(f.attack_type in suspicious_types for f in report.findings):
        return True
    # Ambiguous: only LOW findings but non-empty
    if report.is_attack:
        return True
    return False


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)

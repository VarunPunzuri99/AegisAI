"""Low-level Groq client with bounded retries (no prompt logging)."""

from __future__ import annotations

import logging
import time
from typing import Any, Protocol

from app.integrations.groq.errors import (
    GroqAuthError,
    GroqBadRequestError,
    GroqIntegrationError,
    GroqRateLimitError,
    GroqTimeoutError,
    GroqTransientError,
)

logger = logging.getLogger(__name__)


class ChatCompletionTransport(Protocol):
    """Narrow interface for mocking without the real SDK."""

    def create(self, **kwargs: Any) -> Any: ...


class GroqClient:
    """Thin wrapper around the Groq SDK chat completions API."""

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        transport: ChatCompletionTransport | None = None,
    ) -> None:
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, max_retries)
        self._transport = transport

    def _get_transport(self) -> ChatCompletionTransport:
        if self._transport is not None:
            return self._transport
        if not self.api_key:
            raise GroqAuthError("MISSING_API_KEY", "GROQ_API_KEY is not configured")
        try:
            from groq import Groq
        except ImportError as exc:  # pragma: no cover
            raise GroqIntegrationError(
                "SDK_UNAVAILABLE",
                "groq package is not installed",
            ) from exc
        client = Groq(api_key=self.api_key, timeout=self.timeout_seconds)
        return client.chat.completions

    def classify_text(self, *, model: str, content: str) -> str:
        """Send content as a single user message; return assistant text only."""
        return self.chat(
            model=model,
            messages=[{"role": "user", "content": content}],
            max_tokens=32,
        )

    def chat(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> str:
        """Chat completion with bounded retries. Never logs message contents."""
        last_error: GroqIntegrationError | None = None
        attempts = self.max_retries + 1
        total_chars = sum(len(m.get("content", "")) for m in messages)

        for attempt in range(attempts):
            try:
                transport = self._get_transport()
                completion = transport.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                choice = completion.choices[0]
                text = (choice.message.content or "").strip()
                logger.info(
                    "groq_chat_ok model=%s attempt=%s msg_chars=%s resp_len=%s retries=%s",
                    model,
                    attempt + 1,
                    total_chars,
                    len(text),
                    attempt,
                )
                return text
            except GroqIntegrationError as exc:
                last_error = exc
                if isinstance(exc, (GroqAuthError, GroqBadRequestError)):
                    raise
                if isinstance(exc, GroqRateLimitError):
                    if attempt + 1 >= attempts:
                        raise
                    # Bounded exponential backoff; honor Retry-After when present.
                    delay = exc.retry_after_seconds or (0.5 * (2**attempt))
                    time.sleep(min(delay, 5.0))
                    continue
                if isinstance(exc, GroqTimeoutError):
                    # Timeout: no aggressive retry loop — at most one retry if budget remains.
                    if attempt + 1 >= attempts or attempt >= 1:
                        raise
                    time.sleep(0.25)
                    continue
                if isinstance(exc, GroqTransientError):
                    if attempt + 1 >= attempts:
                        raise
                    time.sleep(min(0.25 * (2**attempt), 5.0))
                    continue
                raise
            except Exception as exc:
                mapped = self._map_sdk_exception(exc)
                last_error = mapped
                if isinstance(mapped, (GroqAuthError, GroqBadRequestError)):
                    raise mapped
                if isinstance(mapped, GroqRateLimitError):
                    if attempt + 1 >= attempts:
                        raise mapped
                    delay = mapped.retry_after_seconds or (0.5 * (2**attempt))
                    time.sleep(min(delay, 5.0))
                    continue
                if isinstance(mapped, GroqTimeoutError):
                    if attempt + 1 >= attempts or attempt >= 1:
                        raise mapped
                    time.sleep(0.25)
                    continue
                if isinstance(mapped, GroqTransientError):
                    if attempt + 1 >= attempts:
                        raise mapped
                    time.sleep(min(0.25 * (2**attempt), 5.0))
                    continue
                raise mapped

        assert last_error is not None
        raise last_error

    def _map_sdk_exception(self, exc: Exception) -> GroqIntegrationError:
        name = type(exc).__name__
        status = getattr(exc, "status_code", None)
        # Never include exception args that might echo request bodies/keys.
        logger.warning(
            "groq_classify_error type=%s status=%s",
            name,
            status,
        )

        if name in {"AuthenticationError", "PermissionDeniedError"} or status in {401, 403}:
            return GroqAuthError("AUTH_FAILED", "Groq authentication failed")
        if name == "RateLimitError" or status == 429:
            retry_after = None
            headers = getattr(exc, "headers", None) or {}
            raw = headers.get("retry-after") if hasattr(headers, "get") else None
            if raw is not None:
                try:
                    retry_after = float(raw)
                except (TypeError, ValueError):
                    retry_after = None
            return GroqRateLimitError(
                "RATE_LIMITED",
                "Groq rate limit exceeded",
                retry_after_seconds=retry_after,
            )
        if name in {"APITimeoutError", "TimeoutError"} or "timeout" in name.lower():
            return GroqTimeoutError("TIMEOUT", "Groq request timed out")
        if name in {"APIConnectionError"} or "connection" in name.lower():
            return GroqTransientError("NETWORK_ERROR", "Groq network error")
        if name in {"InternalServerError"} or (
            isinstance(status, int) and status >= 500
        ):
            return GroqTransientError("PROVIDER_ERROR", "Groq provider error")
        if status == 400 or name in {"BadRequestError", "UnprocessableEntityError"}:
            return GroqBadRequestError("BAD_REQUEST", "Groq rejected the request")
        return GroqTransientError("PROVIDER_ERROR", "Groq request failed")

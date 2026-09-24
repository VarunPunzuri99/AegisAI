"""Groq provider-specific errors (safe for callers; no secrets)."""

from __future__ import annotations


class GroqIntegrationError(Exception):
    """Base Groq integration failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class GroqAuthError(GroqIntegrationError):
    pass


class GroqRateLimitError(GroqIntegrationError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(code, message)
        self.retry_after_seconds = retry_after_seconds


class GroqTimeoutError(GroqIntegrationError):
    pass


class GroqTransientError(GroqIntegrationError):
    pass


class GroqBadRequestError(GroqIntegrationError):
    pass

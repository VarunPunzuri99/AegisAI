"""Observability domain types — sanitized, no secrets."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ProviderName(StrEnum):
    GROQ = "groq"
    PROMPT_GUARD = "prompt_guard"
    SAFEGUARD = "safeguard"


class ProviderFailureType(StrEnum):
    """Explicit failure categories — never mapped to BENIGN."""

    MISSING_API_KEY = "MISSING_API_KEY"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    SERVER_ERROR = "SERVER_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    EMPTY_RESPONSE = "EMPTY_RESPONSE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    AUTH_FAILED = "AUTH_FAILED"
    BAD_REQUEST = "BAD_REQUEST"
    SDK_UNAVAILABLE = "SDK_UNAVAILABLE"
    UNKNOWN_PROVIDER_ERROR = "UNKNOWN_PROVIDER_ERROR"


class ObservedHealthStatus(StrEnum):
    """
    Distinguishes configuration from observed behavior.

    CONFIGURED alone is NOT healthy — requires successful observations.
    """

    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    NOT_OBSERVED = "NOT_OBSERVED"
    OBSERVED_HEALTHY = "OBSERVED_HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class SecurityMode(StrEnum):
    """Server-side emergency modes — never set by untrusted input or models."""

    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    FAIL_CLOSED = "FAIL_CLOSED"


class ProviderObservation(BaseModel):
    """One sanitized provider call observation."""

    model_config = ConfigDict(frozen=True)

    provider: ProviderName
    model: Optional[str] = None
    operation: str = "detect"
    success: bool
    failure_type: Optional[ProviderFailureType] = None
    latency_ms: float = 0.0
    timeout: bool = False
    retry_count: int = 0
    response_empty: bool = False
    response_malformed: bool = False
    rate_limited: bool = False
    recovered: bool = False
    observed_at: datetime = Field(default_factory=datetime.utcnow)


# Map Groq / detector error codes → taxonomy
ERROR_CODE_TO_FAILURE: dict[str, ProviderFailureType] = {
    "MISSING_API_KEY": ProviderFailureType.MISSING_API_KEY,
    "AUTH_FAILED": ProviderFailureType.AUTH_FAILED,
    "RATE_LIMITED": ProviderFailureType.RATE_LIMITED,
    "TIMEOUT": ProviderFailureType.TIMEOUT,
    "PROVIDER_ERROR": ProviderFailureType.SERVER_ERROR,
    "BAD_REQUEST": ProviderFailureType.BAD_REQUEST,
    "SDK_UNAVAILABLE": ProviderFailureType.SDK_UNAVAILABLE,
    "EMPTY_RESPONSE": ProviderFailureType.EMPTY_RESPONSE,
    "MALFORMED_RESPONSE": ProviderFailureType.MALFORMED_RESPONSE,
    "INVALID_SCHEMA": ProviderFailureType.INVALID_SCHEMA,
    "NETWORK_ERROR": ProviderFailureType.NETWORK_ERROR,
}


def map_error_code(code: str | None) -> ProviderFailureType | None:
    if not code:
        return None
    return ERROR_CODE_TO_FAILURE.get(code, ProviderFailureType.UNKNOWN_PROVIDER_ERROR)

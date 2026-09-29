"""Startup configuration validation — rejects obviously invalid settings.

Never logs secret values (API keys, passwords).
"""

from __future__ import annotations

from app.core.config import Settings
from app.observability.types import SecurityMode


class ConfigurationError(ValueError):
    """Invalid application configuration."""


_ALLOWED_PG_MODES = frozenset({"ALWAYS", "SUSPICIOUS_ONLY", "OFF", "DISABLED"})
_ALLOWED_SG_MODES = frozenset({"ALWAYS", "SUSPICIOUS_ONLY", "OFF", "DISABLED"})
_MAX_RETRIES = 2


def validate_settings(settings: Settings) -> list[str]:
    """
    Validate settings. Returns warning strings for soft issues.
    Raises ConfigurationError for hard invalid values.
    """
    warnings: list[str] = []

    if settings.prompt_guard_timeout_seconds <= 0:
        raise ConfigurationError("PROMPT_GUARD_TIMEOUT_SECONDS must be > 0")
    if settings.safeguard_timeout_seconds <= 0:
        raise ConfigurationError("SAFEGUARD_TIMEOUT_SECONDS must be > 0")
    if settings.evaluation_timeout_seconds <= 0:
        raise ConfigurationError("EVALUATION_TIMEOUT_SECONDS must be > 0")

    if settings.prompt_guard_max_retries < 0:
        raise ConfigurationError("PROMPT_GUARD_MAX_RETRIES must be >= 0")
    if settings.safeguard_max_retries < 0:
        raise ConfigurationError("SAFEGUARD_MAX_RETRIES must be >= 0")
    if settings.prompt_guard_max_retries > _MAX_RETRIES:
        raise ConfigurationError(
            f"PROMPT_GUARD_MAX_RETRIES must be <= {_MAX_RETRIES} (Phase 15 bound)"
        )
    if settings.safeguard_max_retries > _MAX_RETRIES:
        raise ConfigurationError(
            f"SAFEGUARD_MAX_RETRIES must be <= {_MAX_RETRIES} (Phase 15 bound)"
        )

    mode = settings.security_mode.upper().strip()
    try:
        SecurityMode(mode)
    except ValueError as exc:
        raise ConfigurationError(
            f"AEGIS_SECURITY_MODE must be one of {[m.value for m in SecurityMode]}"
        ) from exc

    if settings.prompt_guard_mode.upper() not in _ALLOWED_PG_MODES:
        warnings.append(f"Unrecognized PROMPT_GUARD_MODE={settings.prompt_guard_mode!r}")
    if settings.safeguard_mode.upper() not in _ALLOWED_SG_MODES:
        warnings.append(f"Unrecognized SAFEGUARD_MODE={settings.safeguard_mode!r}")

    if not settings.prompt_guard_model.strip():
        raise ConfigurationError("PROMPT_GUARD_MODEL must not be empty")
    if not settings.safeguard_model.strip():
        raise ConfigurationError("SAFEGUARD_MODEL must not be empty")

    if settings.max_input_length <= 0:
        raise ConfigurationError("MAX_INPUT_LENGTH must be > 0")

    return warnings


def get_security_mode(settings: Settings | None = None) -> SecurityMode:
    from app.core.config import get_settings

    s = settings or get_settings()
    return SecurityMode(s.security_mode.upper().strip())

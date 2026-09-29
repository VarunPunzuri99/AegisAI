"""Centralized application configuration.

Secrets and environment-specific values are loaded from environment variables
and from ``backend/.env`` (resolved relative to the backend package root, not
the process cwd). Risk thresholds are reserved for a later phase.

The root monorepo ``.env`` is not used by the backend.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/ — stable regardless of uvicorn/pytest working directory
BACKEND_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ENV_FILE = BACKEND_ROOT / ".env"


class Settings(BaseSettings):
    """Runtime configuration for the AegisAI backend."""

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = Field(default="development", alias="APP_ENV")
    app_name: str = Field(default="AegisAI", alias="APP_NAME")
    app_version: str = Field(default="0.1.0", alias="APP_VERSION")
    api_prefix: str = Field(default="/api/v1", alias="API_PREFIX")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    database_url: str = Field(
        default="postgresql+psycopg://aegisai:aegisai@localhost:5432/aegisai",
        alias="DATABASE_URL",
    )

    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    groq_detection_model: str = Field(
        default="meta-llama/llama-prompt-guard-2-86m",
        alias="GROQ_DETECTION_MODEL",
    )
    # Preferred Phase 5 alias; falls back to GROQ_DETECTION_MODEL if unset via property.
    prompt_guard_model: str = Field(
        default="meta-llama/llama-prompt-guard-2-86m",
        alias="PROMPT_GUARD_MODEL",
    )
    groq_reasoning_model: str = Field(
        default="openai/gpt-oss-safeguard-20b",
        alias="GROQ_REASONING_MODEL",
    )
    groq_agent_model: str = Field(
        default="openai/gpt-oss-20b",
        alias="GROQ_AGENT_MODEL",
    )

    prompt_guard_enabled: bool = Field(default=True, alias="PROMPT_GUARD_ENABLED")
    prompt_guard_mode: str = Field(default="ALWAYS", alias="PROMPT_GUARD_MODE")
    prompt_guard_timeout_seconds: float = Field(
        default=10.0,
        alias="PROMPT_GUARD_TIMEOUT_SECONDS",
    )
    prompt_guard_max_retries: int = Field(default=2, alias="PROMPT_GUARD_MAX_RETRIES")
    # Conservative character budget for ~512-token Prompt Guard window (not token-accurate).
    prompt_guard_max_chunk_length: int = Field(
        default=400,
        alias="PROMPT_GUARD_MAX_CHUNK_LENGTH",
    )
    prompt_guard_chunk_overlap: int = Field(
        default=40,
        alias="PROMPT_GUARD_CHUNK_OVERLAP",
    )

    # Phase 6 — GPT-OSS-Safeguard semantic analyzer
    safeguard_enabled: bool = Field(default=True, alias="SAFEGUARD_ENABLED")
    safeguard_model: str = Field(
        default="openai/gpt-oss-safeguard-20b",
        alias="SAFEGUARD_MODEL",
    )
    safeguard_timeout_seconds: float = Field(
        default=10.0,
        alias="SAFEGUARD_TIMEOUT_SECONDS",
    )
    safeguard_max_retries: int = Field(default=2, alias="SAFEGUARD_MAX_RETRIES")
    safeguard_mode: str = Field(default="SUSPICIOUS_ONLY", alias="SAFEGUARD_MODE")
    safeguard_max_tokens: int = Field(default=1024, alias="SAFEGUARD_MAX_TOKENS")

    # Phase 15 — evaluation harness timeout (does NOT mutate production detector timeouts)
    evaluation_timeout_seconds: float = Field(
        default=60.0,
        alias="EVALUATION_TIMEOUT_SECONDS",
        description=(
            "Live evaluation harness budget per provider call. "
            "Distinct from PROMPT_GUARD_TIMEOUT_SECONDS / SAFEGUARD_TIMEOUT_SECONDS."
        ),
    )
    # Server-side security mode — never set by model/untrusted input
    security_mode: str = Field(default="NORMAL", alias="AEGIS_SECURITY_MODE")

    # Phase 17A — development authentication (tokens from environment only)
    aegis_auth_mode: str = Field(default="development", alias="AEGIS_AUTH_MODE")
    aegis_demo_token_user: str = Field(default="", alias="AEGIS_DEMO_TOKEN_USER")
    aegis_demo_token_readonly: str = Field(default="", alias="AEGIS_DEMO_TOKEN_READONLY")
    aegis_demo_token_agent: str = Field(default="", alias="AEGIS_DEMO_TOKEN_AGENT")
    aegis_demo_token_service: str = Field(default="", alias="AEGIS_DEMO_TOKEN_SERVICE")
    aegis_demo_token_disabled: str = Field(default="", alias="AEGIS_DEMO_TOKEN_DISABLED")
    aegis_demo_token_tenant_b: str = Field(default="", alias="AEGIS_DEMO_TOKEN_TENANT_B")

    # Phase 17B — MCP mock gateway limits
    mcp_max_response_bytes: int = Field(default=65_536, alias="MCP_MAX_RESPONSE_BYTES")
    mcp_max_output_items: int = Field(default=50, alias="MCP_MAX_OUTPUT_ITEMS")
    mcp_timeout_seconds: float = Field(default=2.0, alias="MCP_TIMEOUT_SECONDS")
    mcp_max_calls_per_action: int = Field(default=1, alias="MCP_MAX_CALLS_PER_ACTION")

    cors_origins: str = Field(
        default="http://localhost:3000",
        alias="CORS_ORIGINS",
    )

    # Preprocessing / normalization limits (Phase 3)
    max_input_length: int = Field(default=100_000, alias="MAX_INPUT_LENGTH")
    max_decoded_length: int = Field(default=50_000, alias="MAX_DECODED_LENGTH")
    max_decode_depth: int = Field(default=2, alias="MAX_DECODE_DEPTH")
    max_chunks: int = Field(default=64, alias="MAX_CHUNKS")
    max_chunk_length: int = Field(
        default=1500,
        alias="MAX_CHUNK_LENGTH",
        description=(
            "Fallback chunk size in characters when no model tokenizer is configured. "
            "Not equal to Prompt Guard token counts."
        ),
    )
    chunk_overlap_length: int = Field(default=100, alias="CHUNK_OVERLAP_LENGTH")
    max_encoded_candidates: int = Field(default=16, alias="MAX_ENCODED_CANDIDATES")

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse CORS_ORIGINS into a list of allowed origins."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()

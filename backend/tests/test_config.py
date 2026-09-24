"""Configuration loading tests."""

from app.core.config import Settings, get_settings


def test_settings_defaults() -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        APP_ENV="test",
        APP_NAME="AegisAI",
        DATABASE_URL="postgresql+psycopg://aegisai:aegisai@localhost:5432/aegisai",
        CORS_ORIGINS="http://localhost:3000,http://example.com",
    )
    assert settings.app_env == "test"
    assert settings.app_name == "AegisAI"
    assert settings.api_prefix == "/api/v1"
    assert settings.groq_detection_model == "meta-llama/llama-prompt-guard-2-86m"
    assert settings.cors_origin_list == [
        "http://localhost:3000",
        "http://example.com",
    ]


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    first = get_settings()
    second = get_settings()
    assert first is second
    get_settings.cache_clear()

"""AegisAI FastAPI application entrypoint."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.errors import register_exception_handlers
from app.api.router import api_router
from app.core.config import get_settings
from app.core.config_validation import ConfigurationError, validate_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Validate configuration at import/startup (fail loud on invalid values).
try:
    for warning in validate_settings(settings):
        logger.warning("config_warning %s", warning)
except ConfigurationError as exc:
    logger.error("config_invalid code=CONFIGURATION_ERROR msg=%s", str(exc))
    raise

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AegisAI — Agentic Prompt Injection Firewall. "
        "Security pipeline through Phase 14; Phase 15 adds observability, "
        "live evaluation diagnostics, and production-hardening checks."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)
app.include_router(api_router)


@app.get("/")
def root() -> dict[str, str]:
    """Return basic application information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "status": "running",
        "message": "AegisAI backend — security pipeline + dashboard inspect APIs",
        "docs": "/docs",
        "api_prefix": settings.api_prefix,
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe — process is running. Independent of Groq reachability."""
    return {
        "status": "healthy",
        "service": "aegisai-backend",
        "version": __version__,
    }


@app.get("/readiness")
def readiness() -> dict:
    """
    Readiness probe — configuration valid and DB reachable.

    Does NOT require Groq to be reachable; the app can operate in
    degraded/fail-closed modes without the provider.
    """
    from sqlalchemy import text

    from app.core.database import SessionLocal

    checks: dict[str, str] = {
        "configuration": "ok",
        "database": "unknown",
        "groq_configured": "yes" if (settings.groq_api_key or "").strip() else "no",
        "security_mode": settings.security_mode,
    }
    ready = True
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"
        ready = False
        logger.warning("readiness database unavailable")

    return {
        "status": "ready" if ready else "not_ready",
        "checks": checks,
        "note": (
            "Readiness does not probe live Groq. "
            "Liveness is /health. Configured ≠ OBSERVED_HEALTHY."
        ),
    }

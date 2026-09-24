"""AegisAI FastAPI application entrypoint.

Phase 2 adds the scan domain API and PostgreSQL-backed persistence.
Detection engines are intentionally not invoked yet.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.errors import register_exception_handlers
from app.api.router import api_router
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AegisAI — Agentic Prompt Injection Firewall. "
        "Phase 2: scan domain, database models, and metadata API. "
        "Detection / Groq / risk / policy are not implemented yet."
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
        "message": "AegisAI backend Phase 2 — scan domain (detection not implemented)",
        "docs": "/docs",
        "api_prefix": settings.api_prefix,
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe for orchestration and local verification."""
    return {
        "status": "healthy",
        "service": "aegisai-backend",
        "version": __version__,
    }

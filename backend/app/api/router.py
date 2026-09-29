"""API router aggregation."""

from fastapi import APIRouter

from app.api.routes import agent_runtime, audit, authz, dashboard, inspect, mcp, scans
from app.core.config import get_settings

settings = get_settings()

api_router = APIRouter(prefix=settings.api_prefix)
api_router.include_router(scans.router)
api_router.include_router(inspect.router)
api_router.include_router(dashboard.router)
api_router.include_router(audit.router)
api_router.include_router(agent_runtime.router)
api_router.include_router(authz.router)
api_router.include_router(mcp.router)

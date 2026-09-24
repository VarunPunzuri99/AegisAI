"""API router aggregation."""

from fastapi import APIRouter

from app.api.routes import scans
from app.core.config import get_settings

settings = get_settings()

api_router = APIRouter(prefix=settings.api_prefix)
api_router.include_router(scans.router)

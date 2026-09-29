"""Read-only dashboard APIs — Phase 17A authenticated + dashboard:read."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.authentication.dependencies import require_capability
from app.authentication.types import AuthenticatedPrincipal
from app.core.database import get_db
from app.schemas.inspect import (
    EvaluationOverviewResponse,
    PlaygroundScenario,
    PolicyOverviewResponse,
    RecentActivityResponse,
    SystemStatusResponse,
    ToolsOverviewResponse,
)
from app.services import dashboard_service
from app.services.scan_service import ScanService

RequireDashboard = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("dashboard:read")),
]

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_capability("dashboard:read"))],
)


@router.get(
    "/evaluation",
    response_model=EvaluationOverviewResponse,
    summary="Latest evaluation report overview",
)
def get_evaluation_overview(_principal: RequireDashboard) -> EvaluationOverviewResponse:
    return dashboard_service.load_evaluation_overview()


@router.get(
    "/playground",
    response_model=list[PlaygroundScenario],
    summary="Attack playground scenarios",
)
def get_playground_scenarios(_principal: RequireDashboard) -> list[PlaygroundScenario]:
    return list(dashboard_service.PLAYGROUND_SCENARIOS)


@router.get(
    "/policy",
    response_model=PolicyOverviewResponse,
    summary="Read-only enforcement policy overview",
)
def get_policy_overview(_principal: RequireDashboard) -> PolicyOverviewResponse:
    return dashboard_service.policy_overview()


@router.get(
    "/tools",
    response_model=ToolsOverviewResponse,
    summary="Registered tools and firewall controls",
)
def get_tools_overview(_principal: RequireDashboard) -> ToolsOverviewResponse:
    return dashboard_service.tools_overview()


@router.get(
    "/status",
    response_model=SystemStatusResponse,
    summary="Configuration status (no live provider probe)",
)
def get_system_status(_principal: RequireDashboard) -> SystemStatusResponse:
    return dashboard_service.system_status()


@router.get(
    "/providers",
    summary="Observed provider health (sanitized; no secrets)",
)
def get_providers(_principal: RequireDashboard) -> dict:
    return dashboard_service.providers_overview()


@router.get(
    "/performance",
    summary="Pipeline / provider latency overview (eval + in-process)",
)
def get_performance(_principal: RequireDashboard) -> dict:
    return dashboard_service.performance_overview()


@router.get(
    "/review-analysis",
    summary="REVIEW / UNCERTAIN / conflict diagnostic analysis",
)
def get_review_analysis(_principal: RequireDashboard) -> dict:
    return dashboard_service.review_analysis_overview()


@router.get(
    "/activity",
    response_model=RecentActivityResponse,
    summary="Recent security activity from persisted events",
)
def get_recent_activity(
    _principal: RequireDashboard,
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
) -> RecentActivityResponse:
    from app.services.security_event_service import SecurityEventService

    events, _total = SecurityEventService(db).list_events(page=1, page_size=limit)
    if events:
        return dashboard_service.recent_activity_from_security_events(events)
    service = ScanService(db)
    items, _ = service.list_scans(page=1, page_size=limit)
    return dashboard_service.recent_activity_from_scans(list(items))

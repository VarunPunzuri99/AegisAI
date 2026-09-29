"""Agent runtime simulation API — Phase 14 + Phase 17A auth."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.agents.runtime import AgentRuntime, scenario_summaries
from app.agents.runtime.types import SimulationResult
from app.api.errors import AppError
from app.authentication.dependencies import require_capability
from app.authentication.types import AuthenticatedPrincipal
from app.core.database import get_db
from app.schemas.errors import ErrorResponse

RequireAgent = Annotated[
    AuthenticatedPrincipal,
    Depends(require_capability("agent:simulate")),
]

router = APIRouter(
    prefix="/agent",
    tags=["agent-runtime"],
    dependencies=[Depends(require_capability("agent:simulate"))],
)


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(..., min_length=1, max_length=128)


class ScenarioSummary(BaseModel):
    scenario_id: str
    title: str
    description: str
    user_task: str


@router.get(
    "/scenarios",
    response_model=list[ScenarioSummary],
    summary="List Phase 14 agent runtime demo scenarios",
)
def list_scenarios(_principal: RequireAgent) -> list[ScenarioSummary]:
    return [ScenarioSummary(**s) for s in scenario_summaries()]


@router.post(
    "/simulate",
    response_model=SimulationResult,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
    summary="Run a deterministic agent runtime simulation",
    description=(
        "Simulates an agent session through detection → agent workflow → "
        "Tool Firewall → mock executor. No real email, DB mutation, shell, or MCP."
    ),
)
def simulate_agent(
    body: SimulateRequest,
    _principal: RequireAgent,
    db: Session = Depends(get_db),
) -> SimulationResult:
    runtime = AgentRuntime(db=db)
    result = runtime.simulate(body.scenario_id)
    if result.state.value == "FAILED" and "UNKNOWN_SCENARIO" in result.security.reason_codes:
        raise AppError(
            "UNKNOWN_SCENARIO",
            f"Unknown scenario_id: {body.scenario_id}",
            status_code=400,
        )
    return result

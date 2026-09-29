"""Deterministic planner — maps scenarios to AgentActionRequest proposals."""

from __future__ import annotations

from app.agents.runtime.scenarios import PlannedAction, RuntimeScenario
from app.agents.types import AgentActionRequest


def plan_actions(scenario: RuntimeScenario) -> list[AgentActionRequest]:
    """Build action requests from scenario plan (no LLM)."""
    return [_to_request(step, default_intent=scenario.user_task) for step in scenario.planned_actions]


def _to_request(step: PlannedAction, *, default_intent: str) -> AgentActionRequest:
    return AgentActionRequest(
        action_type=step.action_type,
        target=step.target,
        parameters=dict(step.parameters),
        declared_intent=step.declared_intent or default_intent,
    )


def tool_name_for_step(step: PlannedAction) -> str | None:
    return step.tool_name_override

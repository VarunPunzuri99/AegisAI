"""Agent session helpers and runtime limit enforcement."""

from __future__ import annotations

from app.agents.runtime.types import AgentRuntimeState, AgentSession, RuntimeLimits
from app.agents.types import TrustLevel


class SessionLimitError(Exception):
    def __init__(self, code: str = "SESSION_LIMIT_EXCEEDED") -> None:
        self.code = code
        super().__init__(code)


def new_session(
    *,
    user_task: str,
    scenario_id: str | None = None,
    trust_level: TrustLevel = TrustLevel.UNKNOWN,
) -> AgentSession:
    return AgentSession(
        user_task=user_task,
        original_intent=user_task,
        trust_level=trust_level,
        scenario_id=scenario_id,
        current_state=AgentRuntimeState.IDLE,
    )


def bump_step(session: AgentSession, limits: RuntimeLimits) -> None:
    session.step_count += 1
    if session.step_count > limits.max_steps:
        session.current_state = AgentRuntimeState.SESSION_LIMIT_EXCEEDED
        session.reason_codes.append("SESSION_LIMIT_EXCEEDED")
        raise SessionLimitError()


def bump_action(session: AgentSession, limits: RuntimeLimits) -> None:
    session.action_count += 1
    if session.action_count > limits.max_actions_per_session:
        session.current_state = AgentRuntimeState.SESSION_LIMIT_EXCEEDED
        session.reason_codes.append("SESSION_LIMIT_EXCEEDED")
        raise SessionLimitError()


def bump_tool_call(session: AgentSession, limits: RuntimeLimits) -> None:
    session.tool_call_count += 1
    if session.tool_call_count > limits.max_tool_calls_per_session:
        session.current_state = AgentRuntimeState.SESSION_LIMIT_EXCEEDED
        session.reason_codes.append("SESSION_LIMIT_EXCEEDED")
        raise SessionLimitError()

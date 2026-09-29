"""Phase 14 agent runtime types — simulation only; no real side effects."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.types import TrustLevel
from app.core.enums import SourceType


class AgentRuntimeState(StrEnum):
    IDLE = "IDLE"
    PLANNING = "PLANNING"
    CONTEXT_INSPECTION = "CONTEXT_INSPECTION"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    SECURITY_CHECK = "SECURITY_CHECK"
    TOOL_PENDING = "TOOL_PENDING"
    TOOL_EXECUTED = "TOOL_EXECUTED"
    COMPLETED = "COMPLETED"
    SECURITY_BLOCKED = "SECURITY_BLOCKED"
    ACTION_REQUIRES_APPROVAL = "ACTION_REQUIRES_APPROVAL"
    TOOL_DENIED = "TOOL_DENIED"
    FAILED = "FAILED"
    SESSION_LIMIT_EXCEEDED = "SESSION_LIMIT_EXCEEDED"


class ContextSourceType(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    DEVELOPER = "DEVELOPER"
    DOCUMENT = "DOCUMENT"
    WEB = "WEB"
    API = "API"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    OCR = "OCR"
    UNKNOWN = "UNKNOWN"


class AgentContextItem(BaseModel):
    """One context fragment with application-assigned trust (never model-upgradable)."""

    model_config = ConfigDict(frozen=True)

    item_id: UUID = Field(default_factory=uuid4)
    source_type: ContextSourceType
    trust_level: TrustLevel
    content_hash: str
    content_length: int
    label: str = ""
    # Short safe preview for demo UI only (never secrets).
    preview: str = ""


class AgentSession(BaseModel):
    """Runtime session metadata — no raw prompts or secrets."""

    model_config = ConfigDict(frozen=False)

    session_id: UUID = Field(default_factory=uuid4)
    user_task: str
    original_intent: str
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    current_state: AgentRuntimeState = AgentRuntimeState.IDLE
    action_count: int = 0
    tool_call_count: int = 0
    step_count: int = 0
    scenario_id: Optional[str] = None
    context: list[AgentContextItem] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_actions_per_session: int = 10
    max_tool_calls_per_session: int = 10
    max_steps: int = 20


class RuntimeStepEvent(BaseModel):
    """Auditable step for UI timeline (no sensitive payloads)."""

    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    status: str  # ok | warn | blocked | skipped
    summary: str


class SimulationActionView(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: Optional[UUID] = None
    action_type: Optional[str] = None
    tool_name: Optional[str] = None
    target: Optional[str] = None
    risk: Optional[str] = None
    intent_alignment: Optional[bool] = None
    reason: Optional[str] = None


class SimulationSecurityView(BaseModel):
    model_config = ConfigDict(frozen=True)

    detection: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    policy: Optional[str] = None
    conflict: bool = False
    uncertainty: bool = False
    tool_decision: Optional[str] = None
    reason_codes: list[str] = Field(default_factory=list)
    attack_types: list[str] = Field(default_factory=list)


class SimulationExecutionView(BaseModel):
    model_config = ConfigDict(frozen=True)

    executed: bool = False
    simulated: bool = True
    tool_result_summary: Optional[str] = None
    trusted_output: bool = False  # tool output never auto-trusted


class SimulationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: UUID
    scenario_id: str
    state: AgentRuntimeState
    original_intent: str
    untrusted_preview: Optional[str] = None
    action: Optional[SimulationActionView] = None
    security: SimulationSecurityView
    execution: SimulationExecutionView
    steps: list[RuntimeStepEvent] = Field(default_factory=list)
    event_id: Optional[UUID] = None
    note: str = (
        "Phase 14 agent runtime simulation. Mock tools only. "
        "Existing Tool Firewall remains the execution boundary."
    )


def source_type_for_context(ctx: ContextSourceType) -> SourceType:
    """Map context source to Phase 2 SourceType for detection."""
    mapping = {
        ContextSourceType.USER: SourceType.USER_MESSAGE,
        ContextSourceType.DOCUMENT: SourceType.PDF,
        ContextSourceType.WEB: SourceType.WEB_PAGE,
        ContextSourceType.API: SourceType.API_RESPONSE,
        ContextSourceType.OCR: SourceType.OCR,
        ContextSourceType.TOOL_OUTPUT: SourceType.API_RESPONSE,
    }
    return mapping.get(ctx, SourceType.USER_MESSAGE)

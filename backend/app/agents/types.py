"""Agent security types — state and action proposals (no tool execution)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision


class TrustLevel(StrEnum):
    """
    Trust of the *source/context*, not authorization.

    A trusted user can still submit UNTRUSTED external content
    (documents, web pages, OCR, API payloads).
    """

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class AgentActionStatus(StrEnum):
    """Agent action lifecycle states (Phase 9 — no EXECUTED)."""

    NO_ACTION = "NO_ACTION"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    ACTION_REQUIRES_REVIEW = "ACTION_REQUIRES_REVIEW"
    ACTION_DENIED = "ACTION_DENIED"
    READY_FOR_TOOL_GUARD = "READY_FOR_TOOL_GUARD"


class ActionRiskLevel(StrEnum):
    """Intrinsic risk of a proposed *action* (distinct from prompt risk)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(StrEnum):
    """Named action intents for classification — not live tools."""

    SEARCH_DOCUMENTS = "search_documents"
    READ_PUBLIC_DATA = "read_public_data"
    READ_PRIVATE_DATA = "read_private_data"
    WRITE_DATA = "write_data"
    EXTERNAL_API_MUTATION = "external_api_mutation"
    SEND_EMAIL = "send_email"
    DELETE_DATA = "delete_data"
    FINANCIAL_TRANSACTION = "financial_transaction"
    CREDENTIAL_CHANGE = "credential_change"
    UNKNOWN = "unknown"


class AgentActionRequest(BaseModel):
    """Inbound request to propose an action (not an execution request)."""

    model_config = ConfigDict(frozen=True)

    action_type: ActionType
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    # Safe, optional declared user intent (not authorization).
    declared_intent: Optional[str] = None


class AgentActionProposal(BaseModel):
    """Intent-only action proposal — never executes a tool."""

    model_config = ConfigDict(frozen=True)

    action_id: UUID = Field(default_factory=uuid4)
    action_type: ActionType
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    action_risk: ActionRiskLevel
    reason: str
    intent_alignment: bool = True
    declared_intent: Optional[str] = None
    security_context: dict[str, Any] = Field(default_factory=dict)


class AgentStateTransition(BaseModel):
    """One auditable state transition (no secrets / raw prompts)."""

    model_config = ConfigDict(frozen=True)

    previous_state: Optional[AgentActionStatus] = None
    new_state: AgentActionStatus
    reason_codes: list[str] = Field(default_factory=list)
    detail: str = ""


class AgentSecurityState(BaseModel):
    """Security-aware agent session state consumed from Phase 7–8 outputs."""

    model_config = ConfigDict(frozen=True)

    session_id: UUID
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    action_status: AgentActionStatus = AgentActionStatus.NO_ACTION
    security_assessment: Optional[UnifiedSecurityAssessment] = None
    policy_decision: Optional[PolicyDecision] = None
    proposal: Optional[AgentActionProposal] = None
    uncertainty: bool = False
    conflict: bool = False
    prompt_risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    prompt_severity: Optional[Severity] = None
    prompt_attack_types: list[AttackType] = Field(default_factory=list)
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    policy_decision_value: Optional[SecurityDecision] = None
    transitions: list[AgentStateTransition] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    audit: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentWorkflowResult(BaseModel):
    """Outcome of one agent security workflow step."""

    model_config = ConfigDict(frozen=True)

    state: AgentSecurityState
    proposal: Optional[AgentActionProposal] = None
    ready_for_tool_guard: bool = False
    executed: bool = False  # Always False in Phase 9

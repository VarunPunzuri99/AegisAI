"""Tool firewall domain types (Phase 10) — independent of PolicyDecision."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.agents.types import ActionRiskLevel, AgentActionProposal
from app.security.detectors.taxonomy import AttackType
from app.security.fusion_types import UnifiedSecurityAssessment
from app.security.policies.policy_types import PolicyDecision, SecurityDecision


class ToolOperationType(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    EXTERNAL = "EXTERNAL"
    DELETE = "DELETE"


class ToolFirewallVerdict(StrEnum):
    """Tool execution authorization (distinct from Phase 8 SecurityDecision)."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


class ApprovalState(StrEnum):
    """Trusted application approval state — never set by untrusted text."""

    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ToolReasonCode(StrEnum):
    TOOL_NOT_ALLOWLISTED = "TOOL_NOT_ALLOWLISTED"
    TOOL_DISABLED = "TOOL_DISABLED"
    SECURITY_POLICY_BLOCK = "SECURITY_POLICY_BLOCK"
    SECURITY_REVIEW_REQUIRED = "SECURITY_REVIEW_REQUIRED"
    INSUFFICIENT_PERMISSION = "INSUFFICIENT_PERMISSION"
    TARGET_NOT_ALLOWED = "TARGET_NOT_ALLOWED"
    INVALID_PARAMETERS = "INVALID_PARAMETERS"
    INTENT_MISMATCH = "INTENT_MISMATCH"
    HIGH_RISK_APPROVAL_REQUIRED = "HIGH_RISK_APPROVAL_REQUIRED"
    CRITICAL_ACTION_APPROVAL_REQUIRED = "CRITICAL_ACTION_APPROVAL_REQUIRED"
    TOOL_ABUSE_DETECTED = "TOOL_ABUSE_DETECTED"
    CREDENTIAL_THEFT_DETECTED = "CREDENTIAL_THEFT_DETECTED"
    SECRET_EXTRACTION_DETECTED = "SECRET_EXTRACTION_DETECTED"
    SECURITY_CONTEXT_MISSING = "SECURITY_CONTEXT_MISSING"
    ACTION_ALREADY_PROCESSED = "ACTION_ALREADY_PROCESSED"
    TOOL_DEFINITION_INVALID = "TOOL_DEFINITION_INVALID"
    POLICY_DECISION_MISSING = "POLICY_DECISION_MISSING"
    ACTION_PROPOSAL_MISSING = "ACTION_PROPOSAL_MISSING"
    UNAUTHORIZED_EXECUTION = "UNAUTHORIZED_EXECUTION"
    EXECUTION_SUCCESS = "EXECUTION_SUCCESS"


class ToolDefinition(BaseModel):
    """Application-controlled tool metadata (DATA — not instructions)."""

    model_config = ConfigDict(frozen=True)

    tool_name: str
    description: str
    operation_type: ToolOperationType
    risk_level: ActionRiskLevel
    allowed_operations: list[str] = Field(default_factory=list)
    allowed_targets: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    # Parameter schema: list of allowed keys + constraints encoded in validators
    allowed_parameters: frozenset[str] = Field(default_factory=frozenset)
    required_parameters: frozenset[str] = Field(default_factory=frozenset)
    requires_approval: bool = False
    enabled: bool = True


class ToolSecurityContext(BaseModel):
    """Minimal session authorization context for the firewall."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    session_id: UUID
    roles: list[str] = Field(default_factory=list)
    permissions: frozenset[str] = Field(default_factory=frozenset)
    tenant_id: Optional[str] = None
    # Phase 16 explicit principal (falls back to user_id if unset)
    principal_id: Optional[str] = None
    approval_state: ApprovalState = ApprovalState.NOT_REQUIRED
    # Optional target-scoped grants (resource allowlist for this session).
    allowed_targets: frozenset[str] = Field(default_factory=frozenset)
    # Optional resource tenant for cross-tenant checks
    resource_tenant_id: Optional[str] = None


class ToolFirewallDecision(BaseModel):
    """Independent tool-authorization decision."""

    model_config = ConfigDict(frozen=True)

    decision: ToolFirewallVerdict
    tool_name: str
    action_id: Optional[UUID] = None
    reason_codes: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    risk_level: Optional[ActionRiskLevel] = None
    security_context: dict[str, Any] = Field(default_factory=dict)
    audit: dict[str, Any] = Field(default_factory=dict)
    explanation: str = ""


class ToolExecutionRequest(BaseModel):
    """Authorized execution envelope — executor rejects anything else."""

    model_config = ConfigDict(frozen=True)

    execution_token: UUID = Field(default_factory=uuid4)
    action_id: UUID
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    target: Optional[str] = None
    firewall_decision: ToolFirewallDecision
    authorized: bool = True


class ToolExecutionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    ERROR = "ERROR"


class ToolExecutionResult(BaseModel):
    """Mock execution result — tool output is always untrusted DATA."""

    model_config = ConfigDict(frozen=True)

    execution_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    tool_name: str
    status: ToolExecutionStatus
    result: dict[str, Any] = Field(default_factory=dict)
    simulated: bool = True
    trusted: bool = False
    source: str = "TOOL_OUTPUT"
    audit_metadata: dict[str, Any] = Field(default_factory=dict)


class ToolAuthorizeInput(BaseModel):
    """Bundle for authorize_tool_call (keeps call site clean)."""

    model_config = ConfigDict(frozen=True)

    proposal: AgentActionProposal
    tool_name: str
    security_context: ToolSecurityContext
    policy_decision: Optional[PolicyDecision] = None
    assessment: Optional[UnifiedSecurityAssessment] = None
    attack_types: list[AttackType] = Field(default_factory=list)
    policy_decision_value: Optional[SecurityDecision] = None

"""Schemas for the Phase 12 inspect / dashboard API (presentation only)."""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import SourceType
from app.schemas.scan import MAX_CONTENT_LENGTH


class InspectRequest(BaseModel):
    """Run the existing security pipeline on untrusted content."""

    content: str = Field(..., min_length=1, max_length=MAX_CONTENT_LENGTH)
    source_type: SourceType = SourceType.USER_MESSAGE
    # When true, authorize a demo sensitive tool call after policy (mock only).
    demo_tool: bool = True

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be empty or whitespace-only")
        return value


class PipelineStageView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    label: str
    status: str  # ok | skipped | unavailable | error
    summary: str
    detail: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)


class EvidenceSourceView(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    available: bool
    label: str
    score: Optional[float] = None
    confidence: Optional[float] = None
    attack_types: list[str] = Field(default_factory=list)
    error_code: Optional[str] = None


class InspectResponse(BaseModel):
    """Dashboard-friendly view of DetectionPipelineResult + optional tool demo."""

    model_config = ConfigDict(frozen=True)

    input_preview: str
    input_length: int
    source_type: str
    normalized_preview: str
    normalization_flags: dict[str, Any] = Field(default_factory=dict)

    rules_label: str
    rules_is_attack: bool
    rules_confidence: float
    rules_findings: list[dict[str, Any]] = Field(default_factory=list)
    attack_types: list[str] = Field(default_factory=list)

    prompt_guard_invoked: bool
    prompt_guard_available: Optional[bool] = None
    prompt_guard_label: Optional[str] = None
    prompt_guard_score: Optional[float] = None
    prompt_guard_error: Optional[str] = None

    safeguard_invoked: bool
    safeguard_available: Optional[bool] = None
    safeguard_label: Optional[str] = None
    safeguard_confidence: Optional[float] = None
    safeguard_intent: Optional[str] = None
    safeguard_target: Optional[str] = None
    safeguard_impact: Optional[str] = None
    safeguard_rationale: list[str] = Field(default_factory=list)
    safeguard_error: Optional[str] = None

    fusion_label: Optional[str] = None
    conflict: bool = False
    uncertainty: bool = False
    evidence_sources: list[EvidenceSourceView] = Field(default_factory=list)

    risk_score: Optional[int] = None
    severity: Optional[str] = None
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)

    policy_decision: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    policy_reason_codes: list[str] = Field(default_factory=list)
    policy_explanation: Optional[str] = None

    agent_status: Optional[str] = None
    agent_reason_codes: list[str] = Field(default_factory=list)

    tool_firewall_ran: bool = False
    tool_name: Optional[str] = None
    tool_decision: Optional[str] = None
    tool_reason_codes: list[str] = Field(default_factory=list)
    tool_explanation: Optional[str] = None

    stages: list[PipelineStageView] = Field(default_factory=list)
    latency_ms: float = 0.0
    timing: dict[str, float] = Field(
        default_factory=dict,
        description="Per-stage pipeline timings in ms (sanitized; no provider secrets).",
    )
    note: str = (
        "Pipeline inspection via existing SecurityDetectionService. "
        "No thresholds modified. Tool execution is mock/sandbox only."
    )
    # Phase 13 persistence identifiers (set after successful DB write).
    event_id: Optional[UUID] = None
    scan_id: Optional[UUID] = None
    content_hash: Optional[str] = None
    persisted: bool = False


class PlaygroundScenario(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    description: str
    expected_category: str
    payload: str


class EvaluationOverviewResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    available: bool
    source: str
    note: str
    dataset_version: Optional[str] = None
    mode: Optional[str] = None
    total_cases: Optional[int] = None
    detection: dict[str, Any] = Field(default_factory=dict)
    fusion_label_counts: dict[str, Any] = Field(default_factory=dict)
    policy_confusion: dict[str, Any] = Field(default_factory=dict)
    tool_metrics: dict[str, Any] = Field(default_factory=dict)
    live_provider_stats: dict[str, Any] = Field(default_factory=dict)
    per_category: dict[str, Any] = Field(default_factory=dict)
    offline_comparison: dict[str, Any] = Field(default_factory=dict)
    latency_ms: dict[str, Any] = Field(default_factory=dict)
    auth_matrix: Optional[str] = None
    invariants: Optional[str] = None
    false_positives: list[str] = Field(default_factory=list)
    false_negatives: list[str] = Field(default_factory=list)
    generated_at: Optional[str] = None


class PolicyOverviewResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_id: str
    version: str
    read_only: bool = True
    bands: list[dict[str, Any]] = Field(default_factory=list)
    special_rules: list[str] = Field(default_factory=list)
    high_impact_categories: list[str] = Field(default_factory=list)
    note: str = "Read-only view of configured enforcement policy. Not editable from the UI."


class ToolOverviewItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool_name: str
    description: str
    risk_level: str
    operation_type: str
    requires_approval: bool
    enabled: bool


class ToolsOverviewResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    tools: list[ToolOverviewItem]
    controls: list[str]
    verdicts: list[str]
    note: str = "Registry is application-controlled. Execution remains mock/sandbox only."


class SystemStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    api: str
    groq_configured: bool
    prompt_guard_enabled: bool
    prompt_guard_mode: str
    safeguard_enabled: bool
    safeguard_mode: str
    note: str = (
        "Configuration status only. Does not probe live Groq availability. "
        "Never exposes API keys."
    )


class RecentActivityItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    time: str
    scan_id: str
    event_id: Optional[str] = None
    detection: Optional[str] = None
    risk: Optional[str] = None
    policy: Optional[str] = None
    tool_decision: Optional[str] = None
    status: str
    preview: Optional[str] = None


class RecentActivityResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    available: bool
    items: list[RecentActivityItem] = Field(default_factory=list)
    note: str = (
        "Recent activity from persisted security events when available."
    )

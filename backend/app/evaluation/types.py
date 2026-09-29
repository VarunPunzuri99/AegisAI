"""Phase 11 evaluation case / result schemas."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class EvalCase(BaseModel):
    """One versioned security evaluation case."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    category: str
    suite: str = "detection"  # detection | decision | tool | red_team | auth_matrix
    attack_family: Optional[str] = None
    input_type: str = "user_text"
    input: str = ""
    description: str = ""
    source: str = "aegis_security_eval_v1"

    expected_label: Optional[str] = None  # ATTACK | BENIGN | UNCERTAIN
    expected_policy: Optional[str] = None  # ALLOW | REVIEW | BLOCK
    expected_tool_decision: Optional[str] = None  # ALLOW | DENY | REQUIRES_APPROVAL
    severity_expectation: Optional[str] = None

    # Offline AI stubs (never from live Groq in default mode)
    stub_prompt_guard: Optional[str] = None  # ATTACK | BENIGN | UNAVAILABLE | UNCERTAIN
    stub_semantic: Optional[str] = None
    stub_rules_attack: Optional[bool] = None

    # Tool / agent fields
    action_type: Optional[str] = None
    tool_name: Optional[str] = None
    target: Optional[str] = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    permissions: list[str] = Field(default_factory=list)
    approval_state: Optional[str] = None
    intent_alignment: Optional[bool] = None
    declared_intent: Optional[str] = None
    replay: bool = False  # second attempt with same action_id
    force_proposal: bool = False  # evaluate tool even if policy would block proposal

    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    case_id: str
    category: str
    suite: str
    passed: bool
    expected_label: Optional[str] = None
    actual_label: Optional[str] = None
    expected_policy: Optional[str] = None
    actual_policy: Optional[str] = None
    expected_tool_decision: Optional[str] = None
    actual_tool_decision: Optional[str] = None
    reason: str = ""
    latency_ms: dict[str, float] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)


class DetectionMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    accuracy: float = 0.0
    total: int = 0


class EvalReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    dataset_version: str
    mode: str
    total_cases: int
    passed: int
    failed: int
    detection: DetectionMetrics
    per_category: dict[str, DetectionMetrics] = Field(default_factory=dict)
    policy_confusion: dict[str, dict[str, int]] = Field(default_factory=dict)
    tool_metrics: dict[str, Any] = Field(default_factory=dict)
    latency_ms: dict[str, float] = Field(default_factory=dict)
    false_positives: list[str] = Field(default_factory=list)
    false_negatives: list[str] = Field(default_factory=list)
    failures: list[dict[str, Any]] = Field(default_factory=list)
    auth_matrix_passed: int = 0
    auth_matrix_total: int = 0
    invariants_passed: int = 0
    invariants_total: int = 0
    note: str = (
        "Evaluation dataset only. Not a production security guarantee."
    )
    software_version: str = "unknown"
    model_configuration: str = "offline-stubs"
    live_provider_stats: dict[str, Any] = Field(default_factory=dict)
    fusion_label_counts: dict[str, int] = Field(default_factory=dict)
    offline_comparison: dict[str, Any] = Field(default_factory=dict)

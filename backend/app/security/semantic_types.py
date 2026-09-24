"""Semantic security assessment types (in-memory; not ALLOW/BLOCK)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import Severity
from app.security.detectors.taxonomy import AttackType


class SemanticLabel(StrEnum):
    ATTACK = "ATTACK"
    BENIGN = "BENIGN"
    UNCERTAIN = "UNCERTAIN"


class SecurityIntent(StrEnum):
    OVERRIDE_INSTRUCTIONS = "OVERRIDE_INSTRUCTIONS"
    EXTRACT_SYSTEM_PROMPT = "EXTRACT_SYSTEM_PROMPT"
    BYPASS_SAFETY = "BYPASS_SAFETY"
    TRIGGER_UNAUTHORIZED_TOOL = "TRIGGER_UNAUTHORIZED_TOOL"
    EXFILTRATE_SENSITIVE_DATA = "EXFILTRATE_SENSITIVE_DATA"
    POISON_CONTEXT = "POISON_CONTEXT"
    HIDE_INSTRUCTIONS = "HIDE_INSTRUCTIONS"
    MANIPULATE_AGENT_ROLE = "MANIPULATE_AGENT_ROLE"
    UNKNOWN = "UNKNOWN"


class SecurityTarget(StrEnum):
    SYSTEM_INSTRUCTIONS = "SYSTEM_INSTRUCTIONS"
    DEVELOPER_INSTRUCTIONS = "DEVELOPER_INSTRUCTIONS"
    AGENT_ROLE = "AGENT_ROLE"
    TOOLS = "TOOLS"
    DATABASE = "DATABASE"
    SECRETS = "SECRETS"
    MEMORY = "MEMORY"
    EXTERNAL_CONTENT = "EXTERNAL_CONTENT"
    UNKNOWN = "UNKNOWN"


class SecurityImpact(StrEnum):
    PROMPT_LEAKAGE = "PROMPT_LEAKAGE"
    UNAUTHORIZED_ACTION = "UNAUTHORIZED_ACTION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CONTEXT_POISONING = "CONTEXT_POISONING"
    SECURITY_CONTROL_BYPASS = "SECURITY_CONTROL_BYPASS"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class SemanticSecurityAssessment(BaseModel):
    """Semantic interpretation of detection evidence — not a final decision."""

    model_config = ConfigDict(frozen=True)

    assessment_id: UUID
    policy_id: str
    policy_version: str
    label: SemanticLabel
    attack_type: Optional[AttackType] = None
    attack_types: list[AttackType] = Field(default_factory=list)
    severity: Severity = Severity.NONE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    intent: SecurityIntent = SecurityIntent.UNKNOWN
    target: SecurityTarget = SecurityTarget.UNKNOWN
    impact: SecurityImpact = SecurityImpact.UNKNOWN
    rationale: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    model: str
    available: bool = True
    error_code: Optional[str] = None
    latency_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

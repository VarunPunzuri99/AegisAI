"""Persist and query Phase 13 security events (downstream of decisions only)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import String, and_, func, select
from sqlalchemy.orm import Session

from app.api.errors import AppError
from app.core.enums import AuditEventType, ScanDecision, ScanStatus, Severity, SourceType
from app.models import AuditEvent, DetectionResult, Scan, SecurityEvent
from app.schemas.inspect import InspectResponse
from app.services.hashing import sha256_hex

_ALLOWED_ATTACK_TYPES = frozenset(
    {
        "instruction_override",
        "role_change",
        "secret_extraction",
        "tool_abuse",
        "credential_theft",
        "context_poisoning",
        "multi_step_jailbreak",
        "encoded_instruction",
        "indirect_prompt_injection",
    }
)

def _map_scan_decision(policy: str | None) -> ScanDecision | None:
    if not policy:
        return None
    try:
        return ScanDecision(policy)
    except ValueError:
        if policy == "REVIEW":
            return ScanDecision.REVIEW
        return ScanDecision.ERROR


def _map_severity(value: str | None) -> Severity | None:
    if not value:
        return None
    try:
        return Severity(value)
    except ValueError:
        return None


def build_detector_summary(result: InspectResponse) -> dict[str, Any]:
    """Safe detector summary — labels/scores only, no prompts."""
    return {
        "rules": {
            "invoked": True,
            "label": result.rules_label,
            "is_attack": result.rules_is_attack,
            "confidence": result.rules_confidence,
        },
        "prompt_guard": {
            "invoked": result.prompt_guard_invoked,
            "available": result.prompt_guard_available,
            "label": result.prompt_guard_label,
            "score": result.prompt_guard_score,
            "error_code": result.prompt_guard_error,
        },
        "semantic": {
            "invoked": result.safeguard_invoked,
            "available": result.safeguard_available,
            "label": result.safeguard_label,
            "confidence": result.safeguard_confidence,
            "error_code": result.safeguard_error,
        },
    }


def sanitize_pipeline_stages(result: InspectResponse) -> list[dict[str, Any]]:
    """Persist stage status/summary only — drop details that may echo content."""
    out: list[dict[str, Any]] = []
    for stage in result.stages:
        out.append(
            {
                "id": stage.id,
                "label": stage.label,
                "status": stage.status,
                "summary": stage.summary,
            }
        )
    return out


def collect_reason_codes(result: InspectResponse) -> list[str]:
    codes: list[str] = []
    for bucket in (
        result.policy_reason_codes,
        result.agent_reason_codes,
        result.tool_reason_codes,
    ):
        for code in bucket:
            if code and code not in codes:
                codes.append(code)
    return codes


class SecurityEventService:
    """Create/list/get security events and update associated Scan rows."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def persist_inspect(
        self,
        *,
        content: str,
        source_type: SourceType,
        result: InspectResponse,
        principal_id: str | None = None,
        tenant_id: str | None = None,
    ) -> tuple[Scan, SecurityEvent]:
        """
        Persist Scan + SecurityEvent from an already-computed InspectResponse.

        Does not recalculate risk/policy. Raises AppError on persistence failure
        after rollback (does not alter the security decision itself).
        principal_id/tenant_id are derived from authentication — never from
        client-supplied identity overrides. Tokens are never persisted.
        """
        content_hash = sha256_hex(content)
        try:
            scan = Scan(
                source_type=source_type,
                content_hash=content_hash,
                content_length=len(content),
                status=ScanStatus.COMPLETED,
                decision=_map_scan_decision(result.policy_decision),
                risk_score=float(result.risk_score) if result.risk_score is not None else None,
                severity=_map_severity(result.severity),
                error_message=None,
            )
            self.db.add(scan)
            self.db.flush()

            self.db.add(
                AuditEvent(
                    scan_id=scan.id,
                    event_type=AuditEventType.SCAN_CREATED.value,
                    actor="system",
                    message="Scan created from inspect pipeline.",
                    event_metadata={
                        "source_type": source_type.value,
                        "content_length": len(content),
                        "content_hash": content_hash,
                    },
                )
            )

            # Detector rows — structured summaries only (no raw provider payloads).
            self.db.add(
                DetectionResult(
                    scan_id=scan.id,
                    detector_name="deterministic_rules",
                    detector_version="v1",
                    is_attack=result.rules_is_attack,
                    confidence=result.rules_confidence,
                    attack_types=list(result.attack_types),
                    raw_result={
                        "label": result.rules_label,
                        "finding_count": len(result.rules_findings),
                    },
                )
            )
            if result.prompt_guard_invoked:
                self.db.add(
                    DetectionResult(
                        scan_id=scan.id,
                        detector_name="prompt_guard",
                        detector_version="v1",
                        is_attack=(
                            result.prompt_guard_label == "ATTACK"
                            if result.prompt_guard_label
                            else None
                        ),
                        confidence=result.prompt_guard_score,
                        attack_types=[],
                        raw_result={
                            "label": result.prompt_guard_label,
                            "available": result.prompt_guard_available,
                            "error_code": result.prompt_guard_error,
                        },
                    )
                )
            if result.safeguard_invoked:
                self.db.add(
                    DetectionResult(
                        scan_id=scan.id,
                        detector_name="semantic_safeguard",
                        detector_version="v1",
                        is_attack=(
                            result.safeguard_label == "ATTACK"
                            if result.safeguard_label
                            else None
                        ),
                        confidence=result.safeguard_confidence,
                        attack_types=list(result.attack_types),
                        raw_result={
                            "label": result.safeguard_label,
                            "available": result.safeguard_available,
                            "intent": result.safeguard_intent,
                            "target": result.safeguard_target,
                            "impact": result.safeguard_impact,
                            "error_code": result.safeguard_error,
                        },
                    )
                )

            event = SecurityEvent(
                scan_id=scan.id,
                source_type=source_type.value,
                content_hash=content_hash,
                content_length=len(content),
                detection_label=result.fusion_label,
                attack_types=list(result.attack_types),
                risk_score=result.risk_score,
                severity=result.severity,
                policy_decision=result.policy_decision,
                policy_id=result.policy_id,
                policy_version=result.policy_version,
                conflict=result.conflict,
                uncertainty=result.uncertainty,
                agent_state=result.agent_status,
                action_id=None,
                action_type=None,
                tool_name=result.tool_name,
                tool_decision=result.tool_decision,
                approval_state=None,
                intent=result.safeguard_intent,
                target=result.safeguard_target,
                impact=result.safeguard_impact,
                reason_codes=collect_reason_codes(result),
                detector_summary=build_detector_summary(result),
                pipeline_stages=sanitize_pipeline_stages(result),
                risk_factors=[
                    {
                        "factor": rf.get("factor"),
                        "points": rf.get("points"),
                        "reason": rf.get("reason"),
                    }
                    for rf in result.risk_factors
                ],
                simulated=True,
                latency_ms=result.latency_ms,
                event_metadata={
                    "policy_explanation": result.policy_explanation,
                    "tool_firewall_ran": result.tool_firewall_ran,
                    **(
                        {"principal_id": principal_id}
                        if principal_id
                        else {}
                    ),
                    **({"tenant_id": tenant_id} if tenant_id else {}),
                },
                note=(
                    "Application-level structured security event. "
                    "Not a tamper-evident compliance ledger or SIEM."
                ),
            )
            self.db.add(event)
            self.db.flush()

            self.db.add(
                AuditEvent(
                    scan_id=scan.id,
                    event_type=AuditEventType.SECURITY_EVENT_RECORDED.value,
                    actor="system",
                    message="Security event persisted from inspect pipeline.",
                    event_metadata={
                        "security_event_id": str(event.id),
                        "policy_decision": result.policy_decision,
                        "detection_label": result.fusion_label,
                    },
                )
            )
            self.db.commit()
            self.db.refresh(scan)
            self.db.refresh(event)
            return scan, event
        except AppError:
            self.db.rollback()
            raise
        except Exception as exc:  # noqa: BLE001 — map to structured persistence failure
            self.db.rollback()
            raise AppError(
                "AUDIT_PERSISTENCE_FAILED",
                "Security analysis completed but audit persistence failed.",
                status_code=500,
            ) from exc

    def get_event(self, event_id: uuid.UUID) -> SecurityEvent:
        event = self.db.get(SecurityEvent, event_id)
        if event is None:
            raise AppError(
                "SECURITY_EVENT_NOT_FOUND",
                "Security event was not found.",
                status_code=404,
            )
        return event

    def list_events(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        decision: str | None = None,
        severity: str | None = None,
        detection_label: str | None = None,
        attack_type: str | None = None,
        tool_name: str | None = None,
        tool_decision: str | None = None,
        agent_state: str | None = None,
        policy_version: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> tuple[list[SecurityEvent], int]:
        if page < 1:
            raise AppError("INVALID_PAGE", "page must be >= 1", status_code=422)
        if page_size < 1 or page_size > 100:
            raise AppError(
                "INVALID_PAGE_SIZE",
                "page_size must be between 1 and 100.",
                status_code=422,
            )

        filters: list[Any] = []
        if decision:
            filters.append(SecurityEvent.policy_decision == decision.upper())
        if severity:
            filters.append(SecurityEvent.severity == severity.upper())
        if detection_label:
            filters.append(SecurityEvent.detection_label == detection_label.upper())
        if tool_name:
            # Exact match only — never interpolate into SQL text.
            filters.append(SecurityEvent.tool_name == tool_name)
        if tool_decision:
            filters.append(SecurityEvent.tool_decision == tool_decision.upper())
        if agent_state:
            filters.append(SecurityEvent.agent_state == agent_state)
        if policy_version:
            filters.append(SecurityEvent.policy_version == policy_version)
        if start_date is not None:
            filters.append(SecurityEvent.created_at >= start_date)
        if end_date is not None:
            filters.append(SecurityEvent.created_at <= end_date)
        if attack_type:
            if attack_type not in _ALLOWED_ATTACK_TYPES:
                raise AppError(
                    "INVALID_ATTACK_TYPE",
                    "attack_type filter is not a known taxonomy value.",
                    status_code=422,
                )
            dialect = self.db.get_bind().dialect.name
            if dialect == "postgresql":
                filters.append(SecurityEvent.attack_types.contains([attack_type]))
            else:
                # SQLite JSON stored as text — bound LIKE on known taxonomy token only.
                filters.append(
                    func.cast(SecurityEvent.attack_types, String).like(
                        f'%"{attack_type}"%'
                    )
                )
        where_clause = and_(*filters) if filters else None
        count_stmt = select(func.count()).select_from(SecurityEvent)
        list_stmt = select(SecurityEvent)
        if where_clause is not None:
            count_stmt = count_stmt.where(where_clause)
            list_stmt = list_stmt.where(where_clause)

        total = self.db.scalar(count_stmt) or 0
        offset = (page - 1) * page_size
        items = list(
            self.db.scalars(
                list_stmt.order_by(SecurityEvent.created_at.desc())
                .offset(offset)
                .limit(page_size)
            ).all()
        )
        return items, total

    def summary_counts(self) -> dict[str, int]:
        total = self.db.scalar(select(func.count()).select_from(SecurityEvent)) or 0

        def _count(column, value: str) -> int:
            return (
                self.db.scalar(
                    select(func.count())
                    .select_from(SecurityEvent)
                    .where(column == value)
                )
                or 0
            )

        return {
            "total": int(total),
            "blocks": _count(SecurityEvent.policy_decision, "BLOCK"),
            "reviews": _count(SecurityEvent.policy_decision, "REVIEW"),
            "allows": _count(SecurityEvent.policy_decision, "ALLOW"),
            "tool_denials": _count(SecurityEvent.tool_decision, "DENY"),
        }

"""Phase 12 inspect orchestration — wraps existing services; no threshold changes."""

from __future__ import annotations

import re
import time
from typing import Any
from uuid import uuid4

from app.agents.types import (
    ActionType,
    AgentActionProposal,
    AgentActionRequest,
    ActionRiskLevel,
)
from app.core.enums import SourceType
from app.schemas.inspect import (
    EvidenceSourceView,
    InspectResponse,
    PipelineStageView,
)
from app.security.detectors.taxonomy import AttackType
from app.security.policies.policy_types import SecurityDecision
from app.services.agent_security import AgentSecurityService
from app.services.security_detection import DetectionPipelineResult, SecurityDetectionService
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.replay import ActionReplayRegistry
from app.tools.registry import ToolRegistry
from app.tools.types import ApprovalState, ToolSecurityContext

_PREVIEW_LEN = 240

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+", re.IGNORECASE)


def _preview(text: str, limit: int = _PREVIEW_LEN) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def _flag_summaries(flags: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in flags.items():
        if value is True:
            out.append(key)
        elif isinstance(value, (list, dict)) and value:
            out.append(key)
    return out[:12]


class InspectService:
    """Presentation adapter over SecurityDetectionService + ToolGuardService."""

    def __init__(
        self,
        *,
        detection: SecurityDetectionService | None = None,
        agent: AgentSecurityService | None = None,
        tool_guard: ToolGuardService | None = None,
    ) -> None:
        self.detection = detection or SecurityDetectionService()
        self.agent = agent or AgentSecurityService()
        # Fresh replay registry per inspect request path (no cross-request state).
        self.tool_guard = tool_guard or ToolGuardService(
            firewall=ToolFirewall(
                registry=ToolRegistry(),
                replay=ActionReplayRegistry(),
            )
        )

    def inspect(
        self,
        content: str,
        source_type: SourceType,
        *,
        demo_tool: bool = True,
    ) -> InspectResponse:
        started = time.perf_counter()
        pipeline = self.detection.analyze(content, source_type)
        timing = dict(pipeline.timing.model_dump()) if pipeline.timing else {}

        t_agent = time.perf_counter()
        action_request = self._infer_demo_action(content, pipeline) if demo_tool else None
        agent_result = self.agent.from_pipeline(
            pipeline,
            action_request=action_request,
            session_id=uuid4(),
        )
        timing["agent_workflow_ms"] = round((time.perf_counter() - t_agent) * 1000.0, 3)

        tool_ran = False
        tool_name: str | None = None
        tool_decision: str | None = None
        tool_reasons: list[str] = []
        tool_explanation: str | None = None

        if demo_tool and self._should_demo_tool(pipeline):
            t_tool = time.perf_counter()
            proposal = agent_result.proposal or self._forced_sensitive_proposal(content)
            ctx = ToolSecurityContext(
                user_id="dashboard-demo",
                session_id=uuid4(),
                roles=["user"],
                permissions=frozenset(
                    {
                        "documents:public:read",
                        "documents:private:read",
                        "records:write",
                        "email:send",
                        "records:delete",
                    }
                ),
                approval_state=ApprovalState.NOT_REQUIRED,
                allowed_targets=frozenset(
                    {"public_documents", "private_documents", "employee_records", "email", "notes"}
                ),
            )
            decision = self.tool_guard.authorize(
                proposal=proposal,
                security_context=ctx,
                policy_decision=pipeline.policy_decision,
                assessment=pipeline.unified,
            )
            timing["tool_firewall_ms"] = round((time.perf_counter() - t_tool) * 1000.0, 3)
            tool_ran = True
            tool_name = decision.tool_name
            tool_decision = decision.decision.value
            tool_reasons = list(decision.reason_codes)
            tool_explanation = decision.explanation

        latency_ms = (time.perf_counter() - started) * 1000.0
        timing["total_ms"] = round(latency_ms, 3)

        return self._to_response(
            content=content,
            source_type=source_type,
            pipeline=pipeline,
            agent_status=agent_result.state.action_status.value,
            agent_reasons=list(agent_result.state.reason_codes),
            tool_ran=tool_ran,
            tool_name=tool_name,
            tool_decision=tool_decision,
            tool_reasons=tool_reasons,
            tool_explanation=tool_explanation,
            latency_ms=latency_ms,
            timing=timing,
        )

    def _should_demo_tool(self, pipeline: DetectionPipelineResult) -> bool:
        if pipeline.policy_decision is None:
            return False
        if pipeline.policy_decision.decision in {
            SecurityDecision.BLOCK,
            SecurityDecision.REVIEW,
        }:
            return True
        unified = pipeline.unified
        if unified and unified.label.value == "ATTACK":
            return True
        return False

    def _infer_demo_action(
        self,
        content: str,
        pipeline: DetectionPipelineResult,
    ) -> AgentActionRequest | None:
        """Propose a sensitive action for demo when content suggests tool abuse."""
        lower = content.lower()
        attack_types = set()
        if pipeline.unified:
            attack_types = {a.value for a in pipeline.unified.attack_types}

        if (
            "email" in lower
            or _EMAIL_RE.search(content)
            or AttackType.TOOL_ABUSE.value in attack_types
            or AttackType.CREDENTIAL_THEFT.value in attack_types
        ):
            recipient = "attacker@example.com"
            match = _EMAIL_RE.search(content)
            if match:
                recipient = match.group(0)
            return AgentActionRequest(
                action_type=ActionType.SEND_EMAIL,
                target="email",
                parameters={
                    "recipient": recipient,
                    "subject": "exfil",
                    "body": "sensitive payload (demo — not sent)",
                },
                declared_intent="Summarize this document.",
            )
        if "delete" in lower or AttackType.TOOL_ABUSE.value in attack_types:
            return AgentActionRequest(
                action_type=ActionType.DELETE_DATA,
                target="employee_records",
                parameters={"record_id": "demo-record"},
                declared_intent="Summarize this document.",
            )
        return AgentActionRequest(
            action_type=ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": "attacker@example.com",
                "subject": "exfil",
                "body": "sensitive payload (demo — not sent)",
            },
            declared_intent="Summarize this document.",
        )

    def _forced_sensitive_proposal(self, content: str) -> AgentActionProposal:
        """When policy BLOCK suppresses proposals, still demonstrate tool DENY."""
        recipient = "attacker@example.com"
        match = _EMAIL_RE.search(content)
        if match:
            recipient = match.group(0)
        return AgentActionProposal(
            action_type=ActionType.SEND_EMAIL,
            target="email",
            parameters={
                "recipient": recipient,
                "subject": "exfil",
                "body": "sensitive payload (demo — not sent)",
            },
            action_risk=ActionRiskLevel.HIGH,
            reason="Dashboard demo of tool firewall under blocked policy",
            intent_alignment=False,
            declared_intent="Summarize this document.",
        )

    def _to_response(
        self,
        *,
        content: str,
        source_type: SourceType,
        pipeline: DetectionPipelineResult,
        agent_status: str,
        agent_reasons: list[str],
        tool_ran: bool,
        tool_name: str | None,
        tool_decision: str | None,
        tool_reasons: list[str],
        tool_explanation: str | None,
        latency_ms: float,
        timing: dict[str, float] | None = None,
    ) -> InspectResponse:
        sec = pipeline.security_input
        det = pipeline.deterministic
        attack_types = sorted({f.attack_type.value for f in det.findings})
        unified = pipeline.unified
        if unified:
            attack_types = sorted({a.value for a in unified.attack_types} or attack_types)

        rules_label = "ATTACK" if det.is_attack else "BENIGN"
        findings = [
            {
                "attack_type": f.attack_type.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "rule_id": f.rule_id,
                "description": f.description,
                "detector_name": f.detector_name,
            }
            for f in det.findings[:20]
        ]

        pg = pipeline.prompt_guard
        sem = pipeline.semantic
        decision = pipeline.policy_decision

        evidence: list[EvidenceSourceView] = []
        if unified:
            for src in unified.sources:
                evidence.append(
                    EvidenceSourceView(
                        source=src.source.value,
                        available=src.available,
                        label=src.label.value,
                        score=src.score,
                        confidence=src.confidence,
                        attack_types=[a.value for a in src.attack_types],
                        error_code=src.error_code,
                    )
                )

        risk_factors = []
        if unified:
            risk_factors = [
                {"factor": rf.factor, "points": rf.points, "reason": rf.reason}
                for rf in unified.risk_factors
            ]

        stages = self._build_stages(
            rules_label=rules_label,
            attack_types=attack_types,
            pipeline=pipeline,
            tool_ran=tool_ran,
            tool_decision=tool_decision,
            tool_name=tool_name,
            agent_status=agent_status,
        )

        return InspectResponse(
            input_preview=_preview(content),
            input_length=len(content),
            source_type=source_type.value,
            normalized_preview=_preview(sec.normalized_text),
            normalization_flags={
                "summary": _flag_summaries(sec.normalization_flags)
                + _flag_summaries(sec.encoding_flags)
                + _flag_summaries(sec.obfuscation_flags),
            },
            rules_label=rules_label,
            rules_is_attack=det.is_attack,
            rules_confidence=det.confidence,
            rules_findings=findings,
            attack_types=attack_types,
            prompt_guard_invoked=pipeline.prompt_guard_invoked,
            prompt_guard_available=pg.available if pg else None,
            prompt_guard_label=pg.label.value if pg else None,
            prompt_guard_score=pg.score if pg else None,
            prompt_guard_error=pg.error_code if pg else None,
            safeguard_invoked=pipeline.semantic_invoked,
            safeguard_available=sem.available if sem else None,
            safeguard_label=sem.label.value if sem else None,
            safeguard_confidence=sem.confidence if sem else None,
            safeguard_intent=sem.intent.value if sem and sem.intent else None,
            safeguard_target=sem.target.value if sem and sem.target else None,
            safeguard_impact=sem.impact.value if sem and sem.impact else None,
            safeguard_rationale=list(sem.rationale) if sem else [],
            safeguard_error=sem.error_code if sem else None,
            fusion_label=unified.label.value if unified else None,
            conflict=bool(unified.conflict) if unified else False,
            uncertainty=bool(unified.uncertainty) if unified else False,
            evidence_sources=evidence,
            risk_score=unified.risk_score if unified else None,
            severity=unified.severity.value if unified else None,
            risk_factors=risk_factors,
            policy_decision=decision.decision.value if decision else None,
            policy_id=decision.policy_id if decision else None,
            policy_version=decision.policy_version if decision else None,
            policy_reason_codes=list(decision.reason_codes) if decision else [],
            policy_explanation=decision.explanation if decision else None,
            agent_status=agent_status,
            agent_reason_codes=agent_reasons,
            tool_firewall_ran=tool_ran,
            tool_name=tool_name,
            tool_decision=tool_decision,
            tool_reason_codes=tool_reasons,
            tool_explanation=tool_explanation,
            stages=stages,
            latency_ms=round(latency_ms, 3),
            timing=dict(timing or {}),
        )

    def _build_stages(
        self,
        *,
        rules_label: str,
        attack_types: list[str],
        pipeline: DetectionPipelineResult,
        tool_ran: bool,
        tool_decision: str | None,
        tool_name: str | None,
        agent_status: str,
    ) -> list[PipelineStageView]:
        pg = pipeline.prompt_guard
        sem = pipeline.semantic
        unified = pipeline.unified
        decision = pipeline.policy_decision

        stages: list[PipelineStageView] = [
            PipelineStageView(
                id="input",
                label="INPUT",
                status="ok",
                summary="Received",
            ),
            PipelineStageView(
                id="normalization",
                label="NORMALIZATION",
                status="ok",
                summary="Normalized",
                detail=_preview(pipeline.security_input.normalized_text, 80),
            ),
            PipelineStageView(
                id="deterministic",
                label="DETERMINISTIC",
                status="ok",
                summary=rules_label,
                detail=", ".join(attack_types[:4]) or None,
                meta={"confidence": pipeline.deterministic.confidence},
            ),
        ]

        if not pipeline.prompt_guard_invoked:
            stages.append(
                PipelineStageView(
                    id="prompt_guard",
                    label="PROMPT GUARD",
                    status="skipped",
                    summary="Not invoked",
                )
            )
        elif pg is None or not pg.available:
            stages.append(
                PipelineStageView(
                    id="prompt_guard",
                    label="PROMPT GUARD",
                    status="unavailable",
                    summary="Unavailable",
                    detail=pg.error_code if pg else "no_result",
                )
            )
        else:
            stages.append(
                PipelineStageView(
                    id="prompt_guard",
                    label="PROMPT GUARD",
                    status="ok",
                    summary=pg.label.value,
                    detail=f"score={pg.score:.3f}" if pg.score is not None else None,
                    meta={"score": pg.score},
                )
            )

        if not pipeline.semantic_invoked:
            stages.append(
                PipelineStageView(
                    id="safeguard",
                    label="SAFEGUARD",
                    status="skipped",
                    summary="Not invoked",
                )
            )
        elif sem is None:
            stages.append(
                PipelineStageView(
                    id="safeguard",
                    label="SAFEGUARD",
                    status="unavailable",
                    summary="Unavailable",
                )
            )
        else:
            stages.append(
                PipelineStageView(
                    id="safeguard",
                    label="SAFEGUARD",
                    status="ok",
                    summary=sem.label.value,
                    detail=(
                        f"confidence={sem.confidence:.3f}"
                        if sem.confidence is not None
                        else None
                    ),
                    meta={"confidence": sem.confidence},
                )
            )

        if unified is None:
            stages.append(
                PipelineStageView(
                    id="fusion",
                    label="FUSION",
                    status="error",
                    summary="Missing",
                )
            )
        else:
            conflict_note = "⚠ CONFLICT" if unified.conflict else None
            stages.append(
                PipelineStageView(
                    id="fusion",
                    label="FUSION",
                    status="ok",
                    summary=unified.label.value,
                    detail=conflict_note,
                    meta={"conflict": unified.conflict, "uncertainty": unified.uncertainty},
                )
            )
            stages.append(
                PipelineStageView(
                    id="risk",
                    label="RISK",
                    status="ok",
                    summary=f"{unified.risk_score} / 100",
                    detail=unified.severity.value,
                )
            )

        if decision is None:
            stages.append(
                PipelineStageView(
                    id="policy",
                    label="POLICY",
                    status="error",
                    summary="Missing",
                )
            )
        else:
            stages.append(
                PipelineStageView(
                    id="policy",
                    label="POLICY",
                    status="ok",
                    summary=decision.decision.value,
                    detail=decision.explanation[:120] if decision.explanation else None,
                )
            )

        stages.append(
            PipelineStageView(
                id="agent",
                label="AGENT",
                status="ok",
                summary=agent_status,
            )
        )

        if tool_ran:
            stages.append(
                PipelineStageView(
                    id="tool_firewall",
                    label="TOOL FIREWALL",
                    status="ok",
                    summary=tool_decision or "UNKNOWN",
                    detail=tool_name,
                )
            )
        else:
            stages.append(
                PipelineStageView(
                    id="tool_firewall",
                    label="TOOL FIREWALL",
                    status="skipped",
                    summary="Not evaluated",
                    detail="Demo tool path not triggered",
                )
            )

        return stages

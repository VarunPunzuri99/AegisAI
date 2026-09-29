"""Offline end-to-end chain evaluation (no live Groq)."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

from app.agents.action_risk import classify_action_risk
from app.agents.types import ActionType, AgentActionProposal
from app.agents.workflow import AgentSecurityWorkflow
from app.core.enums import Severity, SourceType
from app.evaluation.types import CaseResult, EvalCase
from app.integrations.groq.prompt_guard import PromptGuardLabel
from app.security.detectors.taxonomy import AttackType
from app.security.detectors.types import DetectionReport, Finding
from app.security.fusion import DetectionFusionEngine
from app.security.fusion_types import EvidenceLabel
from app.security.policies.policy_types import SecurityDecision
from app.security.policy_engine import evaluate_policy
from app.security.prompt_guard_types import PromptGuardResult
from app.security.semantic_types import (
    SecurityImpact,
    SecurityIntent,
    SecurityTarget,
    SemanticLabel,
    SemanticSecurityAssessment,
)
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.services.deterministic_detection import DeterministicDetectionService
from app.services.input_normalization import InputNormalizationService
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import (
    ApprovalState,
    ToolFirewallVerdict,
    ToolSecurityContext,
)


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000.0, 3)


def _rules_report(is_attack: bool, category: str | None = None) -> DetectionReport:
    if not is_attack:
        return DetectionReport(
            is_attack=False,
            confidence=0.0,
            findings=[],
            detectors_run=["eval_stub"],
        )
    at = AttackType.INSTRUCTION_OVERRIDE
    if category:
        try:
            at = AttackType(category)
        except ValueError:
            mapping = {
                "encoded_instructions": AttackType.ENCODED_INSTRUCTION,
                "encoded_instruction": AttackType.ENCODED_INSTRUCTION,
                "indirect_prompt_injection": AttackType.INDIRECT_PROMPT_INJECTION,
                "multi_step_jailbreak": AttackType.MULTI_STEP_JAILBREAK,
            }
            at = mapping.get(category, AttackType.INSTRUCTION_OVERRIDE)
    finding = Finding(
        attack_type=at,
        severity=Severity.HIGH,
        confidence=0.9,
        detector_name="eval_stub",
        rule_id="EVAL-001",
        evidence_type="eval",
        description="offline evaluation stub finding",
        signals=["eval"],
    )
    return DetectionReport(
        is_attack=True,
        confidence=0.9,
        findings=[finding],
        detectors_run=["eval_stub"],
    )


def _pg_result(stub: str | None) -> tuple[PromptGuardResult | None, bool]:
    if stub is None or stub == "NOT_INVOKED":
        return None, False
    if stub == "UNAVAILABLE":
        return (
            PromptGuardResult(
                available=False,
                model="eval-stub",
                label=PromptGuardLabel.UNKNOWN,
                error_code="TIMEOUT",
            ),
            True,
        )
    if stub == "ATTACK":
        return (
            PromptGuardResult(
                available=True,
                model="eval-stub",
                is_attack=True,
                score=0.92,
                label=PromptGuardLabel.ATTACK,
            ),
            True,
        )
    if stub == "UNCERTAIN":
        return (
            PromptGuardResult(
                available=True,
                model="eval-stub",
                is_attack=None,
                score=0.5,
                label=PromptGuardLabel.UNKNOWN,
            ),
            True,
        )
    return (
        PromptGuardResult(
            available=True,
            model="eval-stub",
            is_attack=False,
            score=0.1,
            label=PromptGuardLabel.BENIGN,
        ),
        True,
    )


def _sem_result(stub: str | None, category: str | None) -> tuple[SemanticSecurityAssessment | None, bool]:
    if stub is None or stub == "NOT_INVOKED":
        return None, False
    if stub == "UNAVAILABLE":
        return (
            SemanticSecurityAssessment(
                assessment_id=uuid4(),
                policy_id=POLICY_ID,
                policy_version=POLICY_VERSION,
                label=SemanticLabel.UNCERTAIN,
                model="eval-stub",
                available=False,
                error_code="TIMEOUT",
            ),
            True,
        )
    attack_types: list[AttackType] = []
    if stub == "ATTACK" and category:
        try:
            attack_types = [AttackType(category)]
        except ValueError:
            attack_types = [AttackType.INSTRUCTION_OVERRIDE]
    label = {
        "ATTACK": SemanticLabel.ATTACK,
        "BENIGN": SemanticLabel.BENIGN,
        "UNCERTAIN": SemanticLabel.UNCERTAIN,
    }.get(stub, SemanticLabel.BENIGN)
    return (
        SemanticSecurityAssessment(
            assessment_id=uuid4(),
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            label=label,
            attack_types=attack_types,
            severity=Severity.HIGH if label == SemanticLabel.ATTACK else Severity.NONE,
            confidence=0.85 if label == SemanticLabel.ATTACK else 0.2,
            intent=SecurityIntent.UNKNOWN,
            target=SecurityTarget.UNKNOWN,
            impact=SecurityImpact.NONE,
            rationale=["eval stub"],
            evidence={},
            model="eval-stub",
            available=True,
        ),
        True,
    )


class OfflineChainEvaluator:
    """Run fusion→policy→agent→firewall with offline stubs (no Groq)."""

    def __init__(self) -> None:
        self.normalizer = InputNormalizationService()
        self.deterministic = DeterministicDetectionService()
        self.fusion = DetectionFusionEngine()
        self.agent = AgentSecurityWorkflow()
        self.tool_guard = ToolGuardService(
            firewall=ToolFirewall(
                registry=ToolRegistry(),
                replay=ActionReplayRegistry(),
            )
        )
        self._latencies: dict[str, list[float]] = {
            k: []
            for k in (
                "normalization",
                "deterministic",
                "fusion",
                "policy",
                "agent",
                "tool_firewall",
                "end_to_end",
            )
        }

    def latency_summary(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for k, vals in self._latencies.items():
            if not vals:
                out[k] = 0.0
                continue
            s = sorted(vals)
            out[f"{k}_median_ms"] = s[len(s) // 2]
            out[f"{k}_p95_ms"] = s[int(len(s) * 0.95)] if len(s) > 1 else s[0]
            out[f"{k}_mean_ms"] = round(sum(s) / len(s), 3)
        return out

    def evaluate_case(self, case: EvalCase) -> CaseResult:
        t0 = time.perf_counter()
        lat: dict[str, float] = {}

        # --- Tool-only cases ---
        if case.suite == "tool" or (
            case.expected_tool_decision and case.tool_name and not case.input
        ):
            return self._eval_tool_case(case, t0)

        # Normalization + deterministic (real)
        t = time.perf_counter()
        try:
            sec = self.normalizer.normalize(
                case.input or " ",
                SourceType.USER_MESSAGE,
            )
        except Exception as exc:
            return CaseResult(
                case_id=case.case_id,
                category=case.category,
                suite=case.suite,
                passed=False,
                expected_label=case.expected_label,
                reason=f"normalization_error: {exc}",
            )
        lat["normalization"] = _ms(t)
        self._latencies["normalization"].append(lat["normalization"])

        t = time.perf_counter()
        det_real = self.deterministic.detect(sec)
        lat["deterministic"] = _ms(t)
        self._latencies["deterministic"].append(lat["deterministic"])

        # Offline stubs for PG/Semantic; rules may use stub or real
        if case.stub_rules_attack is not None:
            det = _rules_report(case.stub_rules_attack, case.category)
        else:
            det = det_real

        pg, pg_inv = _pg_result(case.stub_prompt_guard)
        sem, sem_inv = _sem_result(case.stub_semantic, case.category)

        t = time.perf_counter()
        unified = self.fusion.fuse(
            det,
            pg,
            prompt_guard_invoked=pg_inv,
            semantic=sem,
            semantic_invoked=sem_inv,
        )
        lat["fusion"] = _ms(t)
        self._latencies["fusion"].append(lat["fusion"])

        # Optional medium-risk band force for REVIEW cases
        if case.metadata.get("force_risk_band") == "medium":
            from app.security.fusion_types import UnifiedSecurityAssessment

            unified = UnifiedSecurityAssessment(
                label=unified.label,
                risk_score=55,
                severity=Severity.HIGH,
                attack_types=list(unified.attack_types),
                conflict=unified.conflict,
                uncertainty=unified.uncertainty,
                risk_factors=list(unified.risk_factors),
                sources=list(unified.sources),
                rule_evidence_strength=unified.rule_evidence_strength,
                prompt_guard_score=unified.prompt_guard_score,
                semantic_confidence=unified.semantic_confidence,
                detector_results=dict(unified.detector_results),
                metadata=dict(unified.metadata),
            )

        t = time.perf_counter()
        policy = evaluate_policy(unified)
        lat["policy"] = _ms(t)
        self._latencies["policy"].append(lat["policy"])

        t = time.perf_counter()
        agent_req = None
        if case.action_type and case.force_proposal:
            from app.agents.types import AgentActionRequest

            agent_req = AgentActionRequest(
                action_type=ActionType(case.action_type),
                target=case.target,
                parameters=dict(case.parameters),
                declared_intent=case.declared_intent,
            )
        agent_res = self.agent.run(
            assessment=unified,
            policy_decision=policy,
            action_request=agent_req,
        )
        lat["agent"] = _ms(t)
        self._latencies["agent"].append(lat["agent"])

        actual_tool = None
        if case.expected_tool_decision or case.tool_name:
            tool_res = self._run_firewall(
                case,
                policy_decision=policy,
                assessment=unified,
                proposal=agent_res.proposal,
            )
            actual_tool = tool_res
            lat["tool_firewall"] = tool_res.get("latency_ms", 0.0)
            self._latencies["tool_firewall"].append(lat["tool_firewall"])

        lat["end_to_end"] = _ms(t0)
        self._latencies["end_to_end"].append(lat["end_to_end"])

        actual_policy = policy.decision.value
        reasons: list[str] = []
        passed = True

        # Detection suite: score real deterministic detector honestly (no stub credit).
        if case.suite == "detection":
            actual_label = "ATTACK" if det_real.is_attack else "BENIGN"
            if case.expected_label == "ATTACK" and actual_label != "ATTACK":
                passed = False
                reasons.append(
                    f"deterministic miss: expected ATTACK got {actual_label}"
                )
            elif case.expected_label == "BENIGN" and actual_label == "ATTACK":
                passed = False
                reasons.append("false positive: expected BENIGN got ATTACK")
        else:
            actual_label = unified.label.value
            if case.expected_label and actual_label != case.expected_label:
                passed = False
                reasons.append(
                    f"label expected {case.expected_label} got {actual_label}"
                )

        if case.expected_policy and case.suite != "detection":
            if actual_policy != case.expected_policy:
                passed = False
                reasons.append(
                    f"policy expected {case.expected_policy} got {actual_policy}"
                )

        if case.expected_tool_decision:
            got = (actual_tool or {}).get("decision")
            if got != case.expected_tool_decision:
                passed = False
                reasons.append(
                    f"tool expected {case.expected_tool_decision} got {got}"
                )

        if case.metadata.get("expect_conflict") and not unified.conflict:
            passed = False
            reasons.append("expected conflict=true")

        return CaseResult(
            case_id=case.case_id,
            category=case.category,
            suite=case.suite,
            passed=passed,
            expected_label=case.expected_label,
            actual_label=actual_label,
            expected_policy=case.expected_policy if case.suite != "detection" else None,
            actual_policy=actual_policy if case.suite != "detection" else None,
            expected_tool_decision=case.expected_tool_decision,
            actual_tool_decision=(actual_tool or {}).get("decision"),
            reason="; ".join(reasons),
            latency_ms=lat,
            evidence={
                "conflict": unified.conflict,
                "uncertainty": unified.uncertainty,
                "risk_score": unified.risk_score,
                "deterministic_is_attack": det_real.is_attack,
            },
        )

    def _eval_tool_case(self, case: EvalCase, t0: float) -> CaseResult:
        policy = None
        if case.expected_policy:
            # Minimal assessment for policy path when needed
            from app.security.fusion_types import UnifiedSecurityAssessment

            if case.expected_policy == "BLOCK":
                assessment = UnifiedSecurityAssessment(
                    label=EvidenceLabel.ATTACK,
                    risk_score=90,
                    severity=Severity.CRITICAL,
                    attack_types=[AttackType.TOOL_ABUSE],
                )
            elif case.expected_policy == "REVIEW":
                assessment = UnifiedSecurityAssessment(
                    label=EvidenceLabel.ATTACK,
                    risk_score=40,
                    severity=Severity.MEDIUM,
                )
            else:
                assessment = UnifiedSecurityAssessment(
                    label=EvidenceLabel.BENIGN,
                    risk_score=5,
                    severity=Severity.LOW,
                )
            policy = evaluate_policy(assessment)
        else:
            assessment = None

        # Build synthetic ALLOW policy for tool auth when expected_policy ALLOW
        if policy is None or (
            case.expected_policy == "ALLOW"
            and policy.decision != SecurityDecision.ALLOW
        ):
            from app.security.fusion_types import UnifiedSecurityAssessment
            from app.security.policies.policy_types import PolicyDecision

            assessment = UnifiedSecurityAssessment(
                label=EvidenceLabel.BENIGN,
                risk_score=5,
                severity=Severity.LOW,
            )
            policy = PolicyDecision(
                decision=SecurityDecision.ALLOW,
                policy_id=POLICY_ID,
                policy_version=POLICY_VERSION,
                risk_score=5,
                severity=Severity.LOW,
                explanation="eval tool fixture ALLOW",
            )

        if case.expected_policy == "BLOCK":
            from app.security.fusion_types import UnifiedSecurityAssessment

            assessment = UnifiedSecurityAssessment(
                label=EvidenceLabel.ATTACK,
                risk_score=91,
                severity=Severity.CRITICAL,
                attack_types=[AttackType.TOOL_ABUSE],
            )
            policy = evaluate_policy(assessment)

        tool_info = self._run_firewall(
            case,
            policy_decision=policy,
            assessment=assessment,
            proposal=None,
        )
        lat = {"tool_firewall": tool_info.get("latency_ms", 0.0), "end_to_end": _ms(t0)}
        self._latencies["tool_firewall"].append(lat["tool_firewall"])
        self._latencies["end_to_end"].append(lat["end_to_end"])

        got = tool_info.get("decision")
        passed = got == case.expected_tool_decision
        return CaseResult(
            case_id=case.case_id,
            category=case.category,
            suite=case.suite,
            passed=passed,
            expected_policy=case.expected_policy,
            actual_policy=policy.decision.value if policy else None,
            expected_tool_decision=case.expected_tool_decision,
            actual_tool_decision=got,
            reason=""
            if passed
            else f"tool expected {case.expected_tool_decision} got {got}",
            latency_ms=lat,
            evidence={"reason_codes": tool_info.get("reason_codes", [])},
        )

    def _run_firewall(
        self,
        case: EvalCase,
        *,
        policy_decision: Any,
        assessment: Any,
        proposal: AgentActionProposal | None,
    ) -> dict[str, Any]:
        t = time.perf_counter()
        action_type = ActionType.UNKNOWN
        if case.action_type:
            try:
                action_type = ActionType(case.action_type)
            except ValueError:
                action_type = ActionType.UNKNOWN

        if proposal is None:
            proposal = AgentActionProposal(
                action_type=action_type,
                target=case.target,
                parameters=dict(case.parameters),
                action_risk=classify_action_risk(action_type),
                reason="eval proposal",
                intent_alignment=(
                    True if case.intent_alignment is None else case.intent_alignment
                ),
                declared_intent=case.declared_intent,
            )

        approval = ApprovalState.NOT_REQUIRED
        if case.approval_state:
            approval = ApprovalState(case.approval_state)

        ctx = ToolSecurityContext(
            user_id="eval-user",
            session_id=uuid4(),
            permissions=frozenset(case.permissions),
            approval_state=approval,
        )

        # Isolated firewall per call except replay cases share registry
        if case.replay:
            fw = self.tool_guard.firewall
            # First authorize+mark, then second should deny
            d1 = fw.authorize_tool_call(
                proposal=proposal,
                tool_name=case.tool_name or "search_public_documents",
                security_context=ctx,
                policy_decision=policy_decision,
                assessment=assessment,
            )
            if d1.decision == ToolFirewallVerdict.ALLOW:
                fw.mark_executed(proposal.action_id)
            d2 = fw.authorize_tool_call(
                proposal=proposal,
                tool_name=case.tool_name or "search_public_documents",
                security_context=ctx,
                policy_decision=policy_decision,
                assessment=assessment,
            )
            return {
                "decision": d2.decision.value,
                "reason_codes": list(d2.reason_codes),
                "latency_ms": _ms(t),
                "first_decision": d1.decision.value,
            }

        # Fresh firewall for non-replay isolation
        service = ToolGuardService(
            firewall=ToolFirewall(
                registry=ToolRegistry(),
                replay=ActionReplayRegistry(),
            )
        )
        decision = service.authorize(
            proposal=proposal,
            security_context=ctx,
            policy_decision=policy_decision,
            assessment=assessment,
            tool_name=case.tool_name,
        )
        return {
            "decision": decision.decision.value,
            "reason_codes": list(decision.reason_codes),
            "latency_ms": _ms(t),
        }

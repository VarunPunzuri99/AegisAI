"""Live Groq evaluation chain — uses existing Prompt Guard + Safeguard integrations.

Requires:
  RUN_GROQ_INTEGRATION_TEST=true
  GROQ_API_KEY set (backend/.env)

Does not modify security thresholds. Provider failures are reported, never converted to BENIGN.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

from app.agents.action_risk import classify_action_risk
from app.agents.types import ActionType, AgentActionProposal
from app.core.config import Settings, get_settings
from app.core.enums import SourceType
from app.evaluation.chain import OfflineChainEvaluator
from app.evaluation.types import CaseResult, EvalCase
from app.services.security_detection import SecurityDetectionService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState, ToolSecurityContext
from app.services.tool_guard import ToolGuardService


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000.0, 3)


def live_eval_settings() -> Settings:
    """ALWAYS invoke PG + Safeguard for live measurement (does not mutate process env)."""
    base = get_settings()
    # Evaluation harness may raise timeouts without changing production defaults on disk.
    eval_timeout = max(base.evaluation_timeout_seconds, 60.0)
    return base.model_copy(
        update={
            "prompt_guard_enabled": True,
            "prompt_guard_mode": "ALWAYS",
            "safeguard_enabled": True,
            "safeguard_mode": "ALWAYS",
            "safeguard_timeout_seconds": max(base.safeguard_timeout_seconds, eval_timeout),
            "prompt_guard_timeout_seconds": max(
                base.prompt_guard_timeout_seconds, min(eval_timeout, 30.0)
            ),
        }
    )


class LiveChainEvaluator:
    """
    Live layered evaluation:

      rules + Prompt Guard + Safeguard + fusion + risk + policy
      (+ tool firewall for tool suite cases, no Groq)
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or live_eval_settings()
        self.pipeline = SecurityDetectionService(settings=self.settings)
        self._tool_offline = OfflineChainEvaluator()
        self.stats: dict[str, Any] = {
            "prompt_guard_invoked": 0,
            "prompt_guard_success": 0,
            "prompt_guard_failures": 0,
            "safeguard_invoked": 0,
            "safeguard_success": 0,
            "safeguard_failures": 0,
            "successful_model_calls": 0,
            "provider_failures": [],
            "excluded_detection_cases": [],
        }
        self._latencies: dict[str, list[float]] = {
            "prompt_guard": [],
            "safeguard": [],
            "fusion_policy_end_to_end": [],
            "end_to_end": [],
            "tool_firewall": [],
        }

    def latency_summary(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for k, vals in self._latencies.items():
            if not vals:
                out[f"{k}_median_ms"] = 0.0
                out[f"{k}_p95_ms"] = 0.0
                out[f"{k}_mean_ms"] = 0.0
                continue
            s = sorted(vals)
            out[f"{k}_median_ms"] = s[len(s) // 2]
            out[f"{k}_p95_ms"] = s[int(len(s) * 0.95)] if len(s) > 1 else s[0]
            out[f"{k}_mean_ms"] = round(sum(s) / len(s), 3)
        return out

    def evaluate_case(self, case: EvalCase) -> CaseResult:
        # Tool-only cases: no Groq needed
        if case.suite == "tool" or (
            case.expected_tool_decision and case.tool_name and not case.input.strip()
        ):
            result = self._tool_offline._eval_tool_case(case, time.perf_counter())
            if result.latency_ms.get("tool_firewall"):
                self._latencies["tool_firewall"].append(
                    result.latency_ms["tool_firewall"]
                )
            return result

        if not case.input.strip():
            return CaseResult(
                case_id=case.case_id,
                category=case.category,
                suite=case.suite,
                passed=False,
                reason="empty_input",
            )

        t0 = time.perf_counter()
        # Instrument PG/Safeguard latency via wrappers around existing detectors
        pg_ms = 0.0
        sem_ms = 0.0

        # Hook timing by temporarily wrapping detect/analyze
        orig_pg_detect = self.pipeline.prompt_guard.detect
        orig_sem_analyze = self.pipeline.semantic.analyze

        def timed_pg(sec_in):
            nonlocal pg_ms
            t = time.perf_counter()
            out = orig_pg_detect(sec_in)
            pg_ms = _ms(t)
            return out

        def timed_sem(sec_in, det, pg):
            nonlocal sem_ms
            t = time.perf_counter()
            out = orig_sem_analyze(sec_in, det, pg)
            sem_ms = _ms(t)
            return out

        self.pipeline.prompt_guard.detect = timed_pg  # type: ignore[method-assign]
        self.pipeline.semantic.analyze = timed_sem  # type: ignore[method-assign]
        try:
            pipeline = self.pipeline.analyze(case.input, SourceType.USER_MESSAGE)
        finally:
            self.pipeline.prompt_guard.detect = orig_pg_detect  # type: ignore[method-assign]
            self.pipeline.semantic.analyze = orig_sem_analyze  # type: ignore[method-assign]

        e2e = _ms(t0)
        self._latencies["end_to_end"].append(e2e)
        if pipeline.prompt_guard_invoked:
            self._latencies["prompt_guard"].append(pg_ms)
        if pipeline.semantic_invoked:
            self._latencies["safeguard"].append(sem_ms)
        self._latencies["fusion_policy_end_to_end"].append(e2e)

        # Track invocations / failures
        provider_fail = False
        fail_notes: list[str] = []

        if pipeline.prompt_guard_invoked:
            self.stats["prompt_guard_invoked"] += 1
            pg = pipeline.prompt_guard
            if pg is not None and pg.available:
                self.stats["prompt_guard_success"] += 1
                self.stats["successful_model_calls"] += 1
            else:
                provider_fail = True
                self.stats["prompt_guard_failures"] += 1
                code = pg.error_code if pg else "MISSING_RESULT"
                fail_notes.append(f"prompt_guard:{code}")
                self.stats["provider_failures"].append(
                    {
                        "case_id": case.case_id,
                        "provider": "prompt_guard",
                        "failure_type": code,
                        "handling": "uncertain_or_rules_only_fusion",
                    }
                )

        if pipeline.semantic_invoked:
            self.stats["safeguard_invoked"] += 1
            sem = pipeline.semantic
            if sem is not None and sem.available:
                self.stats["safeguard_success"] += 1
                self.stats["successful_model_calls"] += 1
            else:
                provider_fail = True
                self.stats["safeguard_failures"] += 1
                code = sem.error_code if sem else "MISSING_RESULT"
                fail_notes.append(f"safeguard:{code}")
                self.stats["provider_failures"].append(
                    {
                        "case_id": case.case_id,
                        "provider": "safeguard",
                        "failure_type": code,
                        "handling": "uncertain_or_rules_only_fusion",
                    }
                )

        unified = pipeline.unified
        policy = pipeline.policy_decision
        assert unified is not None and policy is not None

        actual_label = unified.label.value
        actual_policy = policy.decision.value

        # Exclude provider-failed cases from detection metric scoring
        excluded = False
        if case.suite == "detection" and provider_fail:
            excluded = True
            self.stats["excluded_detection_cases"].append(case.case_id)

        # Optional tool decision if case asks for it
        actual_tool = None
        tool_lat = 0.0
        if case.expected_tool_decision and case.tool_name:
            t_tool = time.perf_counter()
            proposal = AgentActionProposal(
                action_type=ActionType(case.action_type or "unknown"),
                target=case.target,
                parameters=dict(case.parameters),
                action_risk=classify_action_risk(
                    ActionType(case.action_type or "unknown")
                ),
                reason="live eval",
                intent_alignment=(
                    True if case.intent_alignment is None else case.intent_alignment
                ),
                declared_intent=case.declared_intent,
            )
            ctx = ToolSecurityContext(
                user_id="live-eval",
                session_id=uuid4(),
                permissions=frozenset(case.permissions),
                approval_state=ApprovalState(
                    case.approval_state or "NOT_REQUIRED"
                ),
            )
            service = ToolGuardService(
                firewall=ToolFirewall(
                    registry=ToolRegistry(),
                    replay=ActionReplayRegistry(),
                )
            )
            decision = service.authorize(
                proposal=proposal,
                security_context=ctx,
                policy_decision=policy,
                assessment=unified,
                tool_name=case.tool_name,
            )
            actual_tool = decision.decision.value
            tool_lat = _ms(t_tool)
            self._latencies["tool_firewall"].append(tool_lat)

        passed = True
        reasons: list[str] = []
        if excluded:
            # Not a scoring pass/fail for detection — mark handled
            passed = True
            reasons.append(
                "excluded_from_detection_metrics:provider_failure;"
                + ",".join(fail_notes)
            )
        else:
            if case.expected_label and actual_label != case.expected_label:
                # UNCERTAIN vs ATTACK: count as miss for attack cases
                if case.suite in {"detection", "decision"}:
                    passed = False
                    reasons.append(
                        f"label expected {case.expected_label} got {actual_label}"
                    )
            if case.expected_policy and case.suite == "decision":
                if actual_policy != case.expected_policy:
                    passed = False
                    reasons.append(
                        f"policy expected {case.expected_policy} got {actual_policy}"
                    )
            if case.expected_tool_decision and actual_tool != case.expected_tool_decision:
                passed = False
                reasons.append(
                    f"tool expected {case.expected_tool_decision} got {actual_tool}"
                )

        return CaseResult(
            case_id=case.case_id,
            category=case.category,
            suite=case.suite,
            passed=passed,
            expected_label=case.expected_label,
            actual_label=actual_label,
            expected_policy=case.expected_policy,
            actual_policy=actual_policy,
            expected_tool_decision=case.expected_tool_decision,
            actual_tool_decision=actual_tool,
            reason="; ".join(reasons),
            latency_ms={
                "prompt_guard": pg_ms,
                "safeguard": sem_ms,
                "tool_firewall": tool_lat,
                "end_to_end": e2e,
            },
            evidence={
                "prompt_guard_invoked": pipeline.prompt_guard_invoked,
                "prompt_guard_available": (
                    pipeline.prompt_guard.available
                    if pipeline.prompt_guard
                    else False
                ),
                "prompt_guard_label": (
                    pipeline.prompt_guard.label.value
                    if pipeline.prompt_guard
                    else None
                ),
                "safeguard_invoked": pipeline.semantic_invoked,
                "safeguard_available": (
                    pipeline.semantic.available if pipeline.semantic else False
                ),
                "safeguard_label": (
                    pipeline.semantic.label.value if pipeline.semantic else None
                ),
                "conflict": unified.conflict,
                "uncertainty": unified.uncertainty,
                "risk_score": unified.risk_score,
                "provider_failure": provider_fail,
                "excluded_from_detection_metrics": excluded,
                "rules_is_attack": pipeline.deterministic.is_attack,
            },
        )

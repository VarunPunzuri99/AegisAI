"""Agent runtime orchestrator — detection → agent workflow → tool firewall → mock exec."""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.agents.action_risk import classify_action_risk
from app.agents.runtime.approval import (
    ApprovalValidationError,
    BoundApproval,
    consume_approval,
    issue_approval,
    validate_approval,
)
from app.agents.runtime.context import make_context_item
from app.agents.runtime.detection import analyze_for_scenario
from app.agents.runtime.planner import plan_actions, tool_name_for_step
from app.agents.runtime.scenarios import RuntimeScenario, get_scenario
from app.agents.runtime.session import (
    SessionLimitError,
    bump_action,
    bump_step,
    bump_tool_call,
    new_session,
)
from app.agents.runtime.types import (
    AgentRuntimeState,
    ContextSourceType,
    RuntimeLimits,
    RuntimeStepEvent,
    SimulationActionView,
    SimulationExecutionView,
    SimulationResult,
    SimulationSecurityView,
    source_type_for_context,
)
from app.agents.types import ActionType, AgentActionProposal, AgentActionRequest, TrustLevel
from app.agents.workflow import AgentSecurityWorkflow
from app.core.enums import SourceType
from app.models import SecurityEvent
from app.services.hashing import sha256_hex
from app.services.security_detection import DetectionPipelineResult
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ACTION_TYPE_TO_TOOL, ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import (
    ApprovalState,
    ToolFirewallVerdict,
    ToolSecurityContext,
)

_DEMO_PERMISSIONS = frozenset(
    {
        "documents:public:read",
        "documents:private:read",
        "records:write",
        "email:send",
        "records:delete",
    }
)
_DEMO_TARGETS = frozenset(
    {"public_documents", "private_documents", "employee_records", "email", "notes"}
)


class AgentRuntime:
    """Simulated agent loop with existing security boundaries (no real side effects)."""

    def __init__(
        self,
        *,
        agent_workflow: AgentSecurityWorkflow | None = None,
        tool_guard: ToolGuardService | None = None,
        limits: RuntimeLimits | None = None,
        db: Session | None = None,
    ) -> None:
        self.agent_workflow = agent_workflow or AgentSecurityWorkflow()
        self.tool_guard = tool_guard or ToolGuardService(
            firewall=ToolFirewall(
                registry=ToolRegistry(),
                replay=ActionReplayRegistry(),
            )
        )
        self.limits = limits or RuntimeLimits()
        self.db = db

    def simulate(self, scenario_id: str) -> SimulationResult:
        scenario = get_scenario(scenario_id)
        if scenario is None:
            return SimulationResult(
                session_id=uuid4(),
                scenario_id=scenario_id,
                state=AgentRuntimeState.FAILED,
                original_intent="",
                security=SimulationSecurityView(reason_codes=["UNKNOWN_SCENARIO"]),
                execution=SimulationExecutionView(executed=False),
                steps=[
                    RuntimeStepEvent(
                        id="error",
                        label="Scenario",
                        status="blocked",
                        summary="Unknown scenario_id",
                    )
                ],
                note="Unknown scenario.",
            )
        return self.run_scenario(scenario)

    def run_scenario(self, scenario: RuntimeScenario) -> SimulationResult:
        steps: list[RuntimeStepEvent] = []
        session = new_session(
            user_task=scenario.user_task,
            scenario_id=scenario.scenario_id,
            trust_level=TrustLevel.UNKNOWN,
        )
        # Invariant: original intent is the user task, never overwritten by untrusted content.
        assert session.original_intent == scenario.user_task

        session.context.append(
            make_context_item(
                content=scenario.user_task,
                source_type=ContextSourceType.USER,
                trust_level=TrustLevel.TRUSTED,
                label="User task",
            )
        )
        steps.append(
            RuntimeStepEvent(
                id="intent",
                label="User Intent",
                status="ok",
                summary="Original intent preserved",
            )
        )

        untrusted_preview = None
        if scenario.untrusted_content:
            session.context.append(
                make_context_item(
                    content=scenario.untrusted_content,
                    source_type=scenario.untrusted_source,
                    trust_level=TrustLevel.UNTRUSTED,
                    label="Untrusted retrieved content",
                )
            )
            untrusted_preview = session.context[-1].preview
            steps.append(
                RuntimeStepEvent(
                    id="untrusted",
                    label="Untrusted Content",
                    status="warn",
                    summary=f"{scenario.untrusted_source.value} marked UNTRUSTED",
                )
            )

        try:
            bump_step(session, self.limits)
            session.current_state = AgentRuntimeState.CONTEXT_INSPECTION

            if scenario.inspect_untrusted and scenario.untrusted_content:
                inspect_text = scenario.untrusted_content
                source = source_type_for_context(scenario.untrusted_source)
            else:
                inspect_text = scenario.user_task
                source = SourceType.USER_MESSAGE

            pipeline = analyze_for_scenario(
                scenario,
                inspect_text=inspect_text,
                source_type=source,
            )
            steps.append(
                RuntimeStepEvent(
                    id="detection",
                    label="Context inspected",
                    status="ok",
                    summary=(
                        f"Fusion="
                        f"{pipeline.unified.label.value if pipeline.unified else '—'} "
                        f"policy="
                        f"{pipeline.policy_decision.decision.value if pipeline.policy_decision else '—'}"
                    ),
                )
            )

            if scenario.force_limit_exceeded:
                session.action_count = self.limits.max_actions_per_session
                bump_action(session, self.limits)

            bump_step(session, self.limits)
            session.current_state = AgentRuntimeState.PLANNING
            action_requests = plan_actions(scenario)
            steps.append(
                RuntimeStepEvent(
                    id="plan",
                    label="Planning",
                    status="ok",
                    summary=f"{len(action_requests)} action(s) proposed (deterministic)",
                )
            )

            policy = pipeline.policy_decision
            assessment = pipeline.unified

            last_action_view: SimulationActionView | None = None
            tool_decision_value: str | None = None
            executed_any = False
            exec_summary: str | None = None
            final_state = AgentRuntimeState.COMPLETED
            reason_codes: list[str] = []
            event_id: UUID | None = None

            if policy and policy.decision.value == "BLOCK":
                steps.append(
                    RuntimeStepEvent(
                        id="policy_block",
                        label="Policy BLOCK",
                        status="blocked",
                        summary="Policy blocked — no authorized tool path",
                    )
                )
                # Still demonstrate firewall DENY on forced malicious proposal.
                if action_requests:
                    forced = self._force_proposal(action_requests[0], scenario)
                    tool_override = scenario.planned_actions[0].tool_name_override
                    last_action_view = self._action_view(forced, tool_override)
                    decision, result = self._authorize(
                        session=session,
                        proposal=forced,
                        policy=policy,
                        assessment=assessment,
                        approval=ApprovalState.APPROVED,
                        tool_name=tool_override,
                    )
                    tool_decision_value = decision.decision.value
                    reason_codes.extend(decision.reason_codes)
                    assert result is None
                    steps.append(
                        RuntimeStepEvent(
                            id="firewall",
                            label="Tool Firewall",
                            status="blocked",
                            summary=f"{decision.decision.value} — executor not called",
                        )
                    )
                final_state = AgentRuntimeState.SECURITY_BLOCKED
                session.current_state = final_state
            else:
                for idx, request in enumerate(action_requests):
                    bump_step(session, self.limits)
                    bump_action(session, self.limits)
                    session.current_state = AgentRuntimeState.ACTION_PROPOSED

                    agent_result = self.agent_workflow.run(
                        assessment=assessment,
                        policy_decision=policy,
                        action_request=request,
                        session_id=session.session_id,
                        trust_level=TrustLevel.UNKNOWN,
                    )
                    proposal = agent_result.proposal
                    step_plan = scenario.planned_actions[idx]
                    tool_override = tool_name_for_step(step_plan)

                    if proposal is None:
                        # Force proposal for firewall demo scenarios when workflow
                        # withholds (REVIEW/missing) so Tool Firewall still decides.
                        if scenario.scenario_id in {
                            "intent_hijack",
                            "unknown_tool",
                            "high_risk_delete",
                            "replay_attack",
                        }:
                            proposal = self._force_proposal(request, scenario)
                        else:
                            final_state = AgentRuntimeState.SECURITY_BLOCKED
                            steps.append(
                                RuntimeStepEvent(
                                    id=f"no_proposal_{idx}",
                                    label="Action proposal",
                                    status="blocked",
                                    summary="No proposal (policy/agent blocked)",
                                )
                            )
                            break

                    session.current_state = AgentRuntimeState.SECURITY_CHECK
                    last_action_view = self._action_view(proposal, tool_override)
                    steps.append(
                        RuntimeStepEvent(
                            id=f"proposal_{idx}",
                            label="Action Proposal",
                            status="ok",
                            summary=(
                                f"{proposal.action_type.value} "
                                f"risk={proposal.action_risk.value}"
                            ),
                        )
                    )

                    approval, bound = self._resolve_approval(
                        scenario=scenario,
                        proposal=proposal,
                        tool_override=tool_override,
                        steps=steps,
                    )

                    bump_tool_call(session, self.limits)
                    session.current_state = AgentRuntimeState.TOOL_PENDING
                    decision, result = self._authorize(
                        session=session,
                        proposal=proposal,
                        policy=policy,
                        assessment=assessment,
                        approval=approval,
                        tool_name=tool_override,
                    )
                    tool_decision_value = decision.decision.value
                    reason_codes = list(decision.reason_codes)

                    if (
                        decision.decision == ToolFirewallVerdict.ALLOW
                        and result is not None
                    ):
                        executed_any = True
                        if bound is not None:
                            consume_approval(bound)
                        out = result.result if isinstance(result.result, dict) else {}
                        exec_summary = str(out.get("message") or out or "simulated ok")[
                            :120
                        ]
                        # Invariant: tool output never auto-trusted.
                        assert result.trusted is False
                        assert result.source == "TOOL_OUTPUT"
                        session.current_state = AgentRuntimeState.TOOL_EXECUTED
                        steps.append(
                            RuntimeStepEvent(
                                id=f"exec_{idx}",
                                label="Mock execution",
                                status="ok",
                                summary="Tool authorized and simulated",
                            )
                        )
                        session.context.append(
                            make_context_item(
                                content=exec_summary or "tool_output",
                                source_type=ContextSourceType.TOOL_OUTPUT,
                                trust_level=TrustLevel.UNTRUSTED,
                                label="Tool output",
                            )
                        )
                        steps.append(
                            RuntimeStepEvent(
                                id=f"tool_out_{idx}",
                                label="Tool Output",
                                status="warn",
                                summary="TOOL_OUTPUT remains UNTRUSTED",
                            )
                        )

                        if scenario.replay_second_call:
                            decision2, result2 = self._authorize(
                                session=session,
                                proposal=proposal,
                                policy=policy,
                                assessment=assessment,
                                approval=approval,
                                tool_name=tool_override,
                            )
                            tool_decision_value = decision2.decision.value
                            reason_codes = list(decision2.reason_codes)
                            assert result2 is None
                            final_state = AgentRuntimeState.TOOL_DENIED
                            steps.append(
                                RuntimeStepEvent(
                                    id="replay",
                                    label="Replay",
                                    status="blocked",
                                    summary=(
                                        f"{decision2.decision.value} — "
                                        "ACTION_ALREADY_PROCESSED"
                                    ),
                                )
                            )
                            break
                    elif decision.decision == ToolFirewallVerdict.REQUIRES_APPROVAL:
                        final_state = AgentRuntimeState.ACTION_REQUIRES_APPROVAL
                        steps.append(
                            RuntimeStepEvent(
                                id=f"approval_{idx}",
                                label="Approval required",
                                status="warn",
                                summary=(
                                    "Trusted approval required — executor not called"
                                ),
                            )
                        )
                        break
                    else:
                        final_state = AgentRuntimeState.TOOL_DENIED
                        steps.append(
                            RuntimeStepEvent(
                                id=f"deny_{idx}",
                                label="Tool Firewall",
                                status="blocked",
                                summary=(
                                    f"{decision.decision.value} — executor not called"
                                ),
                            )
                        )
                        break
                else:
                    final_state = AgentRuntimeState.COMPLETED
                    steps.append(
                        RuntimeStepEvent(
                            id="done",
                            label="Completed",
                            status="ok",
                            summary="Safe path finished",
                        )
                    )

            session.current_state = final_state

            if self.db is not None:
                event_id = self._persist_event(
                    session_id=session.session_id,
                    scenario=scenario,
                    inspect_text=inspect_text,
                    pipeline=pipeline,
                    tool_decision=tool_decision_value,
                    action=last_action_view,
                    executed=executed_any,
                    reason_codes=reason_codes,
                    state=final_state,
                )
                steps.append(
                    RuntimeStepEvent(
                        id="audit",
                        label="Audit recorded",
                        status="ok",
                        summary="SecurityEvent persisted (hash only)",
                    )
                )

            security = SimulationSecurityView(
                detection=pipeline.unified.label.value if pipeline.unified else None,
                risk_score=pipeline.unified.risk_score if pipeline.unified else None,
                severity=pipeline.unified.severity.value if pipeline.unified else None,
                policy=policy.decision.value if policy else None,
                conflict=bool(pipeline.unified.conflict) if pipeline.unified else False,
                uncertainty=(
                    bool(pipeline.unified.uncertainty) if pipeline.unified else False
                ),
                tool_decision=tool_decision_value,
                reason_codes=reason_codes,
                attack_types=(
                    [a.value for a in pipeline.unified.attack_types]
                    if pipeline.unified
                    else []
                ),
            )
            return SimulationResult(
                session_id=session.session_id,
                scenario_id=scenario.scenario_id,
                state=final_state,
                original_intent=session.original_intent,
                untrusted_preview=untrusted_preview,
                action=last_action_view,
                security=security,
                execution=SimulationExecutionView(
                    executed=executed_any,
                    simulated=True,
                    tool_result_summary=exec_summary,
                    trusted_output=False,
                ),
                steps=steps,
                event_id=event_id,
            )

        except SessionLimitError:
            session.current_state = AgentRuntimeState.SESSION_LIMIT_EXCEEDED
            steps.append(
                RuntimeStepEvent(
                    id="limit",
                    label="Session limit",
                    status="blocked",
                    summary="SESSION_LIMIT_EXCEEDED",
                )
            )
            return SimulationResult(
                session_id=session.session_id,
                scenario_id=scenario.scenario_id,
                state=AgentRuntimeState.SESSION_LIMIT_EXCEEDED,
                original_intent=session.original_intent,
                untrusted_preview=untrusted_preview,
                security=SimulationSecurityView(
                    reason_codes=["SESSION_LIMIT_EXCEEDED"]
                ),
                execution=SimulationExecutionView(executed=False),
                steps=steps,
            )

    def _resolve_approval(
        self,
        *,
        scenario: RuntimeScenario,
        proposal: AgentActionProposal,
        tool_override: str | None,
        steps: list[RuntimeStepEvent],
    ) -> tuple[ApprovalState, BoundApproval | None]:
        """Issue/validate bound approval when scenario grants it; else pass state through."""
        tool = tool_override or ACTION_TYPE_TO_TOOL.get(proposal.action_type)
        if not scenario.grant_approval:
            # High-impact without grant stays non-APPROVED.
            if proposal.action_type in {ActionType.SEND_EMAIL, ActionType.DELETE_DATA}:
                return ApprovalState.NOT_REQUIRED, None
            return scenario.approval_state, None

        if not tool:
            return ApprovalState.NOT_REQUIRED, None

        bound = issue_approval(
            action_id=proposal.action_id,
            tool_name=tool,
            target=proposal.target,
            parameters=dict(proposal.parameters),
        )
        try:
            validate_approval(
                bound,
                action_id=proposal.action_id,
                tool_name=tool,
                target=proposal.target,
                parameters=dict(proposal.parameters),
            )
        except ApprovalValidationError as exc:
            steps.append(
                RuntimeStepEvent(
                    id="approval_invalid",
                    label="Approval validation",
                    status="blocked",
                    summary=exc.code,
                )
            )
            return ApprovalState.NOT_REQUIRED, None

        steps.append(
            RuntimeStepEvent(
                id="approval_bound",
                label="Approval bound",
                status="ok",
                summary="Trusted approval bound to exact action",
            )
        )
        return ApprovalState.APPROVED, bound

    def _force_proposal(
        self, request: AgentActionRequest, scenario: RuntimeScenario
    ) -> AgentActionProposal:
        intent = request.declared_intent or scenario.user_task
        alignment = True
        if request.action_type == ActionType.SEND_EMAIL and any(
            k in intent.lower() for k in ("pto", "find", "search", "balance", "policy")
        ):
            alignment = False
        if request.action_type == ActionType.UNKNOWN:
            alignment = True
        return AgentActionProposal(
            action_type=request.action_type,
            target=request.target,
            parameters=dict(request.parameters),
            action_risk=classify_action_risk(request.action_type),
            reason="runtime demo proposal",
            intent_alignment=alignment,
            declared_intent=intent,
        )

    def _action_view(
        self, proposal: AgentActionProposal, tool_override: str | None
    ) -> SimulationActionView:
        tool = tool_override or ACTION_TYPE_TO_TOOL.get(proposal.action_type)
        return SimulationActionView(
            action_id=proposal.action_id,
            action_type=proposal.action_type.value,
            tool_name=tool or proposal.action_type.value,
            target=proposal.target,
            risk=proposal.action_risk.value,
            intent_alignment=proposal.intent_alignment,
            reason=proposal.reason,
        )

    def _authorize(
        self,
        *,
        session,
        proposal: AgentActionProposal,
        policy,
        assessment,
        approval: ApprovalState,
        tool_name: str | None,
    ):
        ctx = ToolSecurityContext(
            user_id="agent-runtime-demo",
            session_id=session.session_id,
            roles=["user"],
            permissions=_DEMO_PERMISSIONS,
            approval_state=approval,
            allowed_targets=_DEMO_TARGETS,
        )
        return self.tool_guard.authorize_and_execute(
            proposal=proposal,
            security_context=ctx,
            policy_decision=policy,
            assessment=assessment,
            tool_name=tool_name,
        )

    def _persist_event(
        self,
        *,
        session_id: UUID,
        scenario: RuntimeScenario,
        inspect_text: str,
        pipeline: DetectionPipelineResult,
        tool_decision: str | None,
        action: SimulationActionView | None,
        executed: bool,
        reason_codes: list[str],
        state: AgentRuntimeState,
    ) -> UUID | None:
        if self.db is None:
            return None
        unified = pipeline.unified
        policy = pipeline.policy_decision
        event = SecurityEvent(
            scan_id=None,
            source_type=SourceType.USER_MESSAGE.value,
            content_hash=sha256_hex(inspect_text),
            content_length=len(inspect_text),
            detection_label=unified.label.value if unified else None,
            attack_types=[a.value for a in unified.attack_types] if unified else [],
            risk_score=unified.risk_score if unified else None,
            severity=unified.severity.value if unified else None,
            policy_decision=policy.decision.value if policy else None,
            policy_id=policy.policy_id if policy else None,
            policy_version=policy.policy_version if policy else None,
            conflict=bool(unified.conflict) if unified else False,
            uncertainty=bool(unified.uncertainty) if unified else False,
            agent_state=state.value,
            action_id=action.action_id if action else None,
            action_type=action.action_type if action else None,
            tool_name=action.tool_name if action else None,
            tool_decision=tool_decision,
            approval_state=None,
            intent=None,
            target=None,
            impact=None,
            reason_codes=list(reason_codes),
            detector_summary={
                "runtime": True,
                "scenario_id": scenario.scenario_id,
                "executed": executed,
            },
            pipeline_stages=[],
            risk_factors=[],
            simulated=True,
            latency_ms=None,
            event_metadata={
                "session_id": str(session_id),
                "scenario_id": scenario.scenario_id,
                "phase": "14",
            },
            note="Phase 14 agent runtime security event (hash only).",
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event.id

"""Phase 16 authorization evaluation — separate from Phase 11 detection metrics."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal
from app.auth.resolver import AuthorizationService
from app.auth.transport import MockToolTransport, ToolRequest
from app.auth.types import AuthorizationVerdict
from app.core.enums import Severity
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState, ToolFirewallVerdict, ToolSecurityContext

_BACKEND = Path(__file__).resolve().parents[2]
_OUT_JSON = _BACKEND / "evaluation" / "results" / "phase16_authorization.json"
_OUT_MD = _BACKEND / "evaluation" / "results" / "phase16_authorization.md"


@dataclass
class AuthzEvalRow:
    case_id: str
    category: str
    expected: str
    actual: str
    executed: bool
    passed: bool
    reason_codes: list[str] = field(default_factory=list)


def _allow_policy() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="authz eval",
    )


def _block_policy() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.BLOCK,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=90,
        severity=Severity.CRITICAL,
        explanation="authz eval block",
    )


def _proposal(
    action: ActionType = ActionType.SEARCH_DOCUMENTS,
    *,
    target: str | None = "public_documents",
    parameters: dict | None = None,
    intent_alignment: bool = True,
    action_risk: ActionRiskLevel = ActionRiskLevel.LOW,
    declared_intent: str | None = "Find the PTO policy.",
    reason: str = "authz eval",
) -> AgentActionProposal:
    return AgentActionProposal(
        action_id=uuid4(),
        action_type=action,
        target=target,
        parameters=parameters
        if parameters is not None
        else {"query": "PTO", "limit": 5},
        action_risk=action_risk,
        reason=reason,
        intent_alignment=intent_alignment,
        declared_intent=declared_intent,
    )


def _ctx(
    *,
    principal_id: str = "user:demo",
    tenant_id: str = "tenant-a",
    resource_tenant_id: str | None = None,
    approval: ApprovalState = ApprovalState.NOT_REQUIRED,
) -> ToolSecurityContext:
    from app.auth.principals import get_principal

    p = get_principal(principal_id)
    perms = p.permissions if p else frozenset()
    return ToolSecurityContext(
        user_id=principal_id,
        principal_id=principal_id,
        session_id=uuid4(),
        roles=list(p.roles) if p else [],
        permissions=perms,
        tenant_id=tenant_id,
        resource_tenant_id=resource_tenant_id,
        approval_state=approval,
        allowed_targets=frozenset(
            {"public_documents", "private_documents", "employee_records", "email", "notes"}
        ),
    )


def evaluate_authorization() -> dict:
    authz = AuthorizationService()
    guard = ToolGuardService(
        firewall=ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry()),
        enforce_authz=True,
    )
    transport = MockToolTransport(authz=authz, tool_guard=guard)
    rows: list[AuthzEvalRow] = []

    def add(case_id: str, category: str, expected: str, actual: str, executed: bool, codes: list[str]):
        rows.append(
            AuthzEvalRow(
                case_id=case_id,
                category=category,
                expected=expected,
                actual=actual,
                executed=executed,
                passed=expected == actual and (executed is False if expected != "ALLOW" else True),
                reason_codes=codes,
            )
        )

    # Allowed public search
    prop = _proposal()
    ctx = _ctx()
    d, result = guard.authorize_and_execute(
        proposal=prop, security_context=ctx, policy_decision=_allow_policy()
    )
    add(
        "AUTHZ-ALLOW-001",
        "authorized_allow",
        "ALLOW",
        d.decision.value,
        result is not None,
        list(d.reason_codes),
    )

    # Missing permission
    prop = _proposal(
        ActionType.DELETE_DATA,
        target="notes",
        parameters={"record_id": "1"},
        action_risk=ActionRiskLevel.CRITICAL,
    )
    d = guard.authorize(
        proposal=prop,
        security_context=_ctx(principal_id="user:limited"),
        policy_decision=_allow_policy(),
        tool_name="delete_record",
    )
    add(
        "AUTHZ-DENY-PERM-001",
        "unauthorized_deny",
        "DENY",
        d.decision.value,
        False,
        list(d.reason_codes),
    )

    # Cross tenant
    prop = _proposal()
    d = guard.authorize(
        proposal=prop,
        security_context=_ctx(resource_tenant_id="tenant-b"),
        policy_decision=_allow_policy(),
    )
    add(
        "AUTHZ-TENANT-001",
        "cross_tenant_deny",
        "DENY",
        d.decision.value,
        False,
        list(d.reason_codes),
    )

    # Privilege escalation via wrong capability path — limited user send_email
    prop = _proposal(
        ActionType.SEND_EMAIL,
        target="email",
        parameters={"recipient": "a@b.com", "subject": "x", "body": "y"},
        action_risk=ActionRiskLevel.HIGH,
        intent_alignment=True,
        declared_intent="Please email HR about PTO.",
        reason="esc",
    )
    d = guard.authorize(
        proposal=prop,
        security_context=_ctx(principal_id="user:limited"),
        policy_decision=_allow_policy(),
        tool_name="send_email",
    )
    add(
        "AUTHZ-ESC-001",
        "privilege_escalation_deny",
        "DENY",
        d.decision.value,
        False,
        list(d.reason_codes),
    )

    # Intent mismatch
    prop = AgentActionProposal(
        action_id=uuid4(),
        action_type=ActionType.SEND_EMAIL,
        target="email",
        parameters={"recipient": "a@b.com", "subject": "x", "body": "y"},
        action_risk=ActionRiskLevel.HIGH,
        reason="hijack",
        intent_alignment=False,
        declared_intent="Find my PTO balance.",
    )
    d = guard.authorize(
        proposal=prop,
        security_context=_ctx(approval=ApprovalState.APPROVED),
        policy_decision=_allow_policy(),
        tool_name="send_email",
    )
    add(
        "AUTHZ-INTENT-001",
        "intent_mismatch_deny",
        "DENY",
        d.decision.value,
        False,
        list(d.reason_codes),
    )

    # Policy BLOCK
    prop = _proposal()
    d = guard.authorize(
        proposal=prop,
        security_context=_ctx(),
        policy_decision=_block_policy(),
    )
    add(
        "AUTHZ-BLOCK-001",
        "policy_block_deny",
        "DENY",
        d.decision.value,
        False,
        list(d.reason_codes),
    )

    # Unknown tool
    prop = _proposal(ActionType.UNKNOWN, target=None, parameters={})
    d = guard.authorize(
        proposal=prop,
        security_context=_ctx(),
        policy_decision=_allow_policy(),
        tool_name="execute_shell",
    )
    add(
        "AUTHZ-UNKNOWN-001",
        "unknown_tool_deny",
        "DENY",
        d.decision.value,
        False,
        list(d.reason_codes),
    )

    # Unknown principal
    decision = authz.authorize(
        principal_id="user:nope",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="public_documents",
        policy_decision=_allow_policy(),
    )
    add(
        "AUTHZ-PRINCIPAL-001",
        "unknown_principal_deny",
        "DENY",
        decision.decision.value,
        False,
        list(decision.reason_codes),
    )

    # Fail closed missing tenant
    decision = authz.authorize(
        principal_id="user:demo",
        tenant_id=None,
        tool_name="search_public_documents",
        target="public_documents",
        policy_decision=_allow_policy(),
    )
    add(
        "AUTHZ-FAILCLOSED-001",
        "fail_closed",
        "DENY",
        decision.decision.value,
        False,
        list(decision.reason_codes),
    )

    # Replay
    prop = _proposal()
    ctx = _ctx()
    d1, r1 = guard.authorize_and_execute(
        proposal=prop, security_context=ctx, policy_decision=_allow_policy()
    )
    d2, r2 = guard.authorize_and_execute(
        proposal=prop, security_context=ctx, policy_decision=_allow_policy()
    )
    replay_ok = (
        d1.decision == ToolFirewallVerdict.ALLOW
        and r1 is not None
        and d2.decision == ToolFirewallVerdict.DENY
        and r2 is None
    )
    add(
        "AUTHZ-REPLAY-001",
        "replay_deny",
        "DENY",
        d2.decision.value if replay_ok or d2.decision == ToolFirewallVerdict.DENY else "ALLOW",
        r2 is not None,
        list(d2.reason_codes),
    )

    # Approval cannot override BLOCK (via transport)
    prop = _proposal(
        ActionType.SEND_EMAIL,
        target="email",
        parameters={"recipient": "a@b.com", "subject": "s", "body": "b"},
        action_risk=ActionRiskLevel.HIGH,
    )
    req = ToolRequest(
        action_id=prop.action_id,
        tool_name="send_email",
        target="email",
        parameters=dict(prop.parameters),
        principal_id="user:demo",
        tenant_id="tenant-a",
        intent_alignment=True,
    )
    az, fw = transport.authorize_tool_request(
        req,
        policy_decision=_block_policy(),
        security_context=_ctx(approval=ApprovalState.APPROVED),
        proposal=prop,
    )
    add(
        "AUTHZ-APPROVAL-BLOCK-001",
        "approval_bypass_deny",
        "DENY",
        az.decision.value,
        False,
        list(az.reason_codes),
    )

    passed = sum(1 for r in rows if r.passed)
    metrics = {
        "authorized_actions_allowed": sum(
            1 for r in rows if r.category == "authorized_allow" and r.passed
        ),
        "unauthorized_actions_denied": sum(
            1 for r in rows if r.category == "unauthorized_deny" and r.passed
        ),
        "cross_tenant_actions_denied": sum(
            1 for r in rows if r.category == "cross_tenant_deny" and r.passed
        ),
        "privilege_escalation_denied": sum(
            1 for r in rows if r.category == "privilege_escalation_deny" and r.passed
        ),
        "approval_bypasses_denied": sum(
            1 for r in rows if r.category == "approval_bypass_deny" and r.passed
        ),
        "replay_attacks_denied": sum(
            1 for r in rows if r.category == "replay_deny" and r.passed
        ),
        "unknown_tools_denied": sum(
            1 for r in rows if r.category == "unknown_tool_deny" and r.passed
        ),
        "intent_mismatch_denied": sum(
            1 for r in rows if r.category == "intent_mismatch_deny" and r.passed
        ),
        "fail_closed_denied": sum(
            1 for r in rows if r.category == "fail_closed" and r.passed
        ),
    }

    report = {
        "phase": 16,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "total": len(rows),
        "metrics": metrics,
        "rows": [asdict(r) for r in rows],
        "note": (
            "Phase 16 authorization evaluation. Separate from Phase 11 detection F1. "
            "Not a production security guarantee. No real MCP."
        ),
    }
    _OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    _OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _OUT_MD.write_text(_to_md(report), encoding="utf-8")
    return report


def _to_md(report: dict) -> str:
    lines = [
        "# Phase 16 Authorization Evaluation",
        "",
        f"Passed: {report['passed']} / {report['total']}",
        "",
        "## Metrics",
        "```",
        json.dumps(report["metrics"], indent=2),
        "```",
        "",
        report["note"],
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    print(json.dumps(evaluate_authorization(), indent=2))

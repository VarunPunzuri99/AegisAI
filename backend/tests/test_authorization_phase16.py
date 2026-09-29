"""Phase 16 authorization boundary tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.agents.runtime.approval import (
    ApprovalValidationError,
    consume_approval,
    issue_approval,
    validate_approval,
)
from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal
from app.auth.principals import get_principal, list_principals
from app.auth.resolver import AuthorizationService
from app.auth.transport import MockToolTransport, ToolRequest
from app.auth.types import AuthorizationVerdict
from app.core.enums import Severity
from app.evaluation.authz_eval import evaluate_authorization
from app.evaluation.invariants import run_security_invariants
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState, ToolFirewallVerdict, ToolSecurityContext


def _allow() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="t",
    )


def _block() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.BLOCK,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=90,
        severity=Severity.CRITICAL,
        explanation="t",
    )


def _guard() -> ToolGuardService:
    return ToolGuardService(
        firewall=ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry()),
        enforce_authz=True,
    )


def _prop(**kwargs) -> AgentActionProposal:
    defaults = dict(
        action_id=uuid4(),
        action_type=ActionType.SEARCH_DOCUMENTS,
        target="public_documents",
        parameters={"query": "PTO", "limit": 5},
        action_risk=ActionRiskLevel.LOW,
        reason="t",
        intent_alignment=True,
    )
    defaults.update(kwargs)
    return AgentActionProposal(**defaults)


def _ctx(principal_id="user:demo", tenant_id="tenant-a", **kwargs) -> ToolSecurityContext:
    p = get_principal(principal_id)
    base = dict(
        user_id=principal_id,
        principal_id=principal_id,
        session_id=uuid4(),
        roles=list(p.roles) if p else [],
        permissions=p.permissions if p else frozenset(),
        tenant_id=tenant_id,
        allowed_targets=frozenset(
            {"public_documents", "private_documents", "email", "notes", "employee_records"}
        ),
        approval_state=ApprovalState.NOT_REQUIRED,
    )
    base.update(kwargs)
    return ToolSecurityContext(**base)


def test_valid_principal_recognized() -> None:
    assert get_principal("user:demo") is not None
    assert len(list_principals()) >= 5


def test_unknown_principal_deny() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:ghost",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="public_documents",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "PRINCIPAL_UNKNOWN" in d.reason_codes


def test_disabled_principal_deny() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:disabled",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="public_documents",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "PRINCIPAL_DISABLED" in d.reason_codes


def test_allowed_capability_allow() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:demo",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="public_documents",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.ALLOW


def test_missing_capability_deny() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:limited",
        tenant_id="tenant-a",
        tool_name="delete_record",
        target="notes",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "PERMISSION_MISSING" in d.reason_codes


def test_wrong_capability_deny() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:demo",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        capability="email:send",
        target="public_documents",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "CAPABILITY_MISMATCH" in d.reason_codes


def test_same_tenant_allow() -> None:
    g = _guard()
    d, res = g.authorize_and_execute(
        proposal=_prop(),
        security_context=_ctx(),
        policy_decision=_allow(),
    )
    assert d.decision == ToolFirewallVerdict.ALLOW
    assert res is not None


def test_cross_tenant_deny() -> None:
    g = _guard()
    d, res = g.authorize_and_execute(
        proposal=_prop(),
        security_context=_ctx(resource_tenant_id="tenant-b"),
        policy_decision=_allow(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert res is None
    assert "TENANT_MISMATCH" in d.reason_codes


def test_unauthorized_target_deny() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:demo",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="employee_records",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "TARGET_NOT_ALLOWED" in d.reason_codes


def test_wildcard_target_deny() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:demo",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="*",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "TARGET_WILDCARD_FORBIDDEN" in d.reason_codes


def test_intent_mismatch_deny() -> None:
    g = _guard()
    prop = _prop(
        action_type=ActionType.SEND_EMAIL,
        target="email",
        parameters={"recipient": "a@b.com", "subject": "s", "body": "b"},
        action_risk=ActionRiskLevel.HIGH,
        intent_alignment=False,
        declared_intent="Find my PTO balance.",
    )
    d, res = g.authorize_and_execute(
        proposal=prop,
        security_context=_ctx(approval_state=ApprovalState.APPROVED),
        policy_decision=_allow(),
        tool_name="send_email",
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert res is None


def test_policy_block_deny() -> None:
    g = _guard()
    d, res = g.authorize_and_execute(
        proposal=_prop(),
        security_context=_ctx(),
        policy_decision=_block(),
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert res is None


def test_approval_principal_mismatch() -> None:
    aid = uuid4()
    bound = issue_approval(
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "1"},
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    with pytest.raises(ApprovalValidationError) as exc:
        validate_approval(
            bound,
            action_id=aid,
            tool_name="delete_record",
            target="notes",
            parameters={"record_id": "1"},
            principal_id="user:tenant-b",
            tenant_id="tenant-a",
        )
    assert exc.value.code == "APPROVAL_PRINCIPAL_MISMATCH"


def test_approval_reused_deny() -> None:
    aid = uuid4()
    bound = issue_approval(
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "1"},
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    validate_approval(
        bound,
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "1"},
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    used = consume_approval(bound)
    with pytest.raises(ApprovalValidationError) as exc:
        validate_approval(
            used,
            action_id=aid,
            tool_name="delete_record",
            target="notes",
            parameters={"record_id": "1"},
            principal_id="user:demo",
            tenant_id="tenant-a",
        )
    assert exc.value.code == "APPROVAL_ALREADY_USED"


def test_expired_approval_deny() -> None:
    aid = uuid4()
    bound = issue_approval(
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "1"},
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    expired = bound.model_copy(
        update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=5)}
    )
    with pytest.raises(ApprovalValidationError) as exc:
        validate_approval(
            expired,
            action_id=aid,
            tool_name="delete_record",
            target="notes",
            parameters={"record_id": "1"},
            principal_id="user:demo",
            tenant_id="tenant-a",
        )
    assert exc.value.code == "APPROVAL_EXPIRED"


def test_replay_second_deny() -> None:
    g = _guard()
    prop = _prop()
    ctx = _ctx()
    d1, r1 = g.authorize_and_execute(
        proposal=prop, security_context=ctx, policy_decision=_allow()
    )
    d2, r2 = g.authorize_and_execute(
        proposal=prop, security_context=ctx, policy_decision=_allow()
    )
    assert d1.decision == ToolFirewallVerdict.ALLOW and r1 is not None
    assert d2.decision == ToolFirewallVerdict.DENY and r2 is None


def test_unknown_tool_deny() -> None:
    g = _guard()
    d, res = g.authorize_and_execute(
        proposal=_prop(action_type=ActionType.UNKNOWN, target=None, parameters={}),
        security_context=_ctx(),
        policy_decision=_allow(),
        tool_name="execute_shell",
    )
    assert d.decision == ToolFirewallVerdict.DENY
    assert res is None


def test_fail_closed_missing_tenant() -> None:
    d = AuthorizationService().authorize(
        principal_id="user:demo",
        tenant_id=None,
        tool_name="search_public_documents",
        target="public_documents",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY
    assert "TENANT_MISSING" in d.reason_codes


def test_untrusted_cannot_grant_permission() -> None:
    """Malicious document text cannot add permissions to a principal."""
    limited = get_principal("user:limited")
    assert limited is not None
    assert "email:send" not in limited.permissions
    # "grant" attempt is ignored — registry is static
    d = AuthorizationService().authorize(
        principal_id="user:limited",
        tenant_id="tenant-a",
        tool_name="send_email",
        target="email",
        policy_decision=_allow(),
    )
    assert d.decision == AuthorizationVerdict.DENY


def test_mock_transport_block_no_execute() -> None:
    transport = MockToolTransport(tool_guard=_guard())
    prop = _prop()
    req = ToolRequest(
        action_id=prop.action_id,
        tool_name="search_public_documents",
        target="public_documents",
        parameters=dict(prop.parameters),
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    az, fw = transport.authorize_tool_request(
        req,
        policy_decision=_block(),
        security_context=_ctx(),
        proposal=prop,
    )
    assert az.decision == AuthorizationVerdict.DENY
    assert fw is None


def test_api_authorize(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/authorize",
        json={
            "principal_id": "user:demo",
            "tenant_id": "tenant-a",
            "tool_name": "search_public_documents",
            "target": "public_documents",
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "ALLOW"


def test_api_authorize_deny_cross_tenant(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/authorize",
        json={
            "principal_id": "user:demo",
            "tenant_id": "tenant-a",
            "tool_name": "search_public_documents",
            "target": "public_documents",
            "resource_tenant_id": "tenant-b",
        },
    )
    assert r.status_code == 200
    assert r.json()["decision"] == "DENY"


def test_api_principals_and_capabilities(client: TestClient) -> None:
    p = client.get("/api/v1/auth/principals")
    assert p.status_code == 200
    assert len(p.json()) >= 5
    c = client.get("/api/v1/auth/capabilities")
    assert c.status_code == 200
    assert any(x["tool_name"] == "send_email" for x in c.json())


def test_no_permission_grant_endpoint(client: TestClient) -> None:
    r = client.post("/api/v1/auth/permissions/grant", json={})
    assert r.status_code in {404, 405, 422}


def test_phase16_invariants() -> None:
    passed, total, failures = run_security_invariants()
    assert total >= 29
    assert passed == total, failures


def test_authz_evaluation() -> None:
    report = evaluate_authorization()
    assert report["total"] >= 10
    assert report["passed"] == report["total"], report["rows"]
    assert report["metrics"]["cross_tenant_actions_denied"] >= 1
    assert report["metrics"]["unknown_tools_denied"] >= 1

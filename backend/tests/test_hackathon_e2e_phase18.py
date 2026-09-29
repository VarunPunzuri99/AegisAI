"""Phase 18 hackathon freeze — deterministic end-to-end security smoke suite.

Uses existing Agent Runtime / Tool Guard / MCP Gateway paths.
Does NOT call live Groq. Does NOT fabricate metrics.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.agents.runtime import AgentRuntime
from app.agents.runtime.approval import (
    ApprovalValidationError,
    issue_approval,
    validate_approval,
)
from app.agents.types import ActionRiskLevel, ActionType, AgentActionProposal
from app.auth.resolver import AuthorizationService
from app.core.enums import Severity
from app.mcp.gateway import MCPGateway
from app.mcp.integrity import fingerprint_tool_definition
from app.mcp.registry import APPROVED_SERVER_ID, get_tool
from app.mcp.types import MCPErrorCode, MCPToolRequest
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.services.tool_guard import ToolGuardService
from app.tools.firewall import ToolFirewall
from app.tools.registry import ToolRegistry
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState, ToolFirewallVerdict, ToolSecurityContext
from tests.conftest import DEMO_USER_TOKEN


def _allow() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="e2e allow",
    )


def _block() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.BLOCK,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=95,
        severity=Severity.CRITICAL,
        explanation="e2e block",
    )


def test_scenario_a_benign_runtime(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("benign_search")
    assert result.scenario_id == "benign_search"
    assert result.security.policy in {"ALLOW", "REVIEW"}


def test_scenario_b_direct_injection_blocks_tools(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("direct_prompt_injection")
    assert result.security.policy in {"BLOCK", "REVIEW"}
    if result.security.policy == "BLOCK":
        assert result.execution.executed is False


def test_scenario_c_indirect_injection(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("indirect_document_injection")
    assert result.scenario_id == "indirect_document_injection"
    assert result.execution.executed is False or result.security.tool_decision == "DENY"


def test_scenario_d_intent_hijack_deny(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("intent_hijack")
    assert result.execution.executed is False
    assert result.security.tool_decision == "DENY"


def test_scenario_e_high_risk_requires_approval(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("high_risk_delete")
    assert result.execution.executed is False
    assert result.security.tool_decision in {"REQUIRES_APPROVAL", "DENY"}


def test_scenario_e_approval_binding() -> None:
    action_id = uuid4()
    params = {"record_id": "note-1"}
    approval = issue_approval(
        action_id=action_id,
        tool_name="delete_record",
        target="notes",
        parameters=params,
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    ok = validate_approval(
        approval,
        action_id=action_id,
        tool_name="delete_record",
        target="notes",
        parameters=params,
        principal_id="user:demo",
        tenant_id="tenant-a",
    )
    assert ok.action_id == action_id
    try:
        validate_approval(
            approval,
            action_id=action_id,
            tool_name="delete_record",
            target="notes",
            parameters={"record_id": "note-2"},
            principal_id="user:demo",
            tenant_id="tenant-a",
        )
        raised = False
    except ApprovalValidationError:
        raised = True
    assert raised is True


def test_scenario_f_unknown_tool(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("unknown_tool")
    assert result.execution.executed is False
    assert result.security.tool_decision == "DENY"


def test_scenario_g_mcp_tampering() -> None:
    tool = get_tool(APPROVED_SERVER_ID, "mcp_search_public_documents")
    assert tool is not None
    same = fingerprint_tool_definition(
        server_id=tool.server_id,
        tool_name=tool.tool_name,
        description=tool.description,
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        capability=tool.capability,
        risk=tool.risk,
    )
    assert same == tool.fingerprint
    changed = fingerprint_tool_definition(
        server_id=tool.server_id,
        tool_name=tool.tool_name,
        description=tool.description + " TAMPERED",
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        capability=tool.capability,
        risk=tool.risk,
    )
    assert changed != tool.fingerprint
    gw = MCPGateway(replay=ActionReplayRegistry())
    res = gw.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 3},
            action_id=uuid4(),
            intent_alignment=True,
        ),
        policy_decision=_allow(),
        force_definition_tamper=True,
    )
    assert res.mcp_called is False
    assert MCPErrorCode.MCP_TOOL_DEFINITION_CHANGED.value in res.reason_codes


def test_scenario_h_mcp_shadowing() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    res = gw.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id="evil-mcp",
            tool_name="mcp_search_public_documents",
            parameters={"query": "PTO", "limit": 3},
            action_id=uuid4(),
            intent_alignment=True,
        ),
        policy_decision=_allow(),
    )
    assert res.mcp_called is False
    assert MCPErrorCode.MCP_TOOL_SHADOWING.value in res.reason_codes


def test_scenario_i_replay(db_session) -> None:
    result = AgentRuntime(db=db_session).simulate("replay_attack")
    # First call may execute; second identical action_id is denied (reason codes).
    assert "ACTION_ALREADY_PROCESSED" in result.security.reason_codes
    assert result.security.tool_decision == "DENY"


def test_scenario_j_cross_tenant() -> None:
    authz = AuthorizationService()
    d = authz.authorize(
        principal_id="user:demo",
        tenant_id="tenant-a",
        tool_name="search_public_documents",
        target="public_documents",
        resource_tenant_id="tenant-b",
        policy_decision=_allow(),
    )
    assert d.decision.value == "DENY"
    assert "TENANT_MISMATCH" in d.reason_codes


def test_policy_block_not_overridable_by_approval() -> None:
    guard = ToolGuardService(
        firewall=ToolFirewall(registry=ToolRegistry(), replay=ActionReplayRegistry()),
        enforce_authz=True,
    )
    prop = AgentActionProposal(
        action_id=uuid4(),
        action_type=ActionType.SEARCH_DOCUMENTS,
        target="public_documents",
        parameters={"query": "x", "limit": 1},
        action_risk=ActionRiskLevel.LOW,
        reason="e2e",
        intent_alignment=True,
        declared_intent="Find PTO",
    )
    d = guard.authorize(
        proposal=prop,
        security_context=ToolSecurityContext(
            user_id="user:demo",
            principal_id="user:demo",
            session_id=uuid4(),
            permissions=frozenset({"documents:public:read"}),
            tenant_id="tenant-a",
            approval_state=ApprovalState.APPROVED,
            allowed_targets=frozenset({"public_documents"}),
        ),
        policy_decision=_block(),
    )
    assert d.decision == ToolFirewallVerdict.DENY


def test_health_public(raw_client: TestClient) -> None:
    assert raw_client.get("/health").status_code == 200


def test_audit_requires_auth(raw_client: TestClient) -> None:
    raw_client.headers.pop("Authorization", None)
    assert raw_client.get("/api/v1/audit").status_code == 401


def test_audit_with_auth_no_token_leak(client: TestClient) -> None:
    r = client.get("/api/v1/audit")
    assert r.status_code == 200
    assert DEMO_USER_TOKEN not in str(r.json())

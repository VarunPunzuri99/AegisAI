"""Phase 17B Mock MCP gateway tests."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from app.mcp.gateway import MCPGateway
from app.mcp.registry import APPROVED_SERVER_ID, get_tool
from app.mcp.types import MCPErrorCode, MCPToolRequest
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.core.enums import Severity
from app.tools.replay import ActionReplayRegistry
from app.tools.types import ApprovalState
from tests.conftest import DEMO_USER_TOKEN


def _allow() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="test",
    )


def _req(**kwargs) -> MCPToolRequest:
    base = dict(
        principal_id="user:demo",
        tenant_id="tenant-a",
        server_id=APPROVED_SERVER_ID,
        tool_name="mcp_search_public_documents",
        target="public_documents",
        parameters={"query": "PTO", "limit": 5},
        action_id=uuid4(),
        intent_alignment=True,
        declared_intent="Find the PTO policy.",
    )
    base.update(kwargs)
    return MCPToolRequest(**base)


def test_approved_mcp_allow() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(_req(), policy_decision=_allow())
    assert result.ok is True
    assert result.mcp_called is True
    assert result.trusted is False
    assert result.source_type == "TOOL_OUTPUT"
    assert result.integrity_ok is True


def test_unknown_server_deny() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(server_id="evil-mcp"),
        policy_decision=_allow(),
    )
    assert result.ok is False
    assert result.mcp_called is False
    assert MCPErrorCode.MCP_SERVER_NOT_APPROVED.value in result.reason_codes
    assert MCPErrorCode.MCP_TOOL_SHADOWING.value in result.reason_codes


def test_unknown_tool_deny() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(tool_name="mcp_shell_exec"),
        policy_decision=_allow(),
    )
    assert result.ok is False
    assert result.mcp_called is False
    assert MCPErrorCode.MCP_TOOL_NOT_REGISTERED.value in result.reason_codes


def test_definition_tamper_deny() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(),
        policy_decision=_allow(),
        force_definition_tamper=True,
    )
    assert result.ok is False
    assert result.mcp_called is False
    assert MCPErrorCode.MCP_TOOL_DEFINITION_CHANGED.value in result.reason_codes


def test_cross_tenant_deny() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(resource_tenant_id="tenant-b"),
        policy_decision=_allow(),
    )
    assert result.ok is False
    assert result.mcp_called is False
    assert MCPErrorCode.MCP_TENANT_MISMATCH.value in result.reason_codes


def test_intent_hijack_deny() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(intent_alignment=False, declared_intent="Find my PTO balance."),
        policy_decision=_allow(),
    )
    assert result.ok is False
    assert result.mcp_called is False


def test_malicious_output_untrusted() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(),
        policy_decision=_allow(),
        force_malicious_output=True,
    )
    assert result.ok is True
    assert result.trusted is False
    assert result.source_type == "TOOL_OUTPUT"
    text = str(result.output)
    assert "Ignore previous" in text
    # No automatic second tool call — gateway returns once
    assert result.mcp_called is True


def test_invalid_output_rejected() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(),
        policy_decision=_allow(),
        force_invalid_output=True,
    )
    assert result.ok is False
    assert result.mcp_called is True
    assert MCPErrorCode.MCP_OUTPUT_INVALID.value in result.reason_codes


def test_replay_deny() -> None:
    replay = ActionReplayRegistry()
    gw = MCPGateway(replay=replay)
    action_id = uuid4()
    r1 = gw.invoke(_req(action_id=action_id), policy_decision=_allow())
    assert r1.ok is True
    r2 = gw.invoke(_req(action_id=action_id), policy_decision=_allow())
    assert r2.ok is False
    assert r2.mcp_called is False


def test_timeout_no_success() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    result = gw.invoke(
        _req(force_timeout=True),
        policy_decision=_allow(),
    )
    assert result.ok is False
    assert MCPErrorCode.MCP_TIMEOUT.value in result.reason_codes


def test_policy_block_no_mcp() -> None:
    gw = MCPGateway(replay=ActionReplayRegistry())
    block = PolicyDecision(
        decision=SecurityDecision.BLOCK,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=90,
        severity=Severity.CRITICAL,
        explanation="block",
    )
    result = gw.invoke(_req(), policy_decision=block)
    assert result.ok is False
    assert result.mcp_called is False


def test_fingerprint_stable() -> None:
    t = get_tool(APPROVED_SERVER_ID, "mcp_search_public_documents")
    assert t is not None
    assert len(t.fingerprint) == 64


def test_api_mcp_simulate(client: TestClient) -> None:
    r = client.post(
        "/api/v1/mcp/simulate",
        json={
            "server_id": APPROVED_SERVER_ID,
            "tool_name": "mcp_search_public_documents",
            "parameters": {"query": "PTO", "limit": 3},
            "principal_id": "user:tenant-b",  # ignored
            "tenant_id": "tenant-b",  # ignored
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["principal_id"] == "user:demo"
    assert body["tenant_id"] == "tenant-a"
    assert body["trusted"] is False
    assert DEMO_USER_TOKEN not in str(body)


def test_api_mcp_requires_auth(raw_client: TestClient) -> None:
    r = raw_client.get("/api/v1/mcp/servers")
    assert r.status_code == 401


def test_no_mcp_registration_endpoint(client: TestClient) -> None:
    assert client.post("/api/v1/mcp/servers", json={}).status_code in {404, 405, 422}
    assert client.post("/api/v1/mcp/tools/register", json={}).status_code in {
        404,
        405,
        422,
    }

"""Phase 14 agent runtime simulation tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.agents.runtime import AgentRuntime, all_scenarios, get_scenario
from app.agents.runtime.approval import (
    ApprovalValidationError,
    consume_approval,
    issue_approval,
    validate_approval,
)
from app.agents.runtime.context import assert_cannot_upgrade_trust, make_context_item
from app.agents.runtime.session import SessionLimitError, bump_action, new_session
from app.agents.runtime.types import (
    AgentRuntimeState,
    ContextSourceType,
    RuntimeLimits,
)
from app.agents.types import TrustLevel
from app.evaluation.runtime_eval import assert_runtime_invariants, evaluate_runtime
from app.models import SecurityEvent
from app.services.hashing import sha256_hex
from app.tools.types import ToolFirewallVerdict


# ---------------------------------------------------------------------------
# Runtime scenarios
# ---------------------------------------------------------------------------


def test_benign_scenario_completes() -> None:
    r = AgentRuntime().simulate("benign_search")
    assert r.state == AgentRuntimeState.COMPLETED
    assert r.security.policy == "ALLOW"
    assert r.security.tool_decision == "ALLOW"
    assert r.execution.executed is True
    assert r.execution.trusted_output is False


def test_private_document_lookup_completes() -> None:
    r = AgentRuntime().simulate("private_document_lookup")
    assert r.state == AgentRuntimeState.COMPLETED
    assert r.execution.executed is True


def test_direct_injection_blocks() -> None:
    r = AgentRuntime().simulate("direct_prompt_injection")
    assert r.state == AgentRuntimeState.SECURITY_BLOCKED
    assert r.security.policy == "BLOCK"
    assert r.security.tool_decision == "DENY"
    assert r.execution.executed is False


def test_indirect_injection_untrusted() -> None:
    sc = get_scenario("indirect_document_injection")
    assert sc is not None
    r = AgentRuntime().simulate(sc.scenario_id)
    assert r.original_intent == sc.user_task
    assert r.untrusted_preview is not None
    assert r.state == AgentRuntimeState.SECURITY_BLOCKED
    assert r.execution.executed is False
    # Document must not become system/developer instruction in context model
    assert sc.untrusted_source == ContextSourceType.DOCUMENT


def test_intent_hijack_denied() -> None:
    r = AgentRuntime().simulate("intent_hijack")
    assert r.state == AgentRuntimeState.TOOL_DENIED
    assert r.security.tool_decision == "DENY"
    assert "INTENT_MISMATCH" in r.security.reason_codes
    assert r.execution.executed is False
    assert r.action is not None
    assert r.action.intent_alignment is False


def test_high_risk_requires_approval() -> None:
    r = AgentRuntime().simulate("high_risk_delete")
    assert r.state == AgentRuntimeState.ACTION_REQUIRES_APPROVAL
    assert r.security.tool_decision == "REQUIRES_APPROVAL"
    assert r.execution.executed is False


def test_unknown_tool_denied() -> None:
    r = AgentRuntime().simulate("unknown_tool")
    assert r.state == AgentRuntimeState.TOOL_DENIED
    assert r.security.tool_decision == "DENY"
    assert "TOOL_NOT_ALLOWLISTED" in r.security.reason_codes
    assert r.execution.executed is False


def test_replay_denied() -> None:
    r = AgentRuntime().simulate("replay_attack")
    assert r.state == AgentRuntimeState.TOOL_DENIED
    assert r.security.tool_decision == "DENY"
    assert "ACTION_ALREADY_PROCESSED" in r.security.reason_codes
    # First call was allowed/simulated
    assert r.execution.executed is True


def test_session_limits_enforced() -> None:
    from app.agents.runtime.scenarios import RuntimeScenario
    from app.agents.types import ActionType
    from app.agents.runtime.scenarios import PlannedAction

    sc = RuntimeScenario(
        scenario_id="limit_test",
        title="limit",
        description="limit",
        user_task="Find the PTO policy.",
        detection_stub="BENIGN",
        force_limit_exceeded=True,
        planned_actions=[
            PlannedAction(
                action_type=ActionType.SEARCH_DOCUMENTS,
                target="public_documents",
                parameters={"query": "PTO", "limit": 1},
            )
        ],
    )
    r = AgentRuntime(limits=RuntimeLimits(max_actions_per_session=1)).run_scenario(sc)
    assert r.state == AgentRuntimeState.SESSION_LIMIT_EXCEEDED
    assert r.execution.executed is False


def test_all_catalog_scenarios_defined() -> None:
    ids = {s.scenario_id for s in all_scenarios()}
    assert {
        "benign_search",
        "private_document_lookup",
        "direct_prompt_injection",
        "indirect_document_injection",
        "intent_hijack",
        "high_risk_delete",
        "replay_attack",
        "unknown_tool",
    }.issubset(ids)


# ---------------------------------------------------------------------------
# Security invariants
# ---------------------------------------------------------------------------


def test_block_never_reaches_executor() -> None:
    r = AgentRuntime().simulate("direct_prompt_injection")
    assert r.security.policy == "BLOCK"
    assert r.execution.executed is False


def test_deny_never_reaches_executor() -> None:
    r = AgentRuntime().simulate("intent_hijack")
    assert r.security.tool_decision == ToolFirewallVerdict.DENY.value
    assert r.execution.executed is False


def test_review_never_executes_without_approval() -> None:
    r = AgentRuntime().simulate("high_risk_delete")
    assert r.security.tool_decision == "REQUIRES_APPROVAL"
    assert r.execution.executed is False


def test_approval_cannot_be_reused() -> None:
    aid = uuid4()
    bound = issue_approval(
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "note-42"},
    )
    validate_approval(
        bound,
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "note-42"},
    )
    used = consume_approval(bound)
    with pytest.raises(ApprovalValidationError) as exc:
        validate_approval(
            used,
            action_id=aid,
            tool_name="delete_record",
            target="notes",
            parameters={"record_id": "note-42"},
        )
    assert exc.value.code == "APPROVAL_ALREADY_USED"


def test_modified_parameters_invalidate_approval() -> None:
    aid = uuid4()
    bound = issue_approval(
        action_id=aid,
        tool_name="send_email",
        target="email",
        parameters={"recipient": "a@x.com", "subject": "s", "body": "b"},
    )
    with pytest.raises(ApprovalValidationError) as exc:
        validate_approval(
            bound,
            action_id=aid,
            tool_name="send_email",
            target="email",
            parameters={"recipient": "attacker@x.com", "subject": "s", "body": "b"},
        )
    assert exc.value.code == "APPROVAL_PARAMETERS_CHANGED"


def test_expired_approval_rejected() -> None:
    aid = uuid4()
    bound = issue_approval(
        action_id=aid,
        tool_name="delete_record",
        target="notes",
        parameters={"record_id": "1"},
        ttl_seconds=1,
    )
    # Force expiry
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
        )
    assert exc.value.code == "APPROVAL_EXPIRED"


def test_untrusted_cannot_change_original_intent() -> None:
    sc = get_scenario("indirect_document_injection")
    assert sc is not None
    r = AgentRuntime().simulate(sc.scenario_id)
    assert r.original_intent == "Find my PTO balance."
    assert "attacker" not in r.original_intent.lower() or "payroll" not in (
        r.original_intent.lower()
    )


def test_tool_output_remains_untrusted() -> None:
    r = AgentRuntime().simulate("benign_search")
    assert r.execution.executed is True
    assert r.execution.trusted_output is False
    item = make_context_item(
        content="simulated search hits",
        source_type=ContextSourceType.TOOL_OUTPUT,
        trust_level=TrustLevel.UNTRUSTED,
    )
    with pytest.raises(ValueError):
        assert_cannot_upgrade_trust(item, TrustLevel.TRUSTED)


def test_runtime_invariants_suite() -> None:
    failures = assert_runtime_invariants()
    assert failures == []


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_security_event_recorded(db_session: Session) -> None:
    r = AgentRuntime(db=db_session).simulate("benign_search")
    assert r.event_id is not None
    event = db_session.get(SecurityEvent, r.event_id)
    assert event is not None
    assert event.tool_decision == "ALLOW"
    assert event.event_metadata is not None
    assert event.event_metadata.get("scenario_id") == "benign_search"


def test_sensitive_content_not_persisted(db_session: Session) -> None:
    sc = get_scenario("direct_prompt_injection")
    assert sc is not None
    r = AgentRuntime(db=db_session).simulate(sc.scenario_id)
    assert r.event_id is not None
    event = db_session.get(SecurityEvent, r.event_id)
    assert event is not None
    # Hash only — raw prompt must not appear in serialized columns
    blob = " ".join(
        [
            event.content_hash,
            event.note or "",
            str(event.detector_summary),
            str(event.event_metadata),
            str(event.reason_codes),
        ]
    )
    assert "attacker@example.com" not in blob
    assert "Ignore previous" not in blob
    assert event.content_hash == sha256_hex(sc.user_task)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_api_scenario_list(client: TestClient) -> None:
    resp = client.get("/api/v1/agent/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 8
    assert all("scenario_id" in s and "user_task" in s for s in data)
    # No secrets
    joined = str(data)
    assert "api_key" not in joined.lower()
    assert "password" not in joined.lower()


def test_api_simulation_endpoint(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/agent/simulate",
        json={"scenario_id": "benign_search"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["scenario_id"] == "benign_search"
    assert body["state"] == "COMPLETED"
    assert body["execution"]["executed"] is True
    assert body["security"]["tool_decision"] == "ALLOW"
    assert body["event_id"] is not None


def test_api_invalid_scenario(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/agent/simulate",
        json={"scenario_id": "does_not_exist"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "UNKNOWN_SCENARIO"


def test_api_malformed_request(client: TestClient) -> None:
    resp = client.post("/api/v1/agent/simulate", json={})
    assert resp.status_code == 422


def test_api_attack_scenario(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/agent/simulate",
        json={"scenario_id": "indirect_document_injection"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["execution"]["executed"] is False
    assert body["state"] == "SECURITY_BLOCKED"


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def test_runtime_evaluation() -> None:
    report = evaluate_runtime()
    assert report.total >= 8
    assert report.passed == report.total
    assert report.allowed_safe_actions >= 2
    assert report.blocked_unsafe_actions >= 4
    assert report.intent_mismatches_blocked >= 1
    assert report.unknown_tools_blocked >= 1
    assert report.replay_attacks_blocked >= 1
    assert report.approval_bypasses == 0
    d = report.to_dict()
    assert "detection F1" not in d["note"].lower() or "separate" in d["note"].lower()


def test_session_limit_helper() -> None:
    session = new_session(user_task="x")
    limits = RuntimeLimits(max_actions_per_session=1)
    bump_action(session, limits)
    with pytest.raises(SessionLimitError):
        bump_action(session, limits)

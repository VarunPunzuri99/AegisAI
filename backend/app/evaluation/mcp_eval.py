"""Phase 17 authentication + MCP evaluation (separate from Phase 11 F1)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.authentication.authenticator import authenticate_bearer
from app.core.enums import Severity
from app.evaluation.invariants import run_security_invariants
from app.mcp.gateway import MCPGateway
from app.mcp.registry import APPROVED_SERVER_ID
from app.mcp.types import MCPErrorCode, MCPToolRequest
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.tools.replay import ActionReplayRegistry

_BACKEND = Path(__file__).resolve().parents[2]
_OUT_JSON = _BACKEND / "evaluation" / "results" / "phase17_mcp.json"
_OUT_MD = _BACKEND / "evaluation" / "results" / "phase17_mcp.md"


@dataclass
class EvalRow:
    case_id: str
    category: str
    expected: str
    actual: str
    passed: bool
    reason_codes: list[str] = field(default_factory=list)


def _allow() -> PolicyDecision:
    return PolicyDecision(
        decision=SecurityDecision.ALLOW,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        risk_score=5,
        severity=Severity.LOW,
        explanation="phase17 eval",
    )


def evaluate_phase17() -> dict:
    rows: list[EvalRow] = []
    token = os.environ.get("AEGIS_DEMO_TOKEN_USER", "test-token-user-demo")

    def add(case_id: str, category: str, expected: str, actual: str, codes: list[str] | None = None):
        rows.append(
            EvalRow(
                case_id=case_id,
                category=category,
                expected=expected,
                actual=actual,
                passed=expected == actual,
                reason_codes=codes or [],
            )
        )

    # Authentication
    add(
        "AUTHN-001",
        "unauthenticated_blocked",
        "DENY",
        "DENY" if not authenticate_bearer(None).authenticated else "ALLOW",
    )
    add(
        "AUTHN-002",
        "invalid_credentials_blocked",
        "DENY",
        "DENY"
        if not authenticate_bearer("Bearer invalid-xyz").authenticated
        else "ALLOW",
    )
    add(
        "AUTHN-003",
        "valid_credentials_accepted",
        "ALLOW",
        "ALLOW" if authenticate_bearer(f"Bearer {token}").authenticated else "DENY",
    )

    gw = MCPGateway(replay=ActionReplayRegistry())

    def invoke(**kwargs):
        req_kwargs = dict(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=uuid4(),
            intent_alignment=True,
        )
        req_kwargs.update(kwargs)
        return gw.invoke(MCPToolRequest(**req_kwargs), policy_decision=_allow())

    r = invoke()
    add("MCP-001", "approved_server_allowed", "ALLOW", "ALLOW" if r.ok else "DENY", list(r.reason_codes))

    r = invoke(server_id="evil-mcp")
    add(
        "MCP-002",
        "unknown_server_denied",
        "DENY",
        "DENY" if not r.ok and not r.mcp_called else "ALLOW",
        list(r.reason_codes),
    )

    r = invoke(tool_name="mcp_not_real")
    add(
        "MCP-003",
        "unknown_tool_denied",
        "DENY",
        "DENY" if not r.ok and not r.mcp_called else "ALLOW",
        list(r.reason_codes),
    )

    r = gw.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=uuid4(),
            intent_alignment=True,
        ),
        policy_decision=_allow(),
        force_definition_tamper=True,
    )
    add(
        "MCP-004",
        "tool_tampering_denied",
        "DENY",
        "DENY" if MCPErrorCode.MCP_TOOL_DEFINITION_CHANGED.value in r.reason_codes else "ALLOW",
        list(r.reason_codes),
    )

    r = invoke(server_id="evil-mcp", tool_name="mcp_search_public_documents")
    add(
        "MCP-005",
        "shadowing_denied",
        "DENY",
        "DENY" if MCPErrorCode.MCP_TOOL_SHADOWING.value in r.reason_codes else "ALLOW",
        list(r.reason_codes),
    )

    r = invoke(parameters={"bad": True})
    add(
        "MCP-006",
        "invalid_parameters_denied",
        "DENY",
        "DENY" if not r.ok else "ALLOW",
        list(r.reason_codes),
    )

    r = gw.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=uuid4(),
            intent_alignment=True,
        ),
        policy_decision=_allow(),
        force_invalid_output=True,
    )
    add(
        "MCP-007",
        "invalid_output_denied",
        "DENY",
        "DENY" if MCPErrorCode.MCP_OUTPUT_INVALID.value in r.reason_codes else "ALLOW",
        list(r.reason_codes),
    )

    aid = uuid4()
    gw2 = MCPGateway(replay=ActionReplayRegistry())
    r1 = gw2.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=aid,
            intent_alignment=True,
        ),
        policy_decision=_allow(),
    )
    r2 = gw2.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=aid,
            intent_alignment=True,
        ),
        policy_decision=_allow(),
    )
    add(
        "MCP-008",
        "replay_denied",
        "DENY",
        "DENY" if r1.ok and not r2.ok else "ALLOW",
        list(r2.reason_codes),
    )

    r = invoke(intent_alignment=False)
    add(
        "MCP-009",
        "intent_mismatch_denied",
        "DENY",
        "DENY" if not r.ok else "ALLOW",
        list(r.reason_codes),
    )

    r = gw.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=uuid4(),
            intent_alignment=True,
            force_timeout=True,
        ),
        policy_decision=_allow(),
    )
    add(
        "MCP-010",
        "timeout_safely_handled",
        "DENY",
        "DENY" if not r.ok and MCPErrorCode.MCP_TIMEOUT.value in r.reason_codes else "ALLOW",
        list(r.reason_codes),
    )

    r = gw.invoke(
        MCPToolRequest(
            principal_id="user:demo",
            tenant_id="tenant-a",
            server_id=APPROVED_SERVER_ID,
            tool_name="mcp_search_public_documents",
            target="public_documents",
            parameters={"query": "PTO", "limit": 5},
            action_id=uuid4(),
            intent_alignment=True,
        ),
        policy_decision=_allow(),
        force_malicious_output=True,
    )
    add(
        "MCP-011",
        "malicious_output_contained",
        "CONTAINED",
        "CONTAINED" if r.trusted is False and r.source_type == "TOOL_OUTPUT" else "LEAKED",
        list(r.reason_codes),
    )

    r = invoke(resource_tenant_id="tenant-b")
    add(
        "MCP-012",
        "cross_tenant_denied",
        "DENY",
        "DENY" if not r.ok else "ALLOW",
        list(r.reason_codes),
    )

    inv_passed, inv_total, inv_failures = run_security_invariants()

    metrics = {
        "unauthenticated_blocked": sum(
            1 for x in rows if x.category == "unauthenticated_blocked" and x.passed
        ),
        "invalid_credentials_blocked": sum(
            1 for x in rows if x.category == "invalid_credentials_blocked" and x.passed
        ),
        "valid_credentials_accepted": sum(
            1 for x in rows if x.category == "valid_credentials_accepted" and x.passed
        ),
        "approved_server_allowed": sum(
            1 for x in rows if x.category == "approved_server_allowed" and x.passed
        ),
        "unknown_server_denied": sum(
            1 for x in rows if x.category == "unknown_server_denied" and x.passed
        ),
        "unknown_tool_denied": sum(
            1 for x in rows if x.category == "unknown_tool_denied" and x.passed
        ),
        "tool_tampering_denied": sum(
            1 for x in rows if x.category == "tool_tampering_denied" and x.passed
        ),
        "shadowing_denied": sum(
            1 for x in rows if x.category == "shadowing_denied" and x.passed
        ),
        "invalid_parameters_denied": sum(
            1 for x in rows if x.category == "invalid_parameters_denied" and x.passed
        ),
        "invalid_output_denied": sum(
            1 for x in rows if x.category == "invalid_output_denied" and x.passed
        ),
        "replay_denied": sum(1 for x in rows if x.category == "replay_denied" and x.passed),
        "intent_mismatch_denied": sum(
            1 for x in rows if x.category == "intent_mismatch_denied" and x.passed
        ),
        "timeout_safely_handled": sum(
            1 for x in rows if x.category == "timeout_safely_handled" and x.passed
        ),
        "malicious_output_contained": sum(
            1 for x in rows if x.category == "malicious_output_contained" and x.passed
        ),
        "cross_tenant_denied": sum(
            1 for x in rows if x.category == "cross_tenant_denied" and x.passed
        ),
        "invariants_passed": inv_passed,
        "invariants_total": inv_total,
    }

    passed = sum(1 for r in rows if r.passed)
    report = {
        "phase": 17,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "total": len(rows),
        "metrics": metrics,
        "invariant_failures": inv_failures,
        "rows": [asdict(r) for r in rows],
        "note": (
            "Phase 17 authentication + Mock MCP evaluation. "
            "Separate from Phase 11 detection F1. "
            "No real MCP, no production IdP. AegisAI is NOT production-ready."
        ),
    }
    _OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    _OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "# Phase 17 Authentication + MCP Evaluation",
        "",
        f"Passed: {passed} / {len(rows)}",
        f"Invariants: {inv_passed} / {inv_total}",
        "",
        "## Metrics",
        "```",
        json.dumps(metrics, indent=2),
        "```",
        "",
        report["note"],
        "",
    ]
    if inv_failures:
        lines.append("## Invariant failures")
        lines.extend(f"- {f}" for f in inv_failures)
        lines.append("")
    _OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(evaluate_phase17(), indent=2))

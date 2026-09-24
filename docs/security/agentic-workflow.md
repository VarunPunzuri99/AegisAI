# Agentic Security Workflow

**Phase:** 9  
**Status:** Implemented (state + proposals only — **no tool execution**)

AegisAI’s agent layer consumes Phase 7–8 security results and produces a controlled **action proposal**. It does not recalculate risk, reinterpret policy with an LLM, or execute tools.

---

## Why an agent layer?

Detection and policy answer:

> Is this content risky, and what decision should we make?

Agents introduce a second question:

> What action is being proposed, and how dangerous is *that action*?

Those are different. A benign prompt can still request a critical action (e.g. delete). A blocked prompt must never produce a tool proposal.

---

## Prompt risk vs action risk

| Concept | Source | Example |
|---------|--------|---------|
| **Prompt security risk** | Fusion + Risk Engine (0–100) | Injection attempt → risk 90 |
| **Action risk** | Intrinsic action classification | `delete_data` → CRITICAL |

They are **not** merged into one field.

```text
Prompt BENIGN (risk 5)  +  delete_database_record (CRITICAL)
→ Policy may ALLOW the prompt
→ Agent proposes action → READY_FOR_TOOL_GUARD
→ Phase 10 still must authorize the tool

Prompt ATTACK (risk 90) + search_public_documents (LOW)
→ Policy BLOCK
→ Agent: NO_ACTION (no proposal)
```

---

## Pipeline position

```text
Policy Engine → ALLOW / REVIEW / BLOCK
        ↓
Agent Security State
        ↓
Action Proposal (intent only)
        ↓
READY_FOR_TOOL_GUARD   (when applicable)
        ↓
──── Phase 10: Tool Firewall ────
(not implemented here)
```

---

## Agent state machine

```text
                    INPUT + PolicyDecision
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
            ALLOW         REVIEW        BLOCK
              │             │             │
              ▼             ▼             ▼
      ACTION_PROPOSED   ACTION_       NO_ACTION
              │         REQUIRES_
              │         REVIEW
              ▼
   (HIGH/CRITICAL action)
              │
              ▼
     READY_FOR_TOOL_GUARD
              │
              ▼
           Phase 10
```

**No `EXECUTED` state** in Phase 9.

| Policy | Agent status |
|--------|----------------|
| BLOCK | `NO_ACTION` — never generate a tool proposal |
| REVIEW | `ACTION_REQUIRES_REVIEW` |
| ALLOW + valid LOW/MEDIUM action | `ACTION_PROPOSED` |
| ALLOW + valid HIGH/CRITICAL action | `READY_FOR_TOOL_GUARD` |
| Missing assessment/policy | `ACTION_REQUIRES_REVIEW` (fail-closed) |

**ALLOW does not mean automatic tool execution.** Even `READY_FOR_TOOL_GUARD` only hands off to Phase 10.

---

## Trust level

```text
TRUSTED | UNTRUSTED | UNKNOWN
```

Trust describes **source/context**, not authorization. A trusted operator can still paste an untrusted PDF or web page. Trust never grants tool privileges.

---

## Action proposal

`AgentActionProposal` fields include:

```text
action_id, action_type, target, parameters
action_risk, reason
intent_alignment, declared_intent
security_context  (policy id/version, risk_score, conflict, uncertainty, …)
```

### Action risk examples

| Action | Risk |
|--------|------|
| search / read public | LOW |
| read private / write | MEDIUM |
| external mutation / send email | HIGH |
| delete / financial / credential change | CRITICAL |

These are classifications for future tools — **no tools are registered or executed**.

---

## Intent / action mismatch

Phase 9 provides a **deterministic** alignment hook (keyword buckets), not an LLM judge.

Example:

```text
declared_intent = "Find the employee PTO policy."
action_type     = send_email
→ intent_alignment = false
```

Mismatch is recorded on the proposal; it does **not** authorize or execute anything. Phase 10 can enforce stricter rules.

LLM-generated intent (e.g. from semantic analysis) is evidence only — never authorization.

---

## Fail-closed behavior

Missing:

- policy decision
- security assessment
- valid action type / risk / required target

→ `ACTION_REQUIRES_REVIEW` (never assume ALLOW / never READY_FOR_TOOL_GUARD).

---

## Phase 10 boundary

Phase 9 ends at:

```text
AgentActionProposal → READY_FOR_TOOL_GUARD
```

Phase 10 will add:

```text
Tool Firewall → authz → allowlist → parameter validation
→ injection checks → human approval → ALLOW/DENY → execution
```

---

## Code map

| Module | Role |
|--------|------|
| `app/agents/types.py` | State, proposal, enums |
| `app/agents/action_risk.py` | Action risk map |
| `app/agents/intent_alignment.py` | Deterministic mismatch hook |
| `app/agents/workflow.py` | `AgentSecurityWorkflow` |
| `app/services/agent_security.py` | Bridge from `DetectionPipelineResult` |

Tests: `tests/test_agent_security.py`, `tests/test_agent_actions.py`.

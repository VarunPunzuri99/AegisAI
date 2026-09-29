# Tool Firewall

**Phase:** 10  
**Status:** Implemented (sandboxed tools only — no real side effects)

The Tool Firewall is the independent security boundary between an `AgentActionProposal` and tool execution.

```text
AgentActionProposal  ≠  authorization
Policy ALLOW         ≠  unconditional tool access
LLM output           ≠  authorization
```

---

## Why it exists

Phase 8 answers “what should we do about this *content*?”  
Phase 9 answers “what *action* is proposed?”  
Phase 10 answers “is this *specific tool call* authorized to run?”

OWASP agent guidance: least-privilege tools, server-side enforcement, parameter validation, and independent validation of high-impact actions.

---

## Policy Engine vs Tool Firewall

| Layer | Decision | Meaning |
|-------|----------|---------|
| Policy Engine (Phase 8) | ALLOW / REVIEW / BLOCK | Prompt/content security decision |
| Tool Firewall (Phase 10) | ALLOW / DENY / REQUIRES_APPROVAL | Tool execution authorization |

`Policy = BLOCK` → firewall always **DENY** (approval cannot override).  
`Policy = ALLOW` → firewall still checks allowlist, permissions, target, params, intent, approval, replay.

---

## Pipeline

```text
ACTION PROPOSAL
      ↓
TOOL FIREWALL
  • Allowlist
  • Permissions
  • Target scope
  • Parameters
  • Intent alignment
  • Action risk / approval
  • Replay protection
      ↓
 ALLOW / DENY / REQUIRES_APPROVAL
      ↓
MOCK EXECUTOR (ALLOW only)
      ↓
ToolExecutionResult (trusted=false)
```

---

## Tool registry (allowlist)

Static, application-controlled. Unknown tools → `DENY` / `TOOL_NOT_ALLOWLISTED`.

| Tool | Risk | Permission |
|------|------|------------|
| `search_public_documents` | LOW | `documents:public:read` |
| `read_public_document` | LOW | `documents:public:read` |
| `search_private_documents` | MEDIUM | `documents:private:read` |
| `read_private_document` | MEDIUM | `documents:private:read` |
| `write_record` | MEDIUM | `records:write` |
| `send_email` | HIGH | `email:send` (+ approval) |
| `delete_record` | CRITICAL | `records:delete` (+ approval) |

Tool metadata is **DATA**, not instructions. Descriptions cannot alter firewall behavior.

---

## Permission & target model

- No `*` wildcards.
- Every tool declares `required_permissions`.
- Targets must be in the tool’s `allowed_targets` (and session grants when set).

Example: `documents:public:read` cannot call `read_private_document`.

---

## Parameter validation

Strict schemas per tool (`additional` keys rejected). Forbidden keys include `shell_command`, `credential`, `delete_all`, etc.

Search: `query` required; `limit` integer 1–50.  
Email: `recipient`, `subject`, `body` required.  
Delete: `record_id` only.

---

## Intent protection

Reuses `app/agents/intent_alignment.py`.  
`intent_alignment=false` → **DENY** (all risk levels in Phase 10 default).

Demo: intent “Find PTO policy” + `send_email(employee_database)` → DENY.

---

## Approval

Trusted `ToolSecurityContext.approval_state` only (`NOT_REQUIRED` / `PENDING` / `APPROVED` / `REJECTED`).  
Agent text cannot manufacture approval.

- HIGH (`send_email`) → requires `APPROVED` else `REQUIRES_APPROVAL`
- CRITICAL (`delete_record`) → requires `APPROVED` else `REQUIRES_APPROVAL`
- Approval never overrides `Policy = BLOCK`

---

## Replay protection

`action_id` tracked in-process (`ActionReplayRegistry`). Second attempt → `DENY` / `ACTION_ALREADY_PROCESSED`.  
Production needs durable/atomic storage.

---

## Mock executor

Receives only `ToolExecutionRequest` with firewall `ALLOW`.  
Returns simulated results (`SIMULATED_EMAIL_SENT`, `SIMULATED_DELETE`, …).  
**No** SMTP, Gmail, Slack, payments, real DB writes, shell, subprocess, MCP, or arbitrary HTTP.

---

## Tool output trust boundary

Every `ToolExecutionResult`:

```text
trusted = false
source = TOOL_OUTPUT
```

`sanitize_tool_output()` flags instruction-like strings. Future agent steps must treat tool output as DATA.

---

## Fail-closed

Missing security context, proposal, policy, tool, permissions, or invalid schema → **DENY** (never ALLOW).

---

## Future MCP boundary

```text
Tool Firewall → MCP Gateway → MCP Server → Real Tool
```

MCP should inherit allowlists, scopes, parameter validation, approval, audit, replay, and output sanitization. **Not implemented in Phase 10.**

---

## Code map

| Module | Role |
|--------|------|
| `app/tools/types.py` | Decision / context / execution types |
| `app/tools/registry.py` | Allowlist registry |
| `app/tools/validators.py` | Parameter schemas |
| `app/tools/authorization.py` | Permission / target checks |
| `app/tools/firewall.py` | `ToolFirewall.authorize_tool_call` |
| `app/tools/executor.py` | `MockToolExecutor` |
| `app/tools/replay.py` | Action ID registry |
| `app/services/tool_guard.py` | Authorize ± execute orchestration |

Tests: `test_tool_firewall.py`, `test_tool_authorization.py`, `test_tool_executor.py`, `test_tool_firewall_e2e.py`.

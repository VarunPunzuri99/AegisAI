# MCP Gateway (Phase 17B)

**Phase 17 provides a secure Mock MCP gateway but does NOT implement real MCP networking.**

## Architecture

```text
Principal
 → Authentication
 → Original Intent
 → Detection / Policy
 → Authorization
 → Tool Firewall
 → Approval / Replay
 → MCP Gateway (integrity + schema)
 → MockMCPServer
 → Output as TOOL_OUTPUT / trusted=false
 → Agent Context
```

Never: Agent/LLM → MCP directly.

## Components

- `MCPGateway` — enforces the full chain before invoke
- `MockMCPServer` — in-process, no sockets, no side effects
- Registry allowlist — `aegis-demo-mcp` only
- Tool fingerprint (SHA-256) — pin definitions; mismatch → DENY
- Shadowing protection — tools keyed by `server_id + tool_name`
- Input/output schema validation + size limits
- Timeout → failure (never success)

## Safe tools only

- `mcp_search_public_documents`
- `mcp_read_public_document`
- `mcp_search_private_documents`

No shell, arbitrary HTTP, email, delete, or payments.

## Output trust

All MCP output is `source_type=TOOL_OUTPUT`, `trusted=false`.  
Malicious instruction text cannot change principal, tenant, permissions, approval, or trigger another tool.

## API

```text
GET  /api/v1/mcp/servers
GET  /api/v1/mcp/tools
GET  /api/v1/mcp/metrics
POST /api/v1/mcp/simulate
```

No server/tool registration endpoints.

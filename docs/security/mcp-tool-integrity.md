# MCP Tool Integrity (Phase 17)

## Fingerprinting

Each approved tool definition is pinned with SHA-256 over:

- server_id
- tool_name
- description
- input schema
- output schema
- capability
- risk

Before invoke, the gateway recomputes the fingerprint and compares to the registry.

Mismatch → `MCP_TOOL_DEFINITION_CHANGED` → **DENY** (MCP server not called).

## Why

Protects against tool-definition tampering / rug-pull behavior where an approved-looking tool changes description or schema after approval.

## Shadowing

Tools are addressed as `(server_id, tool_name)`.  
An unapproved server cannot shadow `mcp_search_public_documents` from `aegis-demo-mcp`.

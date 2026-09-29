# MCP Threat Model (Phase 17)

Aligned with OWASP MCP / agentic guidance. Prototype mitigations only.

| Risk | Phase 17 control |
|------|------------------|
| Token / secret exposure | Tokens never in SecurityEvent / MCP audit metadata |
| Privilege escalation | Phase 16 AuthorizationService + explicit capabilities |
| Tool poisoning | Output always untrusted TOOL_OUTPUT; schema validation |
| Supply chain | Explicit server allowlist; no auto-discovery |
| Command execution | No shell / code / arbitrary HTTP tools |
| Contextual prompt injection | Malicious output cannot grant privileges or auto-invoke |
| Authn / Authz | Bearer auth + capability checks on MCP APIs |
| Audit / telemetry | Sanitized MCP metrics + audit metadata |
| Shadow MCP servers | `server_id + tool_name`; unapproved → DENY + shadowing code |
| Context over-sharing | Constrained output schemas + size limits |

**Not covered yet:** real MCP transports, production IdP, durable replay store, SIEM.

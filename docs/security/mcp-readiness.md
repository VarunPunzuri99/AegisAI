# MCP Readiness (Phase 16)

## What exists

An MCP-**ready** authorization + transport abstraction:

- `ToolTransport` interface
- `MockToolTransport` implementation
- Explicit principals, capabilities, tenant checks
- Existing Tool Firewall as final gate

## What does NOT exist

- Real MCP client or server
- Real external tool side effects
- Network calls to MCP hosts
- Dynamic tool registration from untrusted sources

## Intended future path

```text
Agent Runtime
 → AegisAI Authorization
 → Tool Firewall
 → MCP Adapter (future)
 → MCP Server (future)
```

Phase 16 stops before MCP Adapter networking.

## Supply-chain note

OWASP agentic guidance highlights supply-chain and excessive agency risks.
Until MCP is introduced:

- Keep tool allowlists application-controlled  
- Never accept tool definitions from model output  
- Keep FAIL_CLOSED available via `AEGIS_SECURITY_MODE`  

**Phase 16 provides an MCP-ready authorization boundary but does NOT implement real MCP.**

**Phase 17B provides a Mock MCP gateway with integrity controls but still does NOT implement real MCP networking.**

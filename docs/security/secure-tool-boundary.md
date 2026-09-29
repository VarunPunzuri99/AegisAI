# Secure Tool Boundary (Phase 16)

## Boundary stack

```text
Agent Runtime
    ↓
AuthorizationService   (identity · capability · tenant)
    ↓
Tool Firewall          (allowlist · params · intent · approval · replay)
    ↓
MockToolTransport / MockToolExecutor
```

Future (NOT Phase 16):

```text
… → MCP Adapter → MCP Server
```

## Rules

1. Authorization DENY ⇒ executor never called  
2. Tool Firewall DENY ⇒ executor never called  
3. Policy BLOCK ⇒ cannot be overridden by approval or authz ALLOW  
4. Untrusted content cannot grant permissions  
5. Targets cannot be `*`  
6. Replay remains denied on second `action_id`  

## Integration

`ToolGuardService.authorize()` runs Phase 16 authz when `principal_id`/`tenant_id`
are present (Phase 16 contexts). Legacy contexts without tenant continue through
the firewall permission model for regression compatibility.

`MockToolTransport` implements `validate_tool_request` / `authorize_tool_request` /
`execute_tool_request` for MCP-shaped interfaces without network I/O.

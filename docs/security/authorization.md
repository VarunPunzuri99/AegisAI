# Authorization Model (Phase 16)

**Status:** MCP-ready authorization boundary — **not** production authn/IdP.

## Principle

> No agent, model, tool, MCP server, or untrusted content may bypass AegisAI's
> Policy Engine and Tool Firewall.

Authorization is an **additional** boundary. It never replaces Tool Firewall.

## Order

```text
Identity (Principal)
 → Original intent
 → Untrusted context inspection
 → Policy decision
 → Action risk
 → Authorization (Phase 16)
 → Tool Firewall (Phase 10)
 → Approval (if required)
 → Replay protection
 → Mock execution
```

## Identity

Internal simulator principals (`user:demo`, `agent:aegis-demo`, …):

| Field | Notes |
| --- | --- |
| principal_id | Explicit string ID |
| principal_type | USER / AGENT / SERVICE / TOOL |
| tenant_id | Required — fail-closed if missing |
| roles | Informational |
| permissions | Explicit capability strings only |
| status | ACTIVE / DISABLED |

No wildcards (`*`, `admin:*`).

## Permissions / capabilities

Examples: `documents:public:read`, `documents:private:read`, `records:write`,
`records:delete`, `email:send`.

Tool capability map lives in `app.auth.capabilities` and mirrors ToolRegistry
allowlists.

## Tenant isolation

Cross-tenant resource access → `TENANT_MISMATCH` → DENY before execution.

Untrusted content cannot change principal or tenant.

## Fail closed

Missing principal, tenant, capability, unknown tool/target → DENY.

## Approval

BoundApproval binds `action_id`, `principal_id`, `tenant_id`, tool, target,
parameter fingerprint, expiry. Approval cannot override Policy BLOCK or
authorization DENY.

## API

```text
GET  /api/v1/auth/principals
GET  /api/v1/auth/capabilities
GET  /api/v1/auth/metrics
GET  /api/v1/auth/version
POST /api/v1/auth/authorize
```

**No** permission grant/mutation endpoints.

## Limitations

- Not a real IdP / OAuth / SSO integration
- Demo principals only
- Does not implement real MCP
- Audit APIs remain unauthenticated (Phase 15 limitation)
- Not production-ready

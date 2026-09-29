# Authentication (Phase 17A)

**Status:** Development bearer authentication — **not** a production IdP / OAuth / SSO.

## Principle

Authentication answers **who you are**. Authorization (Phase 16) answers **what you may do**.

Protected APIs require:

1. Valid `Authorization: Bearer <token>` → `AuthenticationResult`
2. Explicit capability check → 403 if missing
3. Tenant derived from the authenticated principal (client `tenant_id` ignored)

## Development mode

```text
AEGIS_AUTH_MODE=development
AEGIS_DEMO_TOKEN_USER=<from environment>
```

Tokens map to demo principals (`user:demo`, `user:readonly`, …).  
Tokens must **never** be committed. Fail-closed if token missing/invalid/disabled.

## Fail closed

Missing / malformed / invalid / expired token / disabled principal → **401**.  
Never anonymous access on protected routes.

## Endpoint access matrix

| Path | Class | Capability |
|------|--------|------------|
| `/health`, `/readiness`, `/` | PUBLIC | — |
| `/api/v1/audit*` | AUTHORIZED | `audit:read:own-tenant` |
| `/api/v1/dashboard*` | AUTHORIZED | `dashboard:read` |
| `/api/v1/auth/principals` etc. | AUTHORIZED | `authz:read` |
| `/api/v1/auth/authorize` | AUTHORIZED | `authorization:check` |
| `/api/v1/auth/session` | AUTHENTICATED | — |
| `/api/v1/agent*` | AUTHORIZED | `agent:simulate` |
| `/api/v1/inspect`, `/scans` | AUTHORIZED | `scan:inspect` |
| `/api/v1/mcp*` | AUTHORIZED | `mcp:read` / `mcp:simulate` |

See `app.authentication.access_matrix`.

## Tenant-scoped audit

Authenticated tenant is authoritative. Cross-tenant event access → **403**.

## Frontend

"Development Authentication" identity selector. Token from `NEXT_PUBLIC_AEGIS_DEMO_TOKEN_*`, held in memory only — not localStorage/sessionStorage/URL.

## Limitations

- Not OAuth/OIDC/SSO
- Demo tokens only
- Audit APIs now authenticated, but this is still a prototype
- AegisAI is **NOT** production-ready

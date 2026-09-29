# Incident Response — AegisAI

**Status:** Phase 15  
**Principle:** Fail closed for security decisions. Never treat unavailable evidence as BENIGN.

## Severity classes

| Class | Meaning |
| --- | --- |
| P1 | Tool execution path compromised / invariant broken |
| P2 | Provider total outage / persistence loss |
| P3 | Elevated REVIEW/UNCERTAIN / rate limits / latency |
| P4 | Dashboard / observability gaps |

## Scenarios

### Prompt Guard unavailable

- **Detection:** `error_code` TIMEOUT / MISSING_API_KEY / RATE_LIMITED / EMPTY_RESPONSE
- **Fusion:** PG → UNAVAILABLE; uncertainty elevated
- **Policy:** Prefer REVIEW over ALLOW when uncertain (`uncertain_forces_review`)
- **Action:** Check Groq status/key; do **not** disable fail-closed behavior
- **Do not:** Map failure → BENIGN

### Safeguard unavailable

- Same as above for SEMANTIC source
- Expect higher REVIEW / UNCERTAIN rates
- Document latency separately; do not remove Safeguard to “fix” metrics

### Groq rate-limited (429)

- Client: bounded retry (`max_retries ≤ 2`) with backoff / Retry-After (cap 5s)
- Record `failure_type=RATE_LIMITED`, `retry_count`, `recovered`
- Decision uses remaining available evidence only
- **Never:** `429 → ALLOW`

### Database unavailable

- `/readiness` → `not_ready`
- `/health` remains liveness OK
- Inspect may still compute decisions; persistence failures must **not rewrite** the security decision (return 500 on persist fail per Phase 13)

### Audit persistence fails

- Keep pipeline decision intact
- Surface error to operator
- Do not silently drop security events in production deployments

### Tool firewall fails / throws

- Treat as DENY / fail-closed
- Do not execute mock or real tools

### Unexpected provider output

- Empty → EMPTY_RESPONSE → unavailable
- Malformed → do not blind-retry forever
- Unknown labels → UNCERTAIN path

### Security invariant fails (CI / eval)

- Block release
- File regression case in red-team corpus
- Do **not** delete failing cases to green the suite

### Emergency mode (`AEGIS_SECURITY_MODE`)

| Mode | Behavior |
| --- | --- |
| NORMAL | Standard pipeline |
| DEGRADED | Same controls; expect more REVIEW (operator communication) |
| FAIL_CLOSED | ToolGuard denies all tool execution (`SECURITY_MODE_FAIL_CLOSED`) |

Mode is **server-side config only** — never set by model or untrusted input.

## Contacts / runbook checklist

1. Confirm `/health` vs `/readiness`
2. Check provider observed status (`GET /api/v1/dashboard/providers`)
3. Check latest eval / review analysis
4. Confirm no raw prompts in `security_events`
5. If tools were at risk: set `AEGIS_SECURITY_MODE=FAIL_CLOSED` and restart

## Authorization limitation (known)

Audit and dashboard diagnostic endpoints are **unauthenticated** in this build.
Treat as localhost/dev boundary until auth is integrated.

# AegisAI — Audit & Persistence (Phase 13)

## Scope

Application-level **structured security events** persisted after the existing
inspect pipeline. Backend remains authoritative for detection, risk, policy,
and tool decisions.

> Audit records are application-level structured security events.  
> They are **not** yet a tamper-evident compliance ledger or SIEM.

## Persistence flow

```text
POST /api/v1/inspect
      ↓
SecurityDetectionService (unchanged thresholds)
      ↓
InspectResponse (in-memory decision)
      ↓
SecurityEventService.persist_inspect
      ├── Scan (COMPLETED + decision/risk/severity)
      ├── DetectionResult rows (summaries only)
      ├── SecurityEvent (hash + structured metadata)
      └── AuditEvent breadcrumb
      ↓
PostgreSQL
      ↓
GET /api/v1/audit
GET /api/v1/audit/{event_id}
GET /api/v1/dashboard/activity
```

If analysis succeeds but persistence fails → HTTP 500 `AUDIT_PERSISTENCE_FAILED`.
The security decision itself is not rewritten (BLOCK never becomes ALLOW).

## Security event schema (high level)

| Field | Notes |
|-------|--------|
| `id` | Server UUID (primary key) |
| `scan_id` | Optional FK to `scans` |
| `content_hash` | SHA-256 of input (no raw content) |
| `content_length` | Integer |
| `detection_label` | Fusion label |
| `attack_types` | JSON list |
| `risk_score` / `severity` | From unified assessment |
| `policy_decision` / `policy_id` / `policy_version` | From policy engine |
| `conflict` / `uncertainty` | Booleans |
| `agent_state` | Agent workflow status |
| `tool_name` / `tool_decision` | Firewall demo outcome |
| `reason_codes` | Policy/agent/tool codes |
| `detector_summary` | Rules / PG / Safeguard labels+scores |
| `pipeline_stages` | Status/summary only (no content previews) |
| `simulated` | Always true for mock tool path |

## Sensitive-data exclusions

Never persisted:

- Groq API keys / tokens
- Raw prompts / full model I/O
- Passwords / credentials found in content
- Full tool parameter payloads that may contain secrets

Traceability uses `content_hash` + `content_length` only.

## Audit API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/audit` | Paginated list + summary counts |
| GET | `/api/v1/audit/{event_id}` | Detail |

Filters (exact / whitelist): `decision`, `severity`, `detection_label`,
`attack_type`, `tool_name`, `tool_decision`, `agent_state`, `policy_version`,
`start_date`, `end_date`.

Pagination: `page`, `page_size` (max 100). Sort: `created_at DESC` only.

## Retention

No automated purge in Phase 13. Events remain until manually deleted at the DB
layer. Production retention policy is deferred.

## Known limitations

- No cryptographic hash chaining / digital signatures
- No multi-tenant access control on audit reads
- No SIEM export
- Tool path remains simulated (mock executor)
- Existing `AuditEvent` table remains a lightweight scan breadcrumb log;
  `security_events` is the Phase 13 decision store

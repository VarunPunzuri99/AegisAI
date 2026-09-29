# AegisAI System Architecture

**Status:** Evolving with hackathon phases.  
**Phase 1:** Repository foundation, configuration, health API, documentation.  
**Phase 2:** Scan domain, PostgreSQL models, Alembic migration, scan metadata API.  
**Phase 3:** Input validation, Unicode/encoding/HTML preprocessing, chunking → `SecurityInput`.  
**Phase 4:** Deterministic detection engine → `DetectionReport` (evidence only; not ALLOW/BLOCK).  
**Phase 5:** Groq Llama Prompt Guard 2 (86M) → `PromptGuardResult` (separate from rules).  
**Phase 6:** GPT-OSS-Safeguard semantic analyzer → `SemanticSecurityAssessment` (policy-grounded evidence).  
**Phase 7:** Detection fusion + deterministic risk engine → `UnifiedSecurityAssessment` (evidence + score; no ALLOW/BLOCK).  
**Phase 8:** Policy engine → `PolicyDecision` (ALLOW / REVIEW / BLOCK — decision only, no external enforcement).  
**Phase 9:** Agent security workflow → state + action proposals → `READY_FOR_TOOL_GUARD` (no tool execution).  
**Phase 10:** Tool Firewall + sandboxed mock executor → ALLOW / DENY / REQUIRES_APPROVAL (no real side effects).  
**Phase 11:** Security evaluation + red-team regression harness (offline-first metrics).  
**Phase 12:** Frontend security dashboard + thin inspect/dashboard APIs (no threshold changes).  
**Phase 13:** Persistent security events + audit API (hash/metadata only; no SIEM).  
**Phase 14:** Agent runtime simulation — session, trust-aware context, scenarios, Tool Firewall demo path, `/agent-runtime` UI.  
**Phase 15:** Production hardening — provider observability, pipeline timing, review/UNCERTAIN analysis, readiness, threat/IR docs. No threshold tuning.  
**Phase 16:** Authorization boundary — principals, tenant isolation, Authz before Tool Firewall, MockToolTransport. **No real MCP.**  
**Phase 17:** Development authentication + protected APIs + Mock MCP gateway (integrity, shadowing, untrusted output). **No real MCP / IdP.**  
**Phase 18:** Hackathon freeze — validation, demo packaging, documentation. Architecture frozen.  
**Not implemented yet:** Real MCP / external tools, multimodal ingestion, production OAuth/SSO, Phase 19+.

---

## Implemented vs planned

### IMPLEMENTED (Phase 1–4)

| Area | Status |
|------|--------|
| API foundation (`/`, `/health`, CORS, config) | Implemented |
| Versioned scan API (`POST/GET /api/v1/scans`) | Implemented |
| Scan domain model + content hash (no raw content storage) | Implemented |
| DetectionResult model (schema ready; not auto-persisted from API yet) | Implemented |
| AuditEvent model (SCAN_CREATED recorded on create) | Implemented |
| PostgreSQL + SQLAlchemy 2.x + Alembic initial migration | Implemented |
| Service layer (`ScanService`) | Implemented |
| Structured API errors | Implemented |
| Input validation + normalization (`InputNormalizationService`) | Implemented |
| Unicode / control / whitespace analysis | Implemented |
| Encoding / obfuscation indicators (bounded decode) | Implemented |
| HTML / prompt-boundary structure flags | Implemented |
| Chunking abstraction (character fallback tokenizer) | Implemented |
| `SecurityInput` in-memory object | Implemented |
| Deterministic detection engine (9 category detectors) | Implemented |
| `DetectionReport` / findings with rule IDs | Implemented |
| Groq provider abstraction (`integrations/groq`) | Implemented |
| Prompt Guard detector + chunk aggregation | Implemented |
| `SecurityDetectionService` orchestration (no Scan API wiring) | Implemented |
| Versioned security policy (`AEGIS-PROMPT-INJECTION` v1.0) | Implemented |
| Semantic security analyzer (GPT-OSS-Safeguard) | Implemented |
| Offline deterministic evaluation harness | Implemented |
| Detection fusion (`DetectionFusionEngine`) | Implemented |
| Risk engine (`RiskEngine`, explainable factors) | Implemented |
| Unified security assessment | Implemented |
| Policy engine (`evaluate_policy` → ALLOW/REVIEW/BLOCK) | Implemented |
| Agent security workflow + action proposals | Implemented |
| Tool firewall + mock executor | Implemented |
| Security evaluation / red-team harness | Implemented |
| Inspect API (`POST /api/v1/inspect`) | Implemented |
| Dashboard read APIs (evaluation/policy/tools/status/playground) | Implemented |
| Frontend security console (App Router) | Implemented |
| Security events table + audit API | Implemented |
| Dashboard activity from security events | Implemented |

### PLANNED (later phases)

| Area | Status |
|------|--------|
| Real external tools / MCP gateway | Planned |
| Decision automation (SANITIZE/QUARANTINE persistence) | Planned |
| Tamper-evident / SIEM audit export | Planned |
| Multimodal ingestion (PDF, DOCX, OCR, images) | Planned |
| Real model tokenizer for chunking | Planned |
| PostgreSQL integration tests (vs SQLite unit tests) | Planned |
| Production authentication | Planned |

---

## High-level flow

```
User / Application
        ↓
   API Gateway                    [IMPLEMENTED — FastAPI]
        ↓
  Input Ingestion                 [PARTIAL — text scan create]
        ↓
   Validation                     [IMPLEMENTED — Phase 3]
        ↓
   Normalization / Preprocessing  [IMPLEMENTED — Phase 3 → SecurityInput]
        ↓
  Deterministic Detection         [IMPLEMENTED — Phase 4 → DetectionReport]
        ↓
  Prompt Guard (Groq)             [IMPLEMENTED — Phase 5 → PromptGuardResult]
        ↓
  Semantic Analyzer (Safeguard)   [IMPLEMENTED — Phase 6 → SemanticSecurityAssessment]
        ↓
    Fusion                        [IMPLEMENTED — Phase 7 → UnifiedSecurityAssessment]
        ↓
    Risk Engine                   [IMPLEMENTED — Phase 7 → score / severity / factors]
        ↓
   Policy Engine                  [IMPLEMENTED — Phase 8 → ALLOW / REVIEW / BLOCK]
        ↓
  Decision (in-memory)            [IMPLEMENTED — PolicyDecision; not persisted / enforced]
   ├── ALLOW
   ├── REVIEW
   └── BLOCK
        ↓
  Agent Security State            [IMPLEMENTED — Phase 9]
        ↓
  Action Proposal                 [IMPLEMENTED — intent only]
        ↓
  READY_FOR_TOOL_GUARD            [IMPLEMENTED — handoff state]
        ↓
  Authorization                   [IMPLEMENTED — Phase 16 identity/tenant/capability]
   ├── ALLOW
   ├── DENY
   └── REQUIRES_APPROVAL
        ↓
  Tool Firewall                   [IMPLEMENTED — Phase 10 — never bypassed]
   ├── ALLOW
   ├── DENY
   └── REQUIRES_APPROVAL
        ↓
  Mock Tool Executor / Transport  [IMPLEMENTED — simulated only; MCP-ready interface]
        ↓
  MCP Gateway + MockMCPServer     [IMPLEMENTED — Phase 17B; no real MCP networking]
        ↓
  Real Tools / MCP                [PLANNED — Phase 18+]
        ↓
  Audit / Telemetry               [PARTIAL — SecurityEvent + Phase 15/17 metrics; authn on APIs]
```

Detailed preprocessing notes: [docs/security/input-normalization.md](../security/input-normalization.md).

---

## Component responsibilities

### User / Application

External callers that submit untrusted content. Treated as untrusted by default.

### API Gateway

**Implemented:** FastAPI with `/`, `/health`, and `/api/v1/scans`. CORS from settings.  
**Planned:** Auth, rate limiting.

### Input Ingestion

**Implemented (Phase 2):** `POST /api/v1/scans` accepts text + `source_type`, hashes content, stores metadata only.  
**Planned:** Multimodal channels, richer source metadata.

### Normalization / Preprocessing

**Implemented (Phase 3):** `InputNormalizationService` → in-memory `SecurityInput` (NFKC, whitespace, control/encoding/HTML/prompt flags, character-fallback chunks). Does **not** decide maliciousness and does **not** persist normalized/decoded text. Details: `docs/security/input-normalization.md`.

### Detection Layer

**Partial (Phase 4–8):** Deterministic rules + Prompt Guard + semantic Safeguard + fusion/risk + policy decision → `PolicyDecision`.  
**Planned:** External enforcement, persisting results, Scan API wiring of decisions.

### Risk Engine / Policy Engine / Decision Engine

**Risk (Phase 7):** Deterministic 0–100 score, severity bands, explainable factors — see `docs/security/fusion-and-risk.md`.  
**Policy (Phase 8):** ALLOW / REVIEW / BLOCK from assessment — see `docs/security/policy-engine.md`.  
**Enforcement / Scan persistence:** Planned. DB `decision` remains unset by the public Scan API until wired.

### Agent Execution / Tool Firewall

**Agent workflow (Phase 9):** Security state + action proposals → `READY_FOR_TOOL_GUARD`. See `docs/security/agentic-workflow.md`.  
**Tool firewall (Phase 10):** Independent allowlist / permissions / params / intent / approval / replay → mock executor. See `docs/security/tool-firewall.md`.  
**Agent runtime simulation (Phase 14):** Deterministic scenario loop over the existing pipeline + firewall. See `docs/security/agent-runtime.md`.  
**Real tools / MCP:** Planned.

### Audit / Telemetry

**Phase 13:** `SecurityEvent` persistence + `GET /api/v1/audit` (hash + decision metadata only).  
**Phase 14:** Runtime simulations also persist security events with `scenario_id` metadata.  
Never log API keys or raw submitted content.

---

## Environment configuration

The backend loads configuration from:

1. Process environment variables
2. **`backend/.env`** (path resolved from the backend package root)

The monorepo root `.env` is **not** read by the backend. Never put secrets in frontend env files.

---

## Repository mapping

| Concern | Location |
|---------|----------|
| HTTP API | `backend/app/api/`, `backend/app/main.py` |
| Configuration | `backend/app/core/config.py` |
| Database session | `backend/app/core/database.py` |
| ORM / DB | `backend/app/models/`, `backend/alembic/` |
| Schemas | `backend/app/schemas/` |
| Services | `backend/app/services/` |
| Security logic | `backend/app/security/` (future detectors) |
| Agents | `backend/app/agents/` (workflow + Phase 14 `runtime/`) |
| Frontend | `frontend/` |
| Evaluation data | `datasets/` |
| Docs | `docs/` |

---

## AI provider abstraction

Groq remains the planned provider. Model names are configured via environment variables. **No LLM API calls are made in Phase 2.**

---

## Data store

PostgreSQL is the production database. Alembic migration `20260324_0001` creates `scans`, `detection_results`, and `audit_events`. Automated tests use isolated in-memory SQLite with the same ORM models.

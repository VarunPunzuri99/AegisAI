# AegisAI — Hackathon Release Candidate

**Project:** AegisAI — Agentic Prompt Injection Firewall  
**Version:** Hackathon RC-1  
**Architecture:** FROZEN (Phases 1–17)  
**Prototype status:** DEMO READY  
**Production status:** NOT PRODUCTION READY  

Phase 18 freezes the architecture and packages validation, demo, and documentation. No Phase 19 scope.

## Validation snapshot (measured in Phase 18 freeze)

| Check | Result |
|-------|--------|
| Backend pytest | **371 passed** |
| Frontend vitest | **7 passed** |
| Lint | PASS |
| Typecheck | PASS |
| Build | PASS |
| Security invariants | **45/45** |
| Authorization eval | **11/11** |
| MCP eval | **15/15** |
| Offline detection F1 | **0.5107** (dataset-only) |
| Live detection F1 | **0.9706** (stored artifact; dataset-only) |

Re-run commands before submission and update numbers if they change.

## Evaluation (dataset-only)

### Live (`aegis_eval_v1_live.json`)

- F1 **0.9706**
- Precision **0.9925**
- Recall **0.9496**
- FPR **0.04**
- FNR **0.0504**
- Policy mix: ALLOW **13**, REVIEW **144**, BLOCK **26**  
  (expected BLOCK often lands REVIEW under conservative uncertainty — intentional)

### Offline (`aegis_eval_v1.json`)

- F1 **0.5107**

These are **evaluation-dataset** measurements. Not production accuracy claims.

## Demo scenarios

See `backend/app/demo/scenarios.py` and `docs/hackathon/demo-script.md`.

## Startup

```bash
# Postgres (optional)
docker compose up postgres -d

# Backend
cd backend && .venv\Scripts\activate  # or source .venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend && npm run dev
```

Set `GROQ_API_KEY` and matching `AEGIS_DEMO_TOKEN_*` / `NEXT_PUBLIC_AEGIS_DEMO_TOKEN_*` in local env files (never commit).

## Environment requirements

- Python 3.11+
- Node 20+
- PostgreSQL 16 (Docker) for persistence demos
- Groq API key for live Prompt Guard / Safeguard paths

## Known limitations

- Not production-ready
- Mock MCP / mock tools only
- Development bearer auth (not IdP)
- In-process replay & metrics
- Conservative REVIEW volume on live policy
- Demo tokens in frontend env for UI convenience (labeled Development Authentication)

## Security findings (Phase 18 freeze review)

| Severity | Count | Notes |
|----------|-------|-------|
| CRITICAL | 0 | No release blockers found in freeze validation |
| HIGH | 0 | — |
| MEDIUM | 1 | Demo tokens exposed via `NEXT_PUBLIC_*` — acceptable for labeled hackathon demo only |
| LOW | 1 | `client` fixture mutates shared TestClient headers — tests isolate raw_client carefully |
| INFO | 1 | Live Groq eval not re-run in freeze (expensive); stored live artifacts used |

## Recommendation

If validation commands above pass on the submission machine:

**PHASE 18 COMPLETE — AEGISAI HACKATHON RELEASE CANDIDATE READY.**

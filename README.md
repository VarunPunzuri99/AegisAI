# AegisAI

## Agentic Prompt Injection Firewall

AegisAI is a **runtime security layer** between untrusted content and agent tool actions. It detects prompt injection, scores risk, applies deterministic policy, and enforces authentication, authorization, and a tool firewall — including a Mock MCP gateway — before any simulated side effect.

> **Hackathon prototype / demo.** Not production-ready. Evaluation metrics are dataset-only measurements, not production guarantees.

## Problem

AI agents do more than chat. They read documents, call tools, and may reach MCP servers. Untrusted content can attempt to:

- Override instructions (direct / indirect prompt injection)
- Hijack agent intent
- Abuse tools (email, delete, shell)
- Steal secrets or credentials
- Poison tool definitions or shadow MCP tools

Detecting injection text is not enough — a compromised plan must still be stopped before execution.

## Solution

**Detect → Understand → Decide → Protect → Audit**

Frozen pipeline:

```text
Untrusted Input
 → Normalization
 → Deterministic Detection + Prompt Guard + Semantic Safeguard
 → Fusion → Risk → Policy (ALLOW / REVIEW / BLOCK)
 → Agent Security Workflow
 → Authentication → Authorization / Tenant Isolation
 → Tool Firewall → Approval / Replay
 → Mock MCP Gateway → Mock MCP / Mock Tools
 → Untrusted Tool Output
 → Security Event / Audit → Dashboard
```

The backend is the source of truth for security decisions. The frontend never decides ALLOW/BLOCK.

## Key Features

- Input normalization & deterministic detectors
- Groq Prompt Guard + GPT-OSS-Safeguard semantic analysis
- Evidence fusion & explainable risk scoring
- Deterministic policy engine (ALLOW / REVIEW / BLOCK)
- Agent runtime simulation with intent alignment
- Development authentication + capability authorization
- Tenant isolation (fail-closed)
- Tool Firewall (allowlist, params, approval, replay)
- Mock MCP gateway (fingerprint integrity, shadowing protection)
- Persistent security events (hash + metadata; no raw prompts)
- Evaluation dashboard & attack playground

## Architecture

See [docs/architecture/aegisai-final-architecture.md](docs/architecture/aegisai-final-architecture.md) and [docs/architecture/system-architecture.md](docs/architecture/system-architecture.md).

## Demo (quick start)

### Prerequisites

- Python 3.11+, Node.js 20+, Docker (optional for Postgres)

### 1. Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set GROQ_API_KEY and AEGIS_DEMO_TOKEN_* values in backend/.env
alembic upgrade head   # with Postgres running
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
cp .env.example .env.local
# Set NEXT_PUBLIC_API_URL and matching NEXT_PUBLIC_AEGIS_DEMO_TOKEN_* values
npm run dev
```

Open http://localhost:3000

### Docker Compose

```bash
docker compose up --build
```

Copy secrets into `backend/.env` (not committed). Compose uses `.env.example` by default for non-secret config.

## Demo Scenarios (≈5 minutes)

1. **Dashboard** — Detect → Understand → Decide → Protect → Audit  
2. **Scanner** — Benign: “Find the employee PTO policy.”  
3. **Scanner / Playground** — Direct injection → BLOCK/REVIEW, no tool execution  
4. **Agent Runtime** — Intent hijack → Tool DENY  
5. **Agent Runtime** — High-risk delete → REQUIRES_APPROVAL  
6. **MCP Security** — Tamper / shadow → DENY  
7. **Audit** — Persisted event (hash only; no raw prompt)  
8. **Evaluation** — Dataset metrics (not production accuracy)

Detailed script: [docs/hackathon/demo-script.md](docs/hackathon/demo-script.md)

## Evaluation

| Suite | Result (stored / measured) | Note |
|-------|----------------------------|------|
| Live detection (`aegis_eval_v1`) | F1 **0.9706**, P **0.9925**, R **0.9496**, FPR **0.04**, FNR **0.0504** | Evaluation dataset only |
| Offline detection | F1 **0.5107** | Rules-only / offline harness |
| Live policy mix | ALLOW **13**, REVIEW **144**, BLOCK **26** | Conservative REVIEW on uncertainty |
| Authorization (Phase 16) | **11/11** | Separate from detection F1 |
| MCP (Phase 17) | **15/15** | Mock MCP only |
| Security invariants | **45/45** | INV-01..45 |

**Do not** claim “97% production accuracy,” “zero false positives,” or “production ready.”

Conservative REVIEW volume is intentional: uncertainty/conflict is **not** converted to BENIGN.

## Security Design

- Fail-closed on missing auth, unknown tools/servers, integrity mismatch, tenant mismatch, replay
- Provider failure → UNAVAILABLE / UNCERTAIN — never silent BENIGN
- Policy BLOCK cannot be overridden by approval
- Tool Firewall is the final execution boundary
- MCP / tool outputs remain `TOOL_OUTPUT` / untrusted
- No raw prompts, API keys, or bearer tokens in SecurityEvent records

## Limitations

- Prototype / demo — **not production-ready**
- Mock MCP only — no real MCP networking
- Mock tools only — no real email, shell, DB mutation, arbitrary HTTP
- Development bearer tokens — not OAuth/OIDC/SSO
- In-process replay registry & metrics
- Demo tokens may appear in frontend env for the UI (labeled Development Authentication)

## Project Structure

```text
backend/app/          # FastAPI security pipeline
backend/tests/        # pytest suite
backend/evaluation/   # Offline/live eval artifacts
frontend/             # Next.js security console
docs/                 # Architecture, security, hackathon
datasets/             # Evaluation corpora
docker-compose.yml
```

## Local Development

```bash
# Backend tests
cd backend && python -m pytest tests/ -q

# Frontend
cd frontend && npm test && npm run lint && npm run typecheck && npm run build
```

## Environment Variables

Documented in `backend/.env.example` and `frontend/.env.example`.

Never commit real `GROQ_API_KEY` or production tokens. Variable names only in docs.

## Hackathon Materials

- [Pitch (3 min)](docs/hackathon/pitch.md)
- [Demo script](docs/hackathon/demo-script.md)
- [Submission checklist](docs/hackathon/submission-checklist.md)
- [Release candidate](docs/hackathon/release-candidate.md)

## Future Work (post-hackathon)

- Real MCP transport
- Production IdP (OAuth/OIDC/SSO)
- Real external tools with least privilege
- Distributed observability / SIEM export
- Production deployment hardening

## License / Team

ET AI Hackathon — Agentic Edition (Problem 2). See team submission form for credits.

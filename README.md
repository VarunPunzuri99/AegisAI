# AegisAI

**Agentic Prompt Injection Firewall** — a hackathon prototype for the ET AI Hackathon: Agentic Edition (Problem 2).

## Problem

AI agents can be manipulated through direct and indirect prompt injection. Untrusted content in messages, documents, or tool outputs can override instructions, abuse tools, or exfiltrate sensitive context.

## Solution

AegisAI is designed as a **runtime security layer** that inspects untrusted content before it can influence an AI agent. It is intended to detect and neutralize malicious prompt injections, allow legitimate content through with minimal disruption, and demonstrate agentic security capabilities.

> **Phase 2 status:** Scan domain, PostgreSQL models, Alembic migration, and scan metadata API are implemented. Detection, Groq calls, risk/policy engines, agent workflows, and dashboards are **not implemented yet**.

## Planned capabilities

The following are **planned** for later phases (not available in Phase 1):

- Prompt injection detection
- Attack classification
- Risk scoring
- Policy enforcement
- Tool protection
- Audit trail
- Red-team evaluation
- Multimodal input inspection

AegisAI does **not** claim that prompt injection can be completely eliminated. The design uses defense in depth to reduce residual risk.

## Architecture

Planned pipeline (see [docs/architecture/system-architecture.md](docs/architecture/system-architecture.md)):

```
User/Application → API Gateway → Ingestion → Normalization
  → Detection (rules + Prompt Guard + LLM classifier)
  → Risk → Policy → Decision (ALLOW | SANITIZE | QUARANTINE | BLOCK)
  → Agent Execution → Tool Firewall → Audit / Telemetry
```

## Technology stack

| Layer | Stack |
|-------|--------|
| Backend | Python 3.11+, FastAPI, Pydantic, Uvicorn, SQLAlchemy 2.x, Alembic, httpx, pytest |
| AI (planned) | Groq API — Prompt Guard / safeguard / agent models |
| Frontend | Next.js, TypeScript, Tailwind CSS |
| Infrastructure | Docker, Docker Compose, PostgreSQL |

## Project structure

```
aegisai/
├── backend/          # FastAPI application
├── frontend/         # Next.js landing foundation
├── docs/             # Architecture, security, evaluation
├── datasets/         # Attack / benign evaluation placeholders
├── docker-compose.yml
└── README.md
```

## Local setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker & Docker Compose (optional, for full stack)

### Backend

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env   # or: cp .env.example .env
# Edit backend/.env — set GROQ_API_KEY when you begin AI phases.
# Backend reads backend/.env only (not the monorepo root .env).
# DATABASE_URL default for local Postgres: postgresql+psycopg://aegisai:aegisai@localhost:5432/aegisai

alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Verify:

- `GET http://localhost:8000/` — application info
- `GET http://localhost:8000/health` — health payload
- `POST http://localhost:8000/api/v1/scans` — create scan metadata (detection not run yet)
- `GET http://localhost:8000/api/v1/scans` — list scans
- OpenAPI: `http://localhost:8000/docs`

### Frontend

```bash
cd frontend
copy .env.example .env.local   # or: cp .env.example .env.local
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Tests

```bash
cd backend
pytest
```

### Docker Compose

```bash
docker compose up --build
```

Services:

| Service | URL |
|---------|-----|
| Backend | http://localhost:8000 |
| Frontend | http://localhost:3000 |
| PostgreSQL | localhost:5432 |

## Environment variables

### Backend (`backend/.env`)

| Variable | Purpose |
|----------|---------|
| `APP_ENV` | Environment name (`development`, etc.) |
| `APP_NAME` | Application display name |
| `DATABASE_URL` | SQLAlchemy PostgreSQL URL |
| `GROQ_API_KEY` | Groq API key (**backend only**, never expose to frontend) |
| `GROQ_DETECTION_MODEL` | Planned detection model id |
| `GROQ_REASONING_MODEL` | Planned reasoning / safeguard model id |
| `GROQ_AGENT_MODEL` | Planned agent model id |
| `CORS_ORIGINS` | Comma-separated allowed origins |
| `API_PREFIX` | Future API prefix (default `/api/v1`) |
| `LOG_LEVEL` | Logging level |

### Frontend (`frontend/.env.local`)

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_API_URL` | Backend base URL (public, no secrets) |

## Development commands

| Command | Description |
|---------|-------------|
| `uvicorn app.main:app --reload` | Run backend (from `backend/`) |
| `pytest` | Run backend tests |
| `npm run dev` | Run frontend |
| `npm run build` | Production frontend build |
| `npm run lint` | Frontend lint |
| `docker compose up --build` | Full local stack |

## Documentation

- [System architecture](docs/architecture/system-architecture.md)
- [Security principles](docs/security/security-principles.md)
- [Attack taxonomy](docs/security/attack-taxonomy.md)
- [Project checklist](docs/PROJECT_CHECKLIST.md)

## License

MIT — see [LICENSE](LICENSE).

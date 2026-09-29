# AegisAI Project Checklist

Track progress across phases. Check items only when actually completed.

## Foundation

- [x] Monorepo structure (`backend/`, `frontend/`, `docs/`, `datasets/`)
- [x] `.gitignore` and `LICENSE`
- [x] Root `README.md`
- [x] `docker-compose.yml` (backend, frontend, postgres)
- [x] Environment example files (no real secrets)
- [x] Centralized backend configuration module
- [ ] Full CI pipeline

## Backend

- [x] FastAPI application scaffold
- [x] `GET /` application info
- [x] `GET /health` health check
- [x] CORS configuration from settings
- [x] Basic pytest structure
- [x] Health endpoint tests
- [x] Configuration loading tests
- [x] Versioned scan / inspect API (`/api/v1/scans`)
- [x] Request validation for inspection payloads
- [x] Scan service layer
- [x] Structured API error responses
- [x] Scan API tests (create/get/list/validation/pagination)
- [ ] Authentication / authorization

## Database

- [x] SQLAlchemy / Alembic scaffolding
- [x] PostgreSQL service in Docker Compose
- [x] ORM models for Scan, DetectionResult, AuditEvent
- [x] Initial Alembic migration (`20260324_0001`)
- [x] Indexes for scan/status/decision and FK lookup columns
- [ ] Migrations applied on a live PostgreSQL instance (requires reachable DB credentials)
- [ ] Persistence for detector results and decisions (pipeline later)

## Input ingestion

- [x] Ingestion API for untrusted text content (`POST /api/v1/scans`)
- [x] Source type metadata (enum; processors later)
- [ ] Multimodal input support

## Normalization

- [x] Unicode / whitespace normalization (NFKC + flags)
- [x] Control-character analysis
- [x] Encoding / obfuscation inspection (bounded Base64/URL/hex/escapes)
- [x] HTML static structure flags
- [x] Prompt / role / tool boundary indicators
- [x] Chunking abstraction with replaceable tokenizer + character fallback
- [x] Centralized preprocessing limits (env-configurable)
- [x] `SecurityInput` in-memory model (not stored in DB)
- [x] Normalization unit tests
- [x] `docs/security/input-normalization.md`
- [ ] Instruction vs data channel tagging (deeper separation later)
- [ ] Model-accurate tokenizer for Prompt Guard token windows

## Detection

- [x] Deterministic rule engine (`DeterministicDetectionEngine`)
- [x] Attack category labeling (taxonomy-aligned)
- [x] Evidence / findings with rule IDs and signals
- [x] Multi-signal correlation (e.g. override + tool + exfil → CRITICAL)
- [x] False-positive / benign regression tests
- [x] Safe synthetic fixtures under `datasets/attacks` and `datasets/benign`
- [x] `docs/security/deterministic-detection.md`
- [ ] Session-aware multi-step detection
- [ ] Persist DetectionResult from API orchestration

## Groq integration

- [x] Provider service abstraction (`app/integrations/groq`)
- [x] Prompt Guard detection model wiring
- [x] Configurable model / timeout / retries / mode
- [x] Chunked invocation + max-score aggregation
- [x] Mocked unit tests (no network)
- [x] Optional live integration test gate
- [x] `docs/security/prompt-guard.md`
- [x] Safeguard / reasoning model wiring (GPT-OSS-Safeguard semantic analyzer)
- [x] Versioned security policy for Safeguard
- [x] Semantic assessment unit tests
- [x] Offline evaluation harness (deterministic)
- [ ] Agent model wiring
- [x] No secrets in frontend

## Risk engine / fusion (Phase 7)

- [x] Detection evidence normalization (`DetectionEvidence`)
- [x] Fusion of detector evidence (`DetectionFusionEngine`)
- [x] Unified security assessment (`UnifiedSecurityAssessment`)
- [x] Risk score aggregation (0–100, deterministic)
- [x] Configurable risk weights (`RiskWeights` / `risk_config.py`)
- [x] Severity mapping from risk score
- [x] Explainable risk factors
- [x] Fusion + risk unit tests
- [x] `docs/security/fusion-and-risk.md`
- [x] Policy actions (ALLOW / REVIEW / BLOCK) — Phase 8 decision layer
- [ ] External enforcement of policy decisions — later

## Policy engine (Phase 8)

- [x] Policy model (`EnforcementPolicy`, `PolicyDecision`)
- [x] Policy configuration (AEGIS-PROMPT-INJECTION v1.0 thresholds)
- [x] Deterministic policy evaluation (`evaluate_policy`)
- [x] ALLOW / REVIEW / BLOCK decisions
- [x] Decision explanation + reason codes
- [x] Policy versioning on every decision
- [x] Uncertainty handling (never silent ALLOW)
- [x] Conflict handling (ALLOW → REVIEW)
- [x] High-impact category elevation (explicit threshold)
- [x] Decision / audit metadata
- [x] Policy engine unit tests
- [x] `docs/security/policy-engine.md`
- [ ] Actual external enforcement (HTTP / agent / tools) — later
- [ ] Persist decisions on Scan API — later

## Policy engine (legacy checklist items)

- [x] Policy definitions (enforcement policy — analysis policy exists in Phase 6)
- [x] Context-aware policy evaluation (risk / conflict / uncertainty / high-impact)
- [x] Fail-safe defaults for sensitive actions (uncertainty/conflict → REVIEW; invalid policy → error)

## Agent workflow (Phase 9)

- [x] Agent security state (`AgentSecurityState`)
- [x] Agent context / trust level model
- [x] Security-aware agent workflow (`AgentSecurityWorkflow`)
- [x] Action proposal model (`AgentActionProposal`)
- [x] Action risk classification (LOW/MEDIUM/HIGH/CRITICAL)
- [x] Agent state transitions (no EXECUTED)
- [x] Security decision propagation (consumes PolicyDecision)
- [x] Intent/action mismatch hook
- [x] Agent audit metadata
- [x] Agent security unit tests
- [x] `docs/security/agentic-workflow.md`
- [x] Protected agent *execution* path — Phase 10 tool firewall + mock executor
- [ ] Instruction / data separation in prompts — later
- [ ] Demo agent scenario for hackathon — later

## Tool firewall (Phase 10)

- [x] Tool definitions + static registry (allowlist)
- [x] Tool authorization (permissions + target scope)
- [x] Parameter / schema validation
- [x] Intent alignment enforcement
- [x] Prompt-injection security-state enforcement
- [x] Approval requirement metadata (trusted context only)
- [x] Replay protection (in-memory action_id registry)
- [x] Tool firewall decisions (ALLOW / DENY / REQUIRES_APPROVAL)
- [x] Sandboxed/mock tool executor (no real side effects)
- [x] Tool execution audit metadata + untrusted output marking
- [x] Tool firewall unit + E2E tests
- [x] `docs/security/tool-firewall.md`
- [ ] Real external tools / MCP — later
- [ ] Demo tools wired to UI — later

## Evaluation / red-team (Phase 11)

- [x] Versioned dataset (`aegis_security_eval_v1`, 145+)
- [x] 9 attack categories + benign
- [x] Indirect / encoded / multi-step / tool-abuse cases
- [x] Privilege escalation / approval / replay / parameter cases
- [x] Authorization matrix evaluation
- [x] Security invariants
- [x] End-to-end offline evaluation runner (`python -m app.evaluation.runner --full`)
- [x] Detection / policy / tool firewall metrics
- [x] FP / FN analysis in report
- [x] Latency measurements (offline)
- [x] Offline evaluation (default CI-safe)
- [x] Optional live Groq gate preserved (not required for pytest)
- [x] Regression: Phase 5–10 suites retained
- [x] JSON + Markdown reports under `backend/evaluation/results/`
- [x] `docs/security/evaluation-and-red-team.md`
- [ ] Production monitoring — later
- [ ] Live model benchmarking as default CI — not required

## Frontend

- [x] Next.js + TypeScript foundation
- [x] Landing page (brand + product description) → redirects to dashboard
- [x] Frontend `.env.example`
- [x] Frontend Dockerfile
- [x] Dashboard shell + security overview (`/dashboard`)
- [x] Live scan / inspect UI (`/scanner`)
- [x] Metrics visualizations from evaluation API (real data only)
- [x] Attack playground (`/attack-playground`)
- [x] Agent runtime simulation UI (`/agent-runtime`)
- [x] Evaluation + detection analytics pages
- [x] Policy center (read-only) + tool security viewer
- [x] Audit viewer (`/audit` connected to `GET /api/v1/audit`)
- [x] API client layer (`frontend/lib/api`)
- [x] Persistent security events + inspect → Scan association
- [x] Dashboard activity from security events
- [ ] Production authentication / hosted demo

## Attack playground

- [x] Safe demo attack catalog UI (backend scenarios)
- [x] Side-by-side evidence / pipeline demonstrations
- [x] Dataset-backed example payloads
- [x] Run through Agent → Phase 14 runtime integration
- [ ] File upload UI for document injection (optional later)

## Agent runtime (Phase 14)

- [x] Agent session + trust-aware context
- [x] Deterministic planner + scenario library
- [x] Reuses Agent Security Workflow + Tool Firewall + mock executor
- [x] `GET /api/v1/agent/scenarios` + `POST /api/v1/agent/simulate`
- [x] Bound approval + replay + session limits
- [x] Runtime evaluation (separate from Phase 11 F1)
- [x] Docs: `docs/security/agent-runtime.md`

## Phase 15 hardening

- [x] Provider telemetry + failure taxonomy
- [x] Pipeline stage timing on inspect
- [x] REVIEW / UNCERTAIN / conflict analysis (no threshold tuning)
- [x] Red-team corpus v1 + expanded invariants
- [x] `/health` vs `/readiness`; config validation; FAIL_CLOSED mode
- [x] Dashboard providers / performance / review-analysis APIs + UI
- [x] Threat model v2 + incident response docs
- [x] Auth limitation documented (audit was unauthenticated through Phase 16)
- [ ] Production authentication / IdP / OAuth — deferred (Phase 17 is development bearer only)

## Phase 16 authorization

- [x] Principal / permission / tenant model (simulator)
- [x] AuthorizationService fail-closed resolver
- [x] Wired before Tool Firewall (does not replace it)
- [x] BoundApproval principal/tenant binding
- [x] MockToolTransport MCP-ready abstraction (no real MCP)
- [x] `POST /api/v1/auth/authorize` + read-only principal/capability APIs
- [x] `/authorization` console (no grant UI)
- [x] Authz evaluation + INV-19..29
- [x] Docs: authorization / secure-tool-boundary / mcp-readiness

## Phase 17 authentication + Mock MCP

- [x] Development bearer authentication (`app.authentication`)
- [x] Protected audit / dashboard / inspect / agent / auth / mcp APIs
- [x] Endpoint access matrix + tenant-scoped audit
- [x] Frontend Development Authentication (in-memory tokens)
- [x] MCPGateway + MockMCPServer (no real MCP)
- [x] Server allowlist, fingerprints, shadowing, schema validation
- [x] `/mcp-security` console + simulate API
- [x] INV-30..45 + phase17 evaluation
- [x] Docs: authentication / mcp-gateway / mcp-threat-model / mcp-tool-integrity
- [ ] Real MCP networking — NOT STARTED
- [ ] Production OAuth/SSO — NOT STARTED

## Phase 18 hackathon freeze

- [x] Architecture frozen (no Phase 19 scope)
- [x] Full backend/frontend validation
- [x] E2E demo smoke suite
- [x] Demo scenario catalog
- [x] Final README + architecture diagram
- [x] Pitch + demo script + submission checklist + RC notes
- [x] Honest evaluation / REVIEW disclosure

## Evaluation

- [x] Dataset directories (`datasets/attacks`, `datasets/benign`)
- [x] Labeled evaluation sets (`aegis_security_eval_v1`)
- [x] Offline evaluation harness (`python -m app.evaluation.runner --full`)
- [x] Confusion / category metrics (dataset-only; not production)
- [x] Phase 14 runtime evaluation (`app.evaluation.runtime_eval`)
- [x] Phase 15 live analysis (`app.evaluation.live_eval`)

## Red teaming

- [x] Versioned red-team case pack (`red_team_v1` metadata flag)
- [ ] Continuous red-team expansion — ongoing
- [ ] Live Groq red-team benchmarking — optional later

- [ ] Red-team protocol document
- [ ] Structured findings log
- [ ] Regression cases from findings

## Documentation

- [x] System architecture document
- [x] Security principles
- [x] Attack taxonomy
- [x] Project checklist
- [x] Architecture updated for Phase 2 implemented vs planned
- [ ] API reference (post-implementation)
- [ ] Demo script / operator guide

## Deployment

- [x] Dockerfiles for backend and frontend
- [x] Docker Compose for local development
- [ ] Production hardening notes
- [ ] Hosted demo deployment

## Demo

- [ ] End-to-end demo path
- [ ] Seeded scenarios
- [ ] Recorded walkthrough (optional)

## Pitch deck

- [ ] Problem / solution slides
- [ ] Architecture diagram slide
- [ ] Live demo plan
- [ ] Differentiator and roadmap

---

**Phase 1 complete when:** foundation, minimal backend health API, frontend landing, Docker skeleton, tests for health/config, and core docs are done — without claiming detection or dashboard capabilities.

**Phase 2 complete when:** scan domain models, Alembic migration, scan CRUD API, hashing, service layer, and tests pass — without claiming detection or scoring capabilities.

**Phase 3 complete when:** offline normalization/`SecurityInput`, encoding/HTML/prompt flags, chunking abstraction, limits, docs, and tests pass — without Groq or detection verdicts.

**Phase 4 complete when:** modular deterministic detectors, `DetectionReport`, taxonomy alignment, FP + multi-signal tests, and docs pass — without Groq, risk scoring, or policy decisions.

**Phase 5 complete when:** Groq Prompt Guard integration, provider abstraction, mocked tests, optional live gate, and docs pass — without GPT-OSS, fusion, risk, or policy.

**Phase 6 complete when:** semantic analyzer + versioned policy + mocked tests + offline eval harness pass — without fusion, risk scoring, or ALLOW/BLOCK.

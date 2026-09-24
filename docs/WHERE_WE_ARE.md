# AegisAI — Where We Are

**Last updated:** 2026-09-24  
**Current checkpoint:** Phase 9 complete → **next = Phase 10 (Tool Firewall)**  
**Product:** AegisAI — Agentic Prompt Injection Firewall (ET AI Hackathon)

Use this file as the single orientation doc: what is done, what we use, where the code lives, and what comes next.

For granular checkboxes see [`PROJECT_CHECKLIST.md`](./PROJECT_CHECKLIST.md).  
For pipeline diagrams see [`architecture/system-architecture.md`](./architecture/system-architecture.md).

---

## One-line status

```text
Evidence → Fusion → Deterministic Risk   ✅ DONE
Policy → ALLOW / REVIEW / BLOCK          ✅ DONE (decision only)
Agent state + action proposals           ✅ DONE (no execution)
Tool Firewall + execution                ⬜ Phase 10
```

Detection answers “what evidence do we have?”  
Risk answers “how risky is this?”  
Policy answers “what should AegisAI decide?”  
Agent answers “what action is proposed, and at what action-risk?”  
**Tool Firewall (not yet built)** independently authorizes/denies actual tool calls.

---

## Design principles (do not break)

1. **Layered defenses** — rules + Prompt Guard + Safeguard complement each other (OWASP-aligned).
2. **Models are evidence, not authority** — Prompt Guard / Safeguard never alone decide ALLOW/BLOCK.
3. **Critical enforcement stays outside the LLM** — risk weights and (future) policy are app config.
4. **Never fail open to BENIGN** when detectors are unavailable → `UNCERTAIN` + `uncertainty=true`.
5. **Do not average detector confidences** — different calibrations; keep source scores and derive AegisAI risk separately.
6. **Unified ATTACK ≠ policy BLOCK** — fusion aggregates evidence; Phase 8 owns the action.

---

## Current pipeline

```text
                 UNTRUSTED INPUT
                        │
                        ▼
               ┌─────────────────┐
               │  Normalization  │   Phase 3 ✅
               └────────┬────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
       RULES       PROMPT GUARD    SAFEGUARD
      Phase 4 ✅    Phase 5 ✅     Phase 6 ✅
          │             │             │
          └─────────────┼─────────────┘
                        ▼
                    FUSION              Phase 7 ✅
                        │
                        ▼
              UNIFIED ASSESSMENT
                        │
                        ▼
                  RISK ENGINE           Phase 7 ✅
                        │
                 0–100 + severity
                        │
                        ▼
                 POLICY ENGINE          Phase 8 ✅
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
            ALLOW     REVIEW     BLOCK
                        │
                        ▼
              AGENT SECURITY STATE  Phase 9 ✅
                        │
                        ▼
               ACTION PROPOSAL
                        │
                        ▼
            READY_FOR_TOOL_GUARD
                        │
                 ─── CURRENT STOP ───
              (no tool execution yet)
                        │
                        ▼
              ╔═══════════════════╗
              ║  PHASE 10 (NEXT)  ║
              ║  TOOL FIREWALL    ║
              ╚═══════════════════╝
```

Scan API (`POST /api/v1/scans`) stores scan **metadata** today. Detection + policy run via `SecurityDetectionService`; agent workflow via `AgentSecurityWorkflow` / `AgentSecurityService`.

---

## Phases completed (1–9)

| Phase | Name | Outcome |
|-------|------|---------|
| **1** | Foundation | Monorepo, FastAPI, health, Docker Compose, docs, config |
| **2** | Scan / DB / API | Scan domain, Postgres models, Alembic, `POST/GET /api/v1/scans` |
| **3** | Normalization | Unicode/encoding/HTML/chunking → `SecurityInput` |
| **4** | Deterministic detection | 9 taxonomy detectors → `DetectionReport` (evidence only) |
| **5** | Prompt Guard | Groq Llama Prompt Guard 2 (86M) → `PromptGuardResult` |
| **6** | Semantic analysis | GPT-OSS-Safeguard 20B + policy → `SemanticSecurityAssessment` |
| **7** | Fusion + risk | Evidence fusion → `UnifiedSecurityAssessment` + 0–100 risk |
| **8** | Policy engine | `evaluate_policy` → ALLOW / REVIEW / BLOCK (`PolicyDecision`) |
| **9** | Agent workflow | State + action proposals → `READY_FOR_TOOL_GUARD` (no execution) |

### Intentionally not done yet

- Tool firewall / actual tool execution
- External HTTP enforcement
- Wiring decisions into Scan API persistence
- Dashboard / attack playground
- Multimodal (PDF / DOCX / OCR / images)

---

## What we use (stack & models)

### Stack

| Layer | Choice |
|-------|--------|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy 2.x, Alembic |
| DB | PostgreSQL (Docker); tests often SQLite |
| Frontend | Next.js + TypeScript (landing foundation; no security UI yet) |
| Tests | pytest (Phase 8 checkpoint — see test counts below) |
| Secrets | `backend/.env` only (not monorepo root for backend runtime) |

### Groq models

| Role | Model | Phase |
|------|-------|-------|
| Prompt-attack classifier | `meta-llama/llama-prompt-guard-2-86m` | 5 |
| Policy-based semantic safety | `openai/gpt-oss-safeguard-20b` | 6 |
| Agent (planned) | `openai/gpt-oss-20b` | later |

### Attack taxonomy (canonical)

```text
instruction_override
role_change
secret_extraction
tool_abuse
credential_theft
context_poisoning
multi_step_jailbreak
encoded_instruction
indirect_prompt_injection
```

High-impact for risk bonus: `credential_theft`, `secret_extraction`, `tool_abuse`.

### Risk defaults (Phase 7)

| Factor | Points |
|--------|--------|
| Deterministic attack | +25 |
| Prompt Guard attack | +25 |
| Semantic attack | +30 |
| Detector agreement (≥2) | +10 |
| Multiple categories | +5 |
| High-impact category | +5 |

Severity from score: `0–19 LOW` · `20–49 MEDIUM` · `50–74 HIGH` · `75–100 CRITICAL`.

---

## Key code map

| Area | Path |
|------|------|
| App entry | `backend/app/main.py` |
| Config | `backend/app/core/config.py`, `backend/.env` |
| Normalization | `backend/app/services/input_normalization.py` |
| Rules engine | `backend/app/security/detectors/` |
| Prompt Guard | `backend/app/security/prompt_guard_detector.py` |
| Semantic / Safeguard | `backend/app/security/semantic_analyzer.py` |
| Analysis policy (Safeguard) | `backend/app/security/policies/prompt_injection_policy.py` |
| Fusion | `backend/app/security/fusion.py`, `fusion_types.py` |
| Risk | `backend/app/security/risk_engine.py`, `risk_config.py` |
| Policy | `backend/app/security/policy_engine.py`, `policies/policy_types.py` |
| Agent workflow | `backend/app/agents/` |
| Pipeline orchestration | `backend/app/services/security_detection.py` |
| Agent bridge | `backend/app/services/agent_security.py` |
| Groq client | `backend/app/integrations/groq/` |
| Fixtures | `datasets/attacks/`, `datasets/benign/` |

### Security docs

| Doc | Topic |
|-----|-------|
| [`security/input-normalization.md`](./security/input-normalization.md) | Phase 3 |
| [`security/deterministic-detection.md`](./security/deterministic-detection.md) | Phase 4 |
| [`security/attack-taxonomy.md`](./security/attack-taxonomy.md) | Categories |
| [`security/prompt-guard.md`](./security/prompt-guard.md) | Phase 5 |
| [`security/semantic-analysis.md`](./security/semantic-analysis.md) | Phase 6 |
| [`security/security-policy.md`](./security/security-policy.md) | AEGIS-PROMPT-INJECTION |
| [`security/fusion-and-risk.md`](./security/fusion-and-risk.md) | Phase 7 |
| [`security/policy-engine.md`](./security/policy-engine.md) | Phase 8 |
| [`security/agentic-workflow.md`](./security/agentic-workflow.md) | Phase 9 |

---

## Tests checkpoint (Phase 9)

```text
Prior tests (through Phase 8)   179
Phase 9 agent tests              see pytest
────────────────────────────────────
Total                           see pytest -q
```

Important covered behaviors:

- All detectors ATTACK → high/critical + agreement factor  
- Conflict (e.g. Rules+PG ATTACK, Semantic BENIGN) → `ATTACK`, `conflict=true`  
- Provider failure (PG+Semantic unavailable, rules no match) → `UNCERTAIN` → policy **REVIEW**  
- LOW→ALLOW, MEDIUM/HIGH→REVIEW, CRITICAL→BLOCK  
- Conflict/uncertainty never silent ALLOW  
- Risk capped 0–100; policy pure (no Groq)  

Run:

```bash
cd backend
python -m pytest -q
```

---

## Demo / story talking points

**Wrong story:** “Prompt Guard said attack, so we block.”

**Right story:**

```text
Rules + Prompt Guard + Safeguard
        → evidence
        → fusion (provenance, conflict, uncertainty)
        → AegisAI risk score + factors
        → (Phase 8) policy decides ALLOW / REVIEW / BLOCK
```

Example conflict:

```text
Rules ATTACK + Prompt Guard ATTACK + Semantic BENIGN
→ unified ATTACK, conflict=true, elevated risk
→ Phase 8 policy may REVIEW instead of auto-BLOCK
```

Example failure:

```text
Rules no match + both AI unavailable
→ UNCERTAIN (not BENIGN)
→ Phase 8 must not treat as safe by default
```

---

## Roadmap (planned)

| Phase | Focus |
|-------|--------|
| **8** | Policy Engine — ✅ COMPLETE (decision only) |
| **9** | Agentic workflow — ✅ COMPLETE (proposals only) |
| **10** | Tool Firewall (independent of LLM / upstream label) |
| **11** | Evaluation expansion |
| **12** | Dashboard |
| **13** | Attack Playground |
| **14** | PDF / DOCX / Image / OCR |
| **15** | Red team + hardening |
| **16** | Demo + pitch |
| **17** | Final audit |

### Phase 8 defaults (implemented)

```text
LOW (0–19)        → ALLOW
MEDIUM (20–49)    → REVIEW
HIGH (50–74)      → REVIEW
CRITICAL (75–100) → BLOCK
conflict / uncertainty preventing ALLOW → REVIEW
high-impact + risk >= 50 → BLOCK
```

See [`security/policy-engine.md`](./security/policy-engine.md).

---

## Env reminder

- Backend secrets: **`backend/.env`** (see `backend/.env.example`)
- Frontend: `frontend/.env.example` only (no secrets)
- Monorepo root `.env` is **not** what the FastAPI app loads

---

## Quick “are we stuck?” checklist

| Question | Answer |
|----------|--------|
| Can we normalize untrusted text? | Yes |
| Can we detect with rules? | Yes |
| Can we call Prompt Guard? | Yes |
| Can we run Safeguard semantic analysis? | Yes |
| Can we fuse + score risk? | Yes |
| Can we decide ALLOW/REVIEW/BLOCK? | **Yes (in-memory)** |
| Can we propose agent actions? | **Yes (no execution)** |
| Is the decision enforced externally? | **No — later** |
| Does Scan API persist the decision? | **Not yet** |
| Are tools firewalled / executed? | **No — Phase 10** |

---

*Update this file when a phase finishes or the roadmap changes.*

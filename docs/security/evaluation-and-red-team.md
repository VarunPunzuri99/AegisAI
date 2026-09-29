# Security Evaluation & Red-Team Regression

**Phase:** 11  
**Status:** Implemented (offline-first; live Groq optional / not required for CI)

Phase 11 **measures** the existing AegisAI chain. It does not redesign detectors, risk weights, or policy thresholds to inflate scores.

```text
EvaluationCase
  → Normalization → Deterministic → (offline AI stubs)
  → Fusion → Risk → Policy → Agent → Tool Firewall → Mock Executor
  → CaseResult → Metrics → Report
```

> Evaluation dataset only. **Not a production security guarantee.**

---

## Dataset: `aegis_security_eval_v1`

Location: `app/evaluation/dataset_v1.py` (versioned, stable `case_id`s).

| Bucket | Minimum |
|--------|--------:|
| benign | 20+ |
| instruction_override | 20+ |
| each other taxonomy category | 15+ |
| tool / approval / replay / privilege | included |
| **Total** | **145+** |

Categories cover the AegisAI taxonomy plus `benign`, plus tool-auth suites.

Red-team pack: cases flagged `metadata.red_team_v1` (indirect, tool abuse, credential theft, encoded, approval bypass, replay, privilege escalation, parameter attacks).

No API keys, customer data, or real credentials.

---

## Offline vs live

| Mode | Behavior |
|------|----------|
| **offline (default)** | Real normalization + deterministic rules; Prompt Guard / Safeguard **stubs**; real fusion/risk/policy/agent/firewall |
| **live** | Optional via existing `RUN_GROQ_INTEGRATION_TEST` patterns — **not** required for `pytest -q` |

Detection metrics for the detection suite score the **real deterministic detector** (honest FN/FP), not stubbed AI labels.

---

## Metrics

**Detection:** TP/TN/FP/FN → precision, recall, F1, FPR, FNR, accuracy (overall + per category).

**Policy:** confusion matrix ALLOW / REVIEW / BLOCK.

**Tool firewall (named rates):**

- unauthorized action block rate  
- intent mismatch block rate  
- privilege escalation block rate  
- approval bypass prevention rate  
- replay prevention rate  
- invalid parameter block rate  

---

## Authorization matrix

`app/evaluation/auth_matrix.py` — Phase 10 permissions × tools (public-reader, private-reader, writer, email-user, delete). Automated; fail if matrix drifts.

---

## Security invariants

`app/evaluation/invariants.py` — must never fail (BLOCK⇒no tool, unknown tool, missing permission, bad params, intent mismatch, unapproved high-risk, replay, approval-text non-trust, tool output untrusted, missing context, executor rejects unauthorized, BLOCK beats approval).

---

## Commands

```bash
cd backend
python -m app.evaluation.runner          # Phase 6 deterministic fixtures
python -m app.evaluation.runner --full   # Phase 11 full offline eval + reports
pytest -q
```

Reports: `backend/evaluation/results/aegis_eval_v1.json` and `.md`.

---

## Limitations

- Offline mode does **not** measure live Prompt Guard / Safeguard accuracy.
- False negatives on semantic-only attacks under offline detection are expected and documented as backlog for hardening — **do not** silently retune thresholds in Phase 11.
- Mock executor only; no MCP / real tools.

---

## Code map

| Module | Role |
|--------|------|
| `evaluation/dataset_v1.py` | Versioned cases |
| `evaluation/chain.py` | Offline chain runner |
| `evaluation/metrics.py` | Detection / policy / tool metrics |
| `evaluation/auth_matrix.py` | Permission matrix |
| `evaluation/invariants.py` | Hard invariants |
| `evaluation/report.py` | JSON + Markdown reports |
| `evaluation/runner.py` | CLI entry (`--full`) |

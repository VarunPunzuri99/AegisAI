# Fusion and Risk Engine

**Phase:** 7  
**Status:** Implemented (evidence + risk only — no ALLOW/BLOCK)

AegisAI does not treat any single detector as the final security policy. Prompt Guard, deterministic rules, and the Safeguard semantic analyzer are **evidence sources**. Fusion normalizes that evidence; the risk engine turns it into an explainable 0–100 score.

---

## Why fusion is required

Each detector answers a different question:

| Source | Role |
|--------|------|
| Deterministic rules | Pattern / structure matches with rule IDs |
| Prompt Guard | Specialized prompt-attack classifier (score + label) |
| Semantic (Safeguard) | Policy-grounded intent / target / impact assessment |

Blindly following one model (“Prompt Guard said attack → BLOCK”) would discard disagreement, hide calibration differences, and fail open when a provider is down. Fusion preserves provenance and surfaces conflict and uncertainty for a later policy phase.

---

## Pipeline position

```text
Normalization
      ↓
Deterministic Rules
      ↓
Prompt Guard
      ↓
Semantic Analyzer
      ↓
     FUSION  →  Unified Detection Evidence
      ↓
   RISK ENGINE  →  Risk Score + Severity + Factors
```

Phase 7 **stops here**. Policy enforcement (ALLOW / BLOCK / REVIEW / SANITIZE) is not implemented.

---

## Evidence model

`DetectionEvidence` (`app/security/fusion_types.py`) normalizes each source:

- `source`: `RULES` | `PROMPT_GUARD` | `SEMANTIC`
- `available`: whether the detector produced usable output
- `label`: `ATTACK` | `BENIGN` | `UNCERTAIN` | `UNAVAILABLE`
- `attack_types`, `confidence` / `score`, `severity`, `evidence`, `metadata`, `error_code`

Unavailable detectors are **never** rewritten as BENIGN.

`UnifiedSecurityAssessment` aggregates:

- unified `label`, `attack_types`
- `conflict`, `uncertainty`
- source-specific `rule_evidence_strength`, `prompt_guard_score`, `semantic_confidence` (never averaged)
- `risk_score`, `severity`, `risk_factors`
- `detector_results` for UI / audit provenance

---

## How labels are fused

1. If **any available** source is `ATTACK` → unified `ATTACK` (attack evidence is kept).
2. Else if available sources are all `BENIGN` **and** invoked AI detectors did not fail → `BENIGN`.
3. Else → `UNCERTAIN` (including: no usable detectors; only uncertain labels; **rules no-match + invoked AI unavailable**).

### Conflict

`conflict = true` when at least one available source is ATTACK and at least one is BENIGN.

Example:

```text
Rules        = ATTACK
Prompt Guard = ATTACK
Semantic     = BENIGN
→ label = ATTACK, conflict = true
```

### Provider failure

```text
Rules        = no match (BENIGN)
Prompt Guard = unavailable (invoked, error)
Semantic     = unavailable (invoked, error)
→ label = UNCERTAIN, uncertainty = true
```

Not BENIGN. Phase 8 can use `uncertainty` for fail-safe policy.

```text
Prompt Guard unavailable + Semantic ATTACK → label = ATTACK (semantic evidence retained)
```

---

## Why confidence is not averaged

Detector scores mean different things (rule confidence vs Prompt Guard probability vs Safeguard policy confidence). Averaging them invents a false precision.

AegisAI keeps:

- `prompt_guard_score`
- `semantic_confidence`
- `rule_evidence_strength`

and computes a separate **risk_score** owned by the application.

---

## Risk scoring model

Configured in `app/security/risk_config.py` (`RiskWeights`). Default point contributions:

| Factor | Points |
|--------|--------|
| Strong deterministic rule attack | +25 |
| Prompt Guard attack | +25 |
| Semantic attack | +30 |
| ≥2 independent detectors agree on ATTACK | +10 |
| ≥2 attack categories | +5 |
| High-impact category (`credential_theft`, `secret_extraction`, `tool_abuse`) | +5 |

Score is clamped to **0–100**. Same inputs → same score (no LLM in the risk engine).

### Severity (from risk score)

| Score | Severity |
|-------|----------|
| 0–19 | LOW |
| 20–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

Semantic severity remains evidence only; **final** severity comes from the risk score.

### Risk factors

Each contribution is explainable, e.g.:

```json
{
  "factor": "semantic_attack",
  "points": 30,
  "reason": "Semantic analyzer classified the content as an attack."
}
```

No chain-of-thought or model internals are exposed.

---

## Example flows

### Attack (agreement)

```text
Rules ATTACK + Prompt Guard ATTACK + Semantic ATTACK
→ label ATTACK, conflict false
→ score ≈ 90 (25+25+30+10), severity CRITICAL
→ detector_agreement factor present
```

### Benign

```text
All available sources BENIGN
→ label BENIGN, score 0, severity LOW, no attack types
```

### Conflict

```text
Rules/Prompt Guard ATTACK, Semantic BENIGN
→ label ATTACK, conflict true, attack types preserved
```

---

## Security constraints

- Risk weights are application configuration — never modified by model output.
- No ALLOW/BLOCK/REVIEW decisions in this layer.
- No tool or agent execution.
- Do not log API keys or raw sensitive prompts in fusion/risk paths.
- Unavailable / uncertain states are explicit for fail-safe policy later.

---

## Code map

| Module | Role |
|--------|------|
| `app/security/fusion_types.py` | Evidence + unified assessment types |
| `app/security/fusion.py` | `DetectionFusionEngine` |
| `app/security/risk_config.py` | Weights + severity thresholds |
| `app/security/risk_engine.py` | Deterministic scoring |
| `app/services/security_detection.py` | Pipeline → fusion → unified assessment |

Tests: `tests/test_security_fusion.py`, `tests/test_risk_engine.py`.

# Policy Engine

**Phase:** 8  
**Status:** Implemented (decision only — no external enforcement)

The Policy Engine answers:

> Given the unified security evidence and calculated risk, what security decision should AegisAI make?

It does **not** detect attacks, recalculate risk, call an LLM, or enforce anything externally.

---

## Separation of concerns

| Layer | Question | Owner |
|-------|----------|--------|
| Detection | What evidence exists? | Rules / Prompt Guard / Safeguard |
| Fusion | How do we combine evidence? | `DetectionFusionEngine` |
| Risk | How risky is this (0–100)? | `RiskEngine` |
| **Policy** | **What should we do?** | **`evaluate_policy`** |
| Enforcement (later) | How do we apply the decision? | PEP / agents / tools |

```text
Detection → Fusion → Risk → Policy → ALLOW | REVIEW | BLOCK
                                      (decision only in Phase 8)
```

---

## Policy identity

```text
policy_id:      AEGIS-PROMPT-INJECTION
policy_version: 1.0
```

Same identity as the Safeguard analysis policy document. Every `PolicyDecision` includes both fields. Material behavior changes must bump the version.

Untrusted input and model output **cannot** change policy ID, version, or thresholds.

---

## Default decision rules

| Severity band | Risk score | Decision |
|---------------|------------|----------|
| LOW | 0–19 | **ALLOW** |
| MEDIUM | 20–49 | **REVIEW** |
| HIGH | 50–74 | **REVIEW** |
| CRITICAL | 75–100 | **BLOCK** |

Configured in `EnforcementPolicy` (`allow_max=19`, `review_max=74`, `block_min=75`).

### Why HIGH is REVIEW, not BLOCK

Elevated risk is not always certain malice. REVIEW holds uncertain, conflicting, or medium/high-risk cases for a later human/agent gate without pretending every suspicious case is definitively malicious.

---

## Conflict handling

If `conflict=true` and the base decision would be **ALLOW**, policy upgrades to **REVIEW**.

Example:

```text
risk=15, severity=LOW, conflict=true
→ REVIEW (not ALLOW)
```

Attack evidence and conflict flags remain on the assessment and decision.

---

## Uncertainty handling

Uncertainty (including unavailable AI detectors) **never** becomes ALLOW when the uncertain-forces-review flag is enabled (default).

```text
Rules = no match
Prompt Guard = unavailable
Semantic = unavailable
→ fusion UNCERTAIN → policy REVIEW
```

```text
Semantic ATTACK + Prompt Guard unavailable + HIGH risk
→ REVIEW (evidence retained; AI unavailable recorded)
```

---

## High-impact attack types

Uses taxonomy already present on the fused assessment:

```text
credential_theft
secret_extraction
tool_abuse
```

**Explicit rule** (not a hidden exception):

```text
high-impact category present
AND risk_score >= high_impact_block_min_risk (default 50)
→ BLOCK
```

So HIGH risk (50–74) with tool abuse becomes BLOCK; without high-impact it stays REVIEW.

---

## Evaluation order

```text
1. Validate policy (enabled, bands, id/version)
2. Validate assessment (risk_score in 0–100)
3. Inspect uncertainty / AI availability
4. Inspect conflict
5. Map risk score → base decision
6. Apply high-impact elevation
7. Upgrade ALLOW → REVIEW for conflict/uncertainty
8. Emit reason codes + explanation + audit metadata
```

Entry point:

```python
from app.security.policy_engine import evaluate_policy

decision = evaluate_policy(assessment, policy=None)  # default policy
```

Pure function: no HTTP, DB, Groq, time, or randomness.

---

## PolicyDecision fields

```text
decision
policy_id / policy_version
risk_score / severity
attack_types
conflict / uncertainty
reason_codes
explanation
audit          # structured, no raw prompts
```

### Reason codes (examples)

```text
LOW_RISK | MEDIUM_RISK | HIGH_RISK | CRITICAL_RISK
DETECTOR_CONFLICT | DETECTOR_UNCERTAIN | AI_PROVIDER_UNAVAILABLE
HIGH_IMPACT_ATTACK | MULTIPLE_DETECTORS_AGREE | MULTIPLE_ATTACK_CATEGORIES
POLICY_DISABLED | POLICY_INVALID | ASSESSMENT_INVALID
```

Explanations are short, deterministic strings (no chain-of-thought).

---

## Failure behavior

| Failure | Behavior |
|---------|----------|
| Policy disabled / corrupt thresholds | `PolicyError` (fail-closed — not ALLOW) |
| Invalid risk_score (&lt;0 or &gt;100) | `PolicyError` |
| Security uncertainty | REVIEW (default) |

`SecurityDecision.ERROR` exists for infrastructure failure representation; the pure evaluator raises `PolicyError` so callers cannot mistake a broken policy for ALLOW.

---

## Example decisions

**Benign**

```text
risk=0, BENIGN → ALLOW
```

**Critical**

```text
risk=91, CRITICAL, credential_theft → BLOCK
reason: CRITICAL_RISK, HIGH_IMPACT_ATTACK
```

**Conflict at low score**

```text
risk=15, conflict=true → REVIEW
```

**Provider failure**

```text
UNCERTAIN, risk=10 → REVIEW
```

---

## Integration

`SecurityDetectionService.analyze()`:

```text
detectors → fusion → UnifiedSecurityAssessment
                  → evaluate_policy → PolicyDecision
```

Result exposes both `unified` and `policy_decision`. Metadata includes `decision`, `policy_id`, `policy_version`, `reason_codes`.

**Not implemented in Phase 8:** rejecting HTTP requests, stopping agents, denying tools, notifications, or Scan API persistence of decisions.

---

## Code map

| Module | Role |
|--------|------|
| `app/security/policies/policy_types.py` | `EnforcementPolicy`, `PolicyDecision`, reason codes |
| `app/security/policy_engine.py` | `evaluate_policy` |
| `app/services/security_detection.py` | Pipeline wiring |
| `tests/test_policy_engine.py` | Unit tests |

Analysis policy text for Safeguard remains in `prompt_injection_policy.py` (assessment guidance, not enforcement).

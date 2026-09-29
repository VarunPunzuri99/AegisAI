# Phase 15 — Production Hardening Notes

## What Phase 15 is

Measurement, observability, diagnostics, and documentation.
**Not** threshold tuning, dataset mutation, MCP, or real side effects.

## Implemented

| Area | Status |
| --- | --- |
| Provider telemetry registry | IMPLEMENTED |
| Pipeline stage timing on inspect | IMPLEMENTED |
| Provider failure taxonomy | IMPLEMENTED |
| Bounded retries (max 2, exp backoff; timeout ≤1 retry) | IMPLEMENTED |
| EVALUATION_TIMEOUT_SECONDS distinct from prod timeouts | IMPLEMENTED |
| Observed provider health (CONFIGURED ≠ healthy) | IMPLEMENTED |
| REVIEW / UNCERTAIN / conflict analysis | IMPLEMENTED (from live eval JSON) |
| FP/FN investigation docs | DOCUMENTED |
| Live eval analysis module | IMPLEMENTED |
| Reproducibility metadata | IMPLEMENTED |
| Red-team corpus v1 | IMPLEMENTED |
| Expanded security invariants | IMPLEMENTED |
| Persistence secret-leak tests | IMPLEMENTED |
| Dashboard providers / performance / review-analysis APIs | IMPLEMENTED |
| `/health` vs `/readiness` | IMPLEMENTED |
| Config validation | IMPLEMENTED |
| FAIL_CLOSED security mode | IMPLEMENTED |
| Threat model v2 | DOCUMENTED |
| Incident response | DOCUMENTED |
| Auth limitation warning | DOCUMENTED |
| Adaptive Safeguard routing | DOCUMENTED ONLY (not enabled) |

## Explicit non-claims

- Phase 15 does **not** claim latency improved vs Phase 11 live baseline.
- Phase 15 does **not** change risk weights or policy thresholds.
- Phase 15 does **not** convert UNCERTAIN → BENIGN.
- Phase 15 does **not** make the product production-ready merely because tests pass.

## Phase 11 live baseline (preserved)

```text
F1 0.9706 | Precision 0.9925 | Recall 0.9496 | FPR 0.0400
Fusion: ATTACK 134, BENIGN 0, UNCERTAIN 35, conflicts 79
Policy: ALLOW 13, REVIEW 144, BLOCK 26
Expected BLOCK→BLOCK 26 | BLOCK→REVIEW 116
FP: BN-LEGIT-014
FN: RC-013, SE-010, TA-008, JB-001, JB-009, EN-012, II-014
PG median~377ms p95~473ms | Safeguard median~5882ms p95~9217ms
```

## Dependency audit (Phase 15)

Inspected `backend` requirements and `frontend/package.json`.

- No automatic major upgrades performed (risk of breaking security tests).
- Keep Groq / FastAPI / Next pinned via lockfiles.
- Recommendation: periodic `pip-audit` / `npm audit` in CI (NOT IMPLEMENTED as gate).

## Authorization

```text
STATUS: DOCUMENTED limitation
Audit + dashboard diagnostics = no authn/authz in this build.
Do not expose beyond trusted localhost until auth is added.
```

## Recommended next phase (NOT STARTED)

Possible Phase 16 themes (choose deliberately):

1. Authn/authz for audit/dashboard
2. Adaptive Safeguard routing **with its own eval**
3. MCP-style tool surface behind existing firewall
4. Distributed replay / durable provider metrics

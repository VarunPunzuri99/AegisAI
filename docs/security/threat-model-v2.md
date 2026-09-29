# Threat Model v2 — AegisAI

**Status:** Phase 15 documentation  
**Scope:** Agentic prompt injection firewall (simulation + mock tools)

This document maps attacks to trust boundaries, existing controls, residual risk,
and test coverage. It does **not** claim production readiness.

## Trust boundaries

| Boundary | Description |
| --- | --- |
| Untrusted input | User text, documents, web, OCR, API payloads, tool output |
| Application control plane | Policy, risk weights, tool allowlist, approvals, security mode |
| Model evidence layer | Prompt Guard / Safeguard — evidence only, never sole authority |
| Tool execution boundary | Tool Firewall → Mock Executor (no real side effects in current build) |
| Persistence | SecurityEvent / Audit — hash + metadata only |

## Attack catalog

| Attack | Trust boundary | Existing control | Residual risk | Test coverage |
| --- | --- | --- | --- | --- |
| Prompt injection (direct) | Untrusted input → detectors | Rules + PG + Safeguard + fusion + policy | Semantic misses → UNCERTAIN/REVIEW | Phase 11 dataset, playground |
| Indirect injection | Document/web/email as DATA | Source typing + UNTRUSTED context + policy | Stub vs live PG gaps | Phase 14 scenarios, RT-IND-* |
| RAG poisoning | Retrieved context | Treat as UNTRUSTED; never SYSTEM | Incomplete retrieval sandbox | Documented; limited fixtures |
| Tool abuse | Agent proposal → firewall | Allowlist, authz, intent, approval | Demo permissions are broad | Tool firewall tests, RT-TOOL-* |
| Privilege escalation | Permissions / roles | Required permissions per tool | No multi-tenant IAM yet | auth_matrix |
| Credential theft | Secrets in prompts | Detectors + fail-closed | Model FN on subtle asks | SE-* cases |
| Data exfiltration | send_email / external tools | HIGH risk + approval + intent | Mock only — real SMTP absent by design | Phase 10/14 |
| Approval bypass | Approval state | Bound approval + firewall | Agent cannot self-approve | approval tests |
| Replay | action_id | ActionReplayRegistry | In-process registry (not distributed) | Replay tests |
| Provider failure | Groq | UNAVAILABLE → uncertainty → REVIEW; never BENIGN | Latency / rate limits | INV-16, live eval |
| Provider compromise | Groq models | Defense in depth; models are evidence | Supply-chain residual | Documented |
| Audit tampering | Persistence | Append-oriented events; no raw prompts | No auth on audit reads (localhost) | Phase 13 + Phase 15 docs |
| Memory/context poisoning | Context items | Trust levels; no UNTRUSTED→TRUSTED | No long-term agent memory yet | INV-17 |
| Denial of service | Inputs / providers | Input limits, timeouts, max retries=2 | Safeguard latency dominates | Timing / readiness |
| Latency exhaustion | Safeguard path | Timeouts; adaptive routing **documented only** | ~6–9s p50–p95 Safeguard | Phase 15 baseline |

## Residual risks (honest)

1. **Audit APIs are unauthenticated** — do not expose to untrusted networks.
2. **Safeguard latency** is the dominant e2e cost; adaptive routing is recommendation-only.
3. **High REVIEW rate** on live eval is often fail-closed uncertainty — not silently BLOCK.
4. **No MCP / real tools** — tool boundary is simulated.
5. **In-process replay / metrics** — not multi-instance durable.

## Related docs

- `docs/security/agent-runtime.md`
- `docs/security/tool-firewall.md`
- `docs/security/incident-response.md`
- `docs/security/evaluation-and-red-team.md`

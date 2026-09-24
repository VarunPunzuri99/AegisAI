# AegisAI Prompt Guard Integration

**Phase 5.** Groq `meta-llama/llama-prompt-guard-2-86m` as an additional detector.

> **Prompt Guard is one detector in a defense-in-depth architecture.**  
> It does **not** make the final ALLOW/BLOCK decision. Deterministic findings and Prompt Guard results remain separate until future fusion/risk/policy phases.

---

## Why Prompt Guard

Deterministic rules catch known patterns. Prompt Guard adds a specialized classifier for prompt injection / jailbreak-style attacks, including paraphrases rules may miss. It complements — not replaces — Phase 4.

---

## Model

| Setting | Default |
|---------|---------|
| `PROMPT_GUARD_MODEL` | `meta-llama/llama-prompt-guard-2-86m` |

Documented Groq context window: **512 tokens**. We chunk with a conservative **character fallback** (`PROMPT_GUARD_MAX_CHUNK_LENGTH`, default 400) until a real tokenizer is wired.

---

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `GROQ_API_KEY` | (empty) | Backend-only secret |
| `PROMPT_GUARD_MODEL` | 86M model id | Model name |
| `PROMPT_GUARD_ENABLED` | `true` | Master switch |
| `PROMPT_GUARD_MODE` | `ALWAYS` | `ALWAYS` or `SUSPICIOUS_ONLY` |
| `PROMPT_GUARD_TIMEOUT_SECONDS` | `10` | Per-request timeout |
| `PROMPT_GUARD_MAX_RETRIES` | `2` | Transient retries only |
| `PROMPT_GUARD_MAX_CHUNK_LENGTH` | `400` | Char fallback chunk size |
| `PROMPT_GUARD_CHUNK_OVERLAP` | `40` | Chunk overlap (chars) |

Never expose `GROQ_API_KEY` to frontend, logs, or API responses.

---

## Provider architecture

```
PromptGuardDetector
        ↓
    GroqClient
        ↓
    Groq chat.completions (SDK)
```

Parsing lives in `app/integrations/groq/prompt_guard.py` so provider formats can change without leaking into routes.

---

## Chunking & aggregation

1. Use `SecurityInput.normalized_text` only (not secrets/metadata).
2. Split via Phase 3 `TextChunker` + character fallback.
3. Classify each chunk.
4. Aggregate with **max `attack_score` across chunks** (heuristic, not optimal).
5. If any chunk is `ATTACK`, overall label is `ATTACK`.

---

## Score / label semantics

Internal labels: `ATTACK` | `BENIGN` | `UNKNOWN`.

`score` is an **`attack_score` in [0, 1]** — a heuristic mapping from model text/JSON, **not** a calibrated probability.

Parse failures → `UNKNOWN` (never silently force ATTACK or BENIGN as a security decision).

---

## Failure behavior

| Condition | Result |
|-----------|--------|
| Missing API key | `available=false`, `MISSING_API_KEY` |
| Timeout / 5xx / connection | retry then `available=false` or chunk `error_code` |
| 429 | respect Retry-After when present; fail gracefully |
| 400 / auth | no aggressive retry |
| Malformed body | `UNKNOWN` |

No circuit breaker in Phase 5.

---

## Execution policy (`PROMPT_GUARD_MODE`)

**ALWAYS** — invoke for every valid analysis (default for demos).

**SUSPICIOUS_ONLY** — invoke when deterministic report has:

- any HIGH/CRITICAL finding, or
- multiple findings, or
- obfuscation / indirect injection / context poisoning findings, or
- `is_attack=true`

---

## Relationship to deterministic detector

```
SecurityDetectionService.analyze()
  → normalize
  → DeterministicDetectionEngine
  → (optional) PromptGuardDetector
  → DetectionPipelineResult { deterministic, prompt_guard }
```

No fusion, risk score, or policy action yet. Scan HTTP API unchanged.

---

## Limitations

- Character chunks ≠ 512 tokens exactly.
- Label/score parsing must tolerate provider format drift.
- Rate limits (RPM/TPM) are surfaced as errors, not queued.
- Not a complete prompt-injection defense alone.

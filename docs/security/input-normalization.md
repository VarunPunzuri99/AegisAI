# AegisAI Input Normalization & Preprocessing

**Phase 3.** Offline security preprocessing. No Groq / Prompt Guard / LLM calls.

> **Normalization and preprocessing do not determine whether an input is malicious.**  
> That decision belongs to the detection layer (planned).

---

## Why normalization is needed

Attackers hide instructions using Unicode tricks, Base64, HTML comments, zero-width characters, mixed encodings, and unusual whitespace. A real firewall first asks *what the input is*, then runs detectors.

Pipeline:

```
RAW INPUT
    → Validation
    → Unicode analysis + NFKC
    → Control-character analysis
    → Whitespace normalization
    → Encoding / obfuscation analysis (bounded)
    → HTML / structure analysis
    → Prompt-boundary indicators
    → Chunk preparation
    → SecurityInput  (in-memory only)
```

Downstream (planned): deterministic detector → Prompt Guard → GPT-OSS-Safeguard → risk engine.

---

## Unicode normalization

We apply **NFKC** (Compatibility Composition).

**Why NFKC:** Compatibility forms (fullwidth letters, ligatures, etc.) collapse toward canonical equivalents so rule and model detectors see more consistent text. Flags still record zero-width, bidi controls, and unusual whitespace on the **original** input so evidence is not discarded.

Suspicious character classes tracked (counts/flags only; not logged as hidden payloads):

- Zero-width characters / joiners
- Bidirectional controls
- Unusual Unicode whitespace
- Other format (`Cf`) characters

---

## Invisible characters

Detection records `zero_width_detected`, `bidi_control_detected`, etc. We do **not** silently strip all of them without flags — analysis preserves evidence for later detectors.

---

## Encoding detection

Bounded, conservative scanners for:

| Pattern | Flag examples |
|---------|----------------|
| Base64-looking runs | `base64_candidate`, `base64_decodable` |
| Hex runs | `hex_candidate` |
| URL encoding (`%20`) | `url_encoding_detected` |
| `\uXXXX` / `\xXX` | `unicode_escape_detected` |

Limits: `MAX_DECODED_LENGTH`, `MAX_DECODE_DEPTH`, `MAX_ENCODED_CANDIDATES`.

Encoded text is **not** automatically malicious. Legitimate Base64 and URLs exist.

Decoded derived text (if any) is size-capped, never executed, and must not be written to logs.

---

## HTML analysis

Static inspection only — **no** JS execution, **no** URL fetching, **no** rendering.

Flags include: `html_detected`, `html_comment_detected`, `hidden_content_detected`, `script_detected`, `iframe_detected`.

---

## Obfuscation indicators

`obfuscation_flags.possible_obfuscation` is a roll-up signal when zero-width, bidi, encodings, or hidden HTML appear. It is **not** a BLOCK decision.

---

## Prompt boundary indicators

Structural markers only: role lines (`SYSTEM:` / `ROLE:`), instruction wording, tool-call-like syntax, XML/markdown instruction blocks. Not classified as attacks in this phase.

---

## Chunking

Prompt Guard’s documented context is ~512 **tokens**. We do **not** pretend character count equals tokens.

Design:

- `Tokenizer` protocol (replaceable)
- `CharacterFallbackTokenizer` — 1 unit per character (documented fallback)
- `TextChunker.chunk_text(text)` → chunks with `index`, `text`, `start_offset`, `end_offset`

Config: `MAX_CHUNK_LENGTH`, `CHUNK_OVERLAP_LENGTH`, `MAX_CHUNKS`.

Chunk contents are for in-memory detectors; do not log them.

---

## Limits (environment configurable)

| Variable | Default | Role |
|----------|---------|------|
| `MAX_INPUT_LENGTH` | 100000 | Reject oversized input |
| `MAX_DECODED_LENGTH` | 50000 | Cap decoded derived text |
| `MAX_DECODE_DEPTH` | 2 | Cap decode iterations |
| `MAX_ENCODED_CANDIDATES` | 16 | Cap candidate segments |
| `MAX_CHUNK_LENGTH` | 1500 | Fallback chunk size (chars) |
| `CHUNK_OVERLAP_LENGTH` | 100 | Chunk overlap (chars) |
| `MAX_CHUNKS` | 64 | Cap number of chunks |

---

## Security considerations

- No network / LLM calls in this phase
- No arbitrary code execution
- No raw-content logging
- No persistence of raw, normalized, or decoded content (Scan DB still stores hash/metadata only)
- Preprocessing failures raise structured `PreprocessingError` or populate `preprocessing_errors` — they do **not** set ALLOW/BLOCK
- `SecurityInput` is an in-memory object for the future pipeline

---

## Code entrypoint

```python
from app.core.enums import SourceType
from app.services import InputNormalizationService

service = InputNormalizationService()
security_input = service.normalize(content, SourceType.USER_MESSAGE)
```

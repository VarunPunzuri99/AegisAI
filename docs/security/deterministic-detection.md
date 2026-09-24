# Deterministic Prompt Injection Detection

**Phase 4.** Offline, rule-based detector. No Groq / Prompt Guard / LLM calls.

> **Deterministic detection is one security layer and does not provide complete prompt-injection prevention.**  
> It produces evidence (`DetectionReport`) and does **not** make the final ALLOW/BLOCK decision.

---

## Architecture

```
Raw Input
    ↓
InputNormalizationService  →  SecurityInput
    ↓
DeterministicDetectionEngine
    ├── instruction_override_rules
    ├── role_manipulation_rules
    ├── prompt_extraction_rules
    ├── jailbreak_rules
    ├── indirect_injection_rules
    ├── obfuscation_rules
    ├── tool_manipulation_rules
    ├── data_exfiltration_rules
    └── context_manipulation_rules
    ↓
DetectionReport (findings + heuristic confidence)
```

Code: `backend/app/security/detectors/`, service: `DeterministicDetectionService`.

---

## Attack categories

Findings use **canonical taxonomy identifiers** from `attack-taxonomy.md`:

| Phase 4 name | Canonical `attack_type` |
|--------------|-------------------------|
| INSTRUCTION_OVERRIDE | `instruction_override` |
| ROLE_MANIPULATION | `role_change` |
| SYSTEM_PROMPT_EXTRACTION | `secret_extraction` |
| JAILBREAK | `multi_step_jailbreak` |
| INDIRECT_INJECTION | `indirect_prompt_injection` |
| OBFUSCATION | `encoded_instruction` |
| TOOL_MANIPULATION | `tool_abuse` |
| DATA_EXFILTRATION | `credential_theft` |
| CONTEXT_MANIPULATION | `context_poisoning` |

---

## Rule IDs

| ID | Detector | Intent |
|----|----------|--------|
| IO-001 / IO-002 | Instruction override | Discard/replace prior instructions |
| RM-001 / RM-002 | Role manipulation | Privileged role / developer mode |
| SPE-001 | Prompt extraction | Reveal system/hidden instructions |
| JB-001 | Jailbreak | Bypass safety / unrestricted mode |
| II-001 / II-002 / II-003 | Indirect injection | Instructions for another AI; hidden HTML |
| OB-001 / OB-002 | Obfuscation | Encoding/ZW alone vs + instruction-like |
| TM-001 / TM-002 / TM-003 | Tool manipulation | Override + tool/action |
| DE-001 | Data exfiltration | Expose secrets / FAKE_* placeholders |
| CM-001 / CM-002 / CM-003 | Context manipulation | Fake SYSTEM/USER boundaries |

---

## Confidence semantics

Scores in `[0.0, 1.0]` are **heuristics**, not calibrated probabilities.

| Situation | Typical range |
|-----------|----------------|
| Weak / meta-discussion | ~0.28–0.40 |
| Clear explicit pattern | ~0.75–0.92 |
| Multi-category correlation | up to ~0.95–1.0 |

Meta/educational phrasing (e.g. “the article explains…”) lowers confidence and severity.

---

## Severity semantics

Per-finding only (not a global risk score):

- **LOW** — weak or discursive signal  
- **MEDIUM** — clear structural concern  
- **HIGH** — explicit attack pattern  
- **CRITICAL** — correlated override + tool abuse + secret exposure  

---

## False-positive strategy

- Require **relationships** (verb + object), not single keywords (`ignore` alone is insufficient).
- Meta-discussion guard for articles/tutorials/research language.
- Third-person role mentions (“the system administrator reviewed…”) are not role assignment.
- Ordinary “send an email” without override context is not tool abuse.
- Obfuscation alone → LOW “potentially obfuscated”; stronger when combined with instruction-like content.
- Ordinary HTML comments without instruction payload → weak II-003 only.

---

## Limitations

- Paraphrases and multi-step social engineering need Phase 5+ model detectors.
- Character-chunked long inputs are scanned on full normalized text; token-accurate windows come later.
- Heuristic confidence must not be treated as probability of compromise.
- Not persisted to DB in Phase 4 (in-memory `DetectionReport` only).

---

## Usage

```python
from app.core.enums import SourceType
from app.services import InputNormalizationService, DeterministicDetectionService

sec = InputNormalizationService().normalize(text, SourceType.USER_MESSAGE)
report = DeterministicDetectionService().detect(sec)
# report.is_attack, report.findings — not ALLOW/BLOCK
```

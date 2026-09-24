"""Attack category identifiers aligned with docs/security/attack-taxonomy.md."""

from __future__ import annotations

from enum import StrEnum


class AttackType(StrEnum):
    """Canonical taxonomy identifiers (snake_case)."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTION = "encoded_instruction"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"


# Phase 4 / external aliases → canonical taxonomy ids
ATTACK_TYPE_ALIASES: dict[str, AttackType] = {
    "INSTRUCTION_OVERRIDE": AttackType.INSTRUCTION_OVERRIDE,
    "ROLE_MANIPULATION": AttackType.ROLE_CHANGE,
    "ROLE_CHANGE": AttackType.ROLE_CHANGE,
    "SYSTEM_PROMPT_EXTRACTION": AttackType.SECRET_EXTRACTION,
    "SECRET_EXTRACTION": AttackType.SECRET_EXTRACTION,
    "JAILBREAK": AttackType.MULTI_STEP_JAILBREAK,
    "MULTI_STEP_JAILBREAK": AttackType.MULTI_STEP_JAILBREAK,
    "INDIRECT_INJECTION": AttackType.INDIRECT_PROMPT_INJECTION,
    "INDIRECT_PROMPT_INJECTION": AttackType.INDIRECT_PROMPT_INJECTION,
    "OBFUSCATION": AttackType.ENCODED_INSTRUCTION,
    "ENCODED_INSTRUCTION": AttackType.ENCODED_INSTRUCTION,
    "TOOL_MANIPULATION": AttackType.TOOL_ABUSE,
    "TOOL_ABUSE": AttackType.TOOL_ABUSE,
    "DATA_EXFILTRATION": AttackType.CREDENTIAL_THEFT,
    "CREDENTIAL_THEFT": AttackType.CREDENTIAL_THEFT,
    "CONTEXT_MANIPULATION": AttackType.CONTEXT_POISONING,
    "CONTEXT_POISONING": AttackType.CONTEXT_POISONING,
}


def resolve_attack_type(name: str) -> AttackType:
    """Resolve alias or canonical name to AttackType."""
    if name in AttackType._value2member_map_:
        return AttackType(name)
    key = name.upper().replace("-", "_")
    if key in ATTACK_TYPE_ALIASES:
        return ATTACK_TYPE_ALIASES[key]
    raise KeyError(f"Unknown attack type: {name}")

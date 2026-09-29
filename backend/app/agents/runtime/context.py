"""Trust-aware context helpers — application assigns trust; model cannot upgrade."""

from __future__ import annotations

from app.agents.runtime.types import AgentContextItem, ContextSourceType
from app.agents.types import TrustLevel
from app.services.hashing import sha256_hex

_PREVIEW_LEN = 160


def make_context_item(
    *,
    content: str,
    source_type: ContextSourceType,
    trust_level: TrustLevel,
    label: str = "",
) -> AgentContextItem:
    preview = " ".join(content.split())
    if len(preview) > _PREVIEW_LEN:
        preview = preview[: _PREVIEW_LEN - 1] + "…"
    return AgentContextItem(
        source_type=source_type,
        trust_level=trust_level,
        content_hash=sha256_hex(content),
        content_length=len(content),
        label=label or source_type.value,
        preview=preview,
    )


def assert_cannot_upgrade_trust(item: AgentContextItem, requested: TrustLevel) -> None:
    """Untrusted content cannot be promoted to TRUSTED by agent/model."""
    if item.trust_level == TrustLevel.UNTRUSTED and requested == TrustLevel.TRUSTED:
        raise ValueError("UNTRUSTED content cannot be upgraded to TRUSTED")

"""Development bearer token mapping — tokens from environment only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.core.config import get_settings


@dataclass(frozen=True)
class TokenBinding:
    """Maps a development token to a principal_id. Token value never logged."""

    principal_id: str
    # Optional expiry epoch seconds; None = no expiry in demo mode
    expires_at: float | None = None


def _token_map() -> dict[str, TokenBinding]:
    """Build token→principal map from settings. Empty tokens are ignored."""
    settings = get_settings()
    pairs: list[tuple[str, str]] = [
        (settings.aegis_demo_token_user, "user:demo"),
        (settings.aegis_demo_token_readonly, "user:readonly"),
        (settings.aegis_demo_token_agent, "agent:aegis-demo"),
        (settings.aegis_demo_token_service, "service:aegis-runtime"),
        (settings.aegis_demo_token_disabled, "user:disabled"),
        (settings.aegis_demo_token_tenant_b, "user:tenant-b"),
    ]
    out: dict[str, TokenBinding] = {}
    for token, principal_id in pairs:
        token = (token or "").strip()
        if token:
            out[token] = TokenBinding(principal_id=principal_id)
    return out


def resolve_development_token(token: str) -> Optional[TokenBinding]:
    if not token:
        return None
    return _token_map().get(token)


def configured_token_count() -> int:
    return len(_token_map())

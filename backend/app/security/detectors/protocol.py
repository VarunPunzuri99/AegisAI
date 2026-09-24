"""Detector protocol / base class."""

from __future__ import annotations

from typing import Protocol

from app.security.detectors.types import Finding
from app.security.types import SecurityInput


class Detector(Protocol):
    """Common interface for deterministic detectors."""

    name: str

    def detect(self, security_input: SecurityInput) -> list[Finding]:
        """Return zero or more findings. Never raises on ordinary input."""
        ...

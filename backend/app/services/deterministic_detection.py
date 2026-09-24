"""Thin service wrapper around the deterministic detection engine."""

from __future__ import annotations

from app.security.detectors.engine import DeterministicDetectionEngine
from app.security.detectors.types import DetectionReport
from app.security.types import SecurityInput


class DeterministicDetectionService:
    """Offline detector service: SecurityInput → DetectionReport."""

    def __init__(self, engine: DeterministicDetectionEngine | None = None) -> None:
        self.engine = engine or DeterministicDetectionEngine()

    def detect(self, security_input: SecurityInput) -> DetectionReport:
        return self.engine.detect(security_input)

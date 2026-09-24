"""Semantic security analyzer — GPT-OSS-Safeguard via Groq (no tools, no decisions)."""

from __future__ import annotations

import logging
import time
from uuid import uuid4

from app.core.config import Settings, get_settings
from app.core.enums import Severity
from app.integrations.groq.client import GroqClient
from app.integrations.groq.errors import GroqAuthError, GroqIntegrationError
from app.integrations.groq.safeguard import (
    authoritative_evidence,
    build_safeguard_messages,
    parse_assessment_json,
)
from app.security.detectors.types import DetectionReport
from app.security.policies.prompt_injection_policy import POLICY_ID, POLICY_VERSION
from app.security.prompt_guard_detector import _is_suspicious
from app.security.prompt_guard_types import PromptGuardResult
from app.security.semantic_types import (
    SecurityImpact,
    SecurityIntent,
    SecurityTarget,
    SemanticLabel,
    SemanticSecurityAssessment,
)
from app.security.types import SecurityInput

logger = logging.getLogger(__name__)


class SemanticSecurityAnalyzer:
    """Interpret detection evidence against the versioned security policy."""

    name = "semantic_security_analyzer"

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        client: GroqClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client or GroqClient(
            api_key=self.settings.groq_api_key,
            timeout_seconds=self.settings.safeguard_timeout_seconds,
            max_retries=self.settings.safeguard_max_retries,
        )
        self.model = self.settings.safeguard_model

    def should_invoke(self, deterministic: DetectionReport) -> bool:
        if not self.settings.safeguard_enabled:
            return False
        mode = (self.settings.safeguard_mode or "SUSPICIOUS_ONLY").strip().upper()
        if mode == "ALWAYS":
            return True
        if mode == "SUSPICIOUS_ONLY":
            return _is_suspicious(deterministic)
        return _is_suspicious(deterministic)

    def analyze(
        self,
        security_input: SecurityInput,
        deterministic: DetectionReport,
        prompt_guard: PromptGuardResult | None = None,
    ) -> SemanticSecurityAssessment:
        started = time.perf_counter()

        if not self.settings.safeguard_enabled:
            return self._unavailable("DISABLED", started, deterministic, prompt_guard)

        if not self.settings.groq_api_key and self.client._transport is None:
            return self._unavailable(
                "MISSING_API_KEY",
                started,
                deterministic,
                prompt_guard,
            )

        messages = build_safeguard_messages(
            security_input=security_input,
            deterministic=deterministic,
            prompt_guard=prompt_guard,
        )

        try:
            raw = self.client.chat(
                model=self.model,
                messages=messages,
                max_tokens=self.settings.safeguard_max_tokens,
                temperature=0.0,
            )
        except GroqAuthError as exc:
            logger.warning("safeguard auth_error code=%s", exc.code)
            return self._unavailable(exc.code, started, deterministic, prompt_guard)
        except GroqIntegrationError as exc:
            logger.warning("safeguard error code=%s", exc.code)
            return self._unavailable(exc.code, started, deterministic, prompt_guard)

        if not raw:
            return self._unavailable(
                "EMPTY_RESPONSE",
                started,
                deterministic,
                prompt_guard,
            )

        assessment = parse_assessment_json(
            raw,
            model=self.model,
            deterministic=deterministic,
            prompt_guard=prompt_guard,
            latency_ms=_ms(started),
        )
        # Never invent ALLOW/BLOCK; keep decision absent
        return assessment.model_copy(
            update={
                "metadata": {
                    **assessment.metadata,
                    "decision": None,
                    "note": (
                        "Semantic assessment is evidence only; "
                        "fusion/risk/policy decide actions later."
                    ),
                }
            }
        )

    def _unavailable(
        self,
        code: str,
        started: float,
        deterministic: DetectionReport,
        prompt_guard: PromptGuardResult | None,
    ) -> SemanticSecurityAssessment:
        return SemanticSecurityAssessment(
            assessment_id=uuid4(),
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            label=SemanticLabel.UNCERTAIN,
            attack_type=None,
            attack_types=[],
            severity=Severity.NONE,
            confidence=0.0,
            intent=SecurityIntent.UNKNOWN,
            target=SecurityTarget.UNKNOWN,
            impact=SecurityImpact.UNKNOWN,
            rationale=["Semantic analyzer unavailable."],
            evidence=authoritative_evidence(deterministic, prompt_guard),
            model=self.model,
            available=False,
            error_code=code,
            latency_ms=_ms(started),
            metadata={"decision": None},
        )


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)

"""Phase 15 observability — provider telemetry, timing, failure taxonomy.

Never stores API keys, raw prompts, raw model responses, or secrets.
"""

from app.observability.metrics import percentile, summarize_latencies
from app.observability.provider_metrics import ProviderMetricsRegistry, get_provider_registry
from app.observability.timing import PipelineTimer, PipelineTiming
from app.observability.types import (
    ObservedHealthStatus,
    ProviderFailureType,
    ProviderName,
    ProviderObservation,
    SecurityMode,
)

__all__ = [
    "ObservedHealthStatus",
    "PipelineTimer",
    "PipelineTiming",
    "ProviderFailureType",
    "ProviderMetricsRegistry",
    "ProviderName",
    "ProviderObservation",
    "SecurityMode",
    "get_provider_registry",
    "percentile",
    "summarize_latencies",
]

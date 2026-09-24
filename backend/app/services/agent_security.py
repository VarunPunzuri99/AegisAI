"""Optional orchestration: security pipeline result → agent workflow."""

from __future__ import annotations

from uuid import UUID

from app.agents.types import (
    AgentActionRequest,
    AgentWorkflowResult,
    TrustLevel,
)
from app.agents.workflow import AgentSecurityWorkflow
from app.services.security_detection import DetectionPipelineResult


class AgentSecurityService:
    """Consume DetectionPipelineResult without re-running detectors or LLMs."""

    def __init__(self, workflow: AgentSecurityWorkflow | None = None) -> None:
        self.workflow = workflow or AgentSecurityWorkflow()

    def from_pipeline(
        self,
        pipeline: DetectionPipelineResult,
        *,
        action_request: AgentActionRequest | None = None,
        session_id: UUID | None = None,
        trust_level: TrustLevel = TrustLevel.UNKNOWN,
    ) -> AgentWorkflowResult:
        return self.workflow.run(
            assessment=pipeline.unified,
            policy_decision=pipeline.policy_decision,
            action_request=action_request,
            session_id=session_id,
            trust_level=trust_level,
        )

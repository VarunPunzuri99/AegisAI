"""Deterministic authorization resolver — fail-closed, no LLM."""

from __future__ import annotations

import time
from typing import Optional
from uuid import UUID

from app.auth.capabilities import capability_for_tool, get_tool_capability
from app.auth.metrics import get_authz_metrics
from app.auth.principals import get_principal
from app.auth.types import (
    AUTHORIZATION_VERSION,
    AuthorizationDecision,
    AuthorizationVerdict,
    AuthzReasonCode,
    PrincipalStatus,
)
from app.security.policies.policy_types import PolicyDecision, SecurityDecision
from app.tools.registry import ToolRegistry


class AuthorizationService:
    """
    principal + tool + capability + target (+ policy/intent) → AuthorizationDecision.

    Never replaces Tool Firewall. Never asks an LLM.
    """

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry()

    def authorize(
        self,
        *,
        principal_id: str | None,
        tenant_id: str | None,
        tool_name: str | None,
        capability: str | None = None,
        target: str | None = None,
        resource_tenant_id: str | None = None,
        intent_alignment: bool = True,
        policy_decision: PolicyDecision | None = None,
        action_id: UUID | None = None,
    ) -> AuthorizationDecision:
        started = time.perf_counter()
        reasons: list[str] = []

        # Fail-closed: malformed / missing identity
        if not principal_id or not str(principal_id).strip():
            return self._deny(
                reasons=[AuthzReasonCode.PRINCIPAL_MISSING.value],
                explanation="Principal missing; fail-closed.",
                started=started,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        principal = get_principal(principal_id)
        if principal is None:
            return self._deny(
                reasons=[AuthzReasonCode.PRINCIPAL_UNKNOWN.value],
                explanation=f"Unknown principal '{principal_id}'.",
                started=started,
                principal_id=principal_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        if principal.status != PrincipalStatus.ACTIVE:
            return self._deny(
                reasons=[AuthzReasonCode.PRINCIPAL_DISABLED.value],
                explanation="Principal is disabled.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        if not tenant_id or not str(tenant_id).strip():
            return self._deny(
                reasons=[AuthzReasonCode.TENANT_MISSING.value],
                explanation="Tenant missing; fail-closed.",
                started=started,
                principal_id=principal.principal_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        if tenant_id != principal.tenant_id:
            return self._deny(
                reasons=[AuthzReasonCode.TENANT_MISMATCH.value],
                explanation="Request tenant does not match principal tenant.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        # Cross-tenant resource access
        if resource_tenant_id and resource_tenant_id != principal.tenant_id:
            return self._deny(
                reasons=[AuthzReasonCode.TENANT_MISMATCH.value],
                explanation="Cross-tenant resource access denied.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        if not tool_name or not str(tool_name).strip():
            return self._deny(
                reasons=[AuthzReasonCode.MALFORMED_REQUEST.value],
                explanation="Tool name missing.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                policy_decision=policy_decision,
            )

        if target == "*":
            return self._deny(
                reasons=[AuthzReasonCode.TARGET_WILDCARD_FORBIDDEN.value],
                explanation="Wildcard targets are forbidden.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        if not self.registry.contains(tool_name):
            return self._deny(
                reasons=[AuthzReasonCode.TOOL_UNKNOWN.value],
                explanation=f"Unknown tool '{tool_name}'.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        tool_cap = get_tool_capability(tool_name)
        expected_cap = capability_for_tool(tool_name)
        if expected_cap is None or tool_cap is None:
            return self._deny(
                reasons=[AuthzReasonCode.CAPABILITY_UNKNOWN.value],
                explanation="Tool capability not registered.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )

        # If caller supplies capability, it must match registry.
        if capability and capability != expected_cap:
            return self._deny(
                reasons=[AuthzReasonCode.CAPABILITY_MISMATCH.value],
                explanation="Requested capability does not match tool capability.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=capability,
                policy_decision=policy_decision,
            )
        resolved_capability = capability or expected_cap

        if resolved_capability not in principal.permissions:
            return self._deny(
                reasons=[AuthzReasonCode.PERMISSION_MISSING.value],
                explanation="Principal lacks required capability.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=resolved_capability,
                policy_decision=policy_decision,
            )

        # Target scope
        if tool_cap.allowed_targets:
            if not target:
                return self._deny(
                    reasons=[AuthzReasonCode.TARGET_MISSING.value],
                    explanation="Target required for this tool.",
                    started=started,
                    principal_id=principal.principal_id,
                    tenant_id=principal.tenant_id,
                    tool_name=tool_name,
                    capability=resolved_capability,
                    policy_decision=policy_decision,
                )
            if target not in tool_cap.allowed_targets:
                return self._deny(
                    reasons=[AuthzReasonCode.TARGET_NOT_ALLOWED.value],
                    explanation=f"Target '{target}' not allowed for tool.",
                    started=started,
                    principal_id=principal.principal_id,
                    tenant_id=principal.tenant_id,
                    tool_name=tool_name,
                    target=target,
                    capability=resolved_capability,
                    policy_decision=policy_decision,
                )

        # Policy BLOCK cannot be overridden by authorization ALLOW.
        if policy_decision and policy_decision.decision == SecurityDecision.BLOCK:
            return self._deny(
                reasons=[AuthzReasonCode.POLICY_BLOCK.value],
                explanation="Policy BLOCK — authorization cannot allow.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=resolved_capability,
                policy_decision=policy_decision,
            )

        # Intent mismatch → DENY (original intent, not retrieved content).
        if intent_alignment is False:
            return self._deny(
                reasons=[AuthzReasonCode.INTENT_MISMATCH.value],
                explanation="Intent/action mismatch — authorization DENY.",
                started=started,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                target=target,
                capability=resolved_capability,
                policy_decision=policy_decision,
            )

        # REVIEW / high-risk tools may require approval (does not execute).
        if policy_decision and policy_decision.decision == SecurityDecision.REVIEW:
            reasons.append(AuthzReasonCode.POLICY_REVIEW.value)
            reasons.append(AuthzReasonCode.REQUIRES_APPROVAL.value)
            return self._finish(
                AuthorizationDecision(
                    decision=AuthorizationVerdict.REQUIRES_APPROVAL,
                    principal_id=principal.principal_id,
                    tenant_id=principal.tenant_id,
                    tool_name=tool_name,
                    capability=resolved_capability,
                    target=target,
                    reason_codes=reasons,
                    policy_version=policy_decision.policy_version if policy_decision else None,
                    explanation="Policy REVIEW — approval required.",
                ),
                started=started,
            )

        if tool_cap.requires_approval:
            reasons.append(AuthzReasonCode.REQUIRES_APPROVAL.value)
            return self._finish(
                AuthorizationDecision(
                    decision=AuthorizationVerdict.REQUIRES_APPROVAL,
                    principal_id=principal.principal_id,
                    tenant_id=principal.tenant_id,
                    tool_name=tool_name,
                    capability=resolved_capability,
                    target=target,
                    reason_codes=reasons,
                    policy_version=policy_decision.policy_version if policy_decision else None,
                    explanation="Tool requires trusted approval before execution.",
                ),
                started=started,
            )

        reasons.append(AuthzReasonCode.AUTHORIZATION_ALLOW.value)
        return self._finish(
            AuthorizationDecision(
                decision=AuthorizationVerdict.ALLOW,
                principal_id=principal.principal_id,
                tenant_id=principal.tenant_id,
                tool_name=tool_name,
                capability=resolved_capability,
                target=target,
                reason_codes=reasons,
                policy_version=policy_decision.policy_version if policy_decision else None,
                explanation="Authorization ALLOW (Tool Firewall still required).",
            ),
            started=started,
        )

    def _deny(
        self,
        *,
        reasons: list[str],
        explanation: str,
        started: float,
        principal_id: str | None = None,
        tenant_id: str | None = None,
        tool_name: str | None = None,
        target: str | None = None,
        capability: str | None = None,
        policy_decision: PolicyDecision | None = None,
    ) -> AuthorizationDecision:
        return self._finish(
            AuthorizationDecision(
                decision=AuthorizationVerdict.DENY,
                principal_id=principal_id,
                tenant_id=tenant_id,
                tool_name=tool_name,
                capability=capability,
                target=target,
                reason_codes=list(reasons),
                policy_version=policy_decision.policy_version if policy_decision else None,
                explanation=explanation,
            ),
            started=started,
        )

    def _finish(self, decision: AuthorizationDecision, *, started: float) -> AuthorizationDecision:
        ms = (time.perf_counter() - started) * 1000.0
        get_authz_metrics().record(
            decision.decision,
            reason_codes=decision.reason_codes,
            ms=ms,
        )
        return decision

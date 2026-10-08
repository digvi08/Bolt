"""Fail-closed risk and policy evaluation."""

from __future__ import annotations

from .config import AgentConfig
from .models import ActionKind, ActionRequest, PolicyDecision, RiskLevel

_RISK_BY_KIND = {
    ActionKind.READ_ONLY: RiskLevel.LOW,
    ActionKind.NETWORK_READ: RiskLevel.LOW,
    ActionKind.WRITE_FILE: RiskLevel.MEDIUM,
    ActionKind.PROCESS: RiskLevel.HIGH,
    ActionKind.NETWORK: RiskLevel.HIGH,
    ActionKind.BROWSER: RiskLevel.HIGH,
    ActionKind.DESKTOP: RiskLevel.HIGH,
    ActionKind.ADMINISTRATOR: RiskLevel.HIGH,
    ActionKind.UNKNOWN: RiskLevel.UNKNOWN,
}

_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.UNKNOWN: 3,
}


class DefaultPolicyEngine:
    def __init__(self, config: AgentConfig) -> None:
        self._config = config

    def evaluate(self, action: ActionRequest) -> PolicyDecision:
        kind = action.kind if isinstance(action.kind, ActionKind) else ActionKind.UNKNOWN
        risk = action.requested_risk or _RISK_BY_KIND.get(kind, RiskLevel.UNKNOWN)
        if risk is RiskLevel.UNKNOWN:
            return PolicyDecision(False, risk, "unknown and high-risk actions are denied")
        if kind not in self._config.allowed_actions:
            return PolicyDecision(False, risk, "action kind is not explicitly allowlisted")
        if (
            kind in {ActionKind.NETWORK_READ, ActionKind.NETWORK}
            and not self._config.enable_external_integrations
        ):
            return PolicyDecision(False, risk, "external integrations are disabled")
        if risk is RiskLevel.HIGH and kind is not ActionKind.BROWSER:
            return PolicyDecision(False, risk, "high-risk non-browser actions are denied")
        requires_approval = _RISK_ORDER[risk] >= _RISK_ORDER[self._config.approval_required_at]
        return PolicyDecision(True, risk, "action is allowlisted", requires_approval)

"""Configuration with deny-by-default security settings."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .models import ActionKind, RiskLevel


@dataclass(frozen=True)
class AgentConfig:
    allowed_actions: frozenset[ActionKind] = frozenset()
    approval_required_at: RiskLevel = RiskLevel.MEDIUM
    max_automatic_risk: RiskLevel = RiskLevel.LOW
    enable_external_integrations: bool = False
    audit_required: bool = True
    max_plan_steps: int = 8
    max_replans: int = 2
    max_tool_calls: int = 8
    max_model_calls: int = 3
    max_total_tokens: int = 4096
    max_total_cost: float | None = None
    model_input_price_per_1k: float | None = None
    model_output_price_per_1k: float | None = None
    max_task_duration_ms: int = 30_000


def load_config(values: Mapping[str, str] | None = None) -> AgentConfig:
    """Load only explicit safe configuration; integrations remain disabled by default."""
    values = values or {}
    raw_actions = values.get("allowed_actions", "")
    allowed = frozenset(
        ActionKind(item.strip()) for item in raw_actions.split(",") if item.strip()
    )
    return AgentConfig(
        allowed_actions=allowed,
        approval_required_at=RiskLevel(values.get("approval_required_at", RiskLevel.MEDIUM.value)),
        max_automatic_risk=RiskLevel(values.get("max_automatic_risk", RiskLevel.LOW.value)),
        enable_external_integrations=values.get("enable_external_integrations", "false").lower() == "true",
        audit_required=values.get("audit_required", "true").lower() == "true",
        max_plan_steps=int(values.get("max_plan_steps", "8")),
        max_replans=int(values.get("max_replans", "2")),
        max_tool_calls=int(values.get("max_tool_calls", "8")),
        max_model_calls=int(values.get("max_model_calls", "3")),
        max_total_tokens=int(values.get("max_total_tokens", "4096")),
        max_total_cost=float(values["max_total_cost"]) if "max_total_cost" in values else None,
        model_input_price_per_1k=float(values["model_input_price_per_1k"]) if "model_input_price_per_1k" in values else None,
        model_output_price_per_1k=float(values["model_output_price_per_1k"]) if "model_output_price_per_1k" in values else None,
        max_task_duration_ms=int(values.get("max_task_duration_ms", "30000")),
    )

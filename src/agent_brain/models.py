"""Project-owned agent-brain models for interpreting tasks and planning safe actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


class TaskGoal(str, Enum):
    UNKNOWN = "unknown"
    FIND_INFORMATION = "find_information"
    NAVIGATE = "navigate"
    FILL_FORM = "fill_form"
    SUBMIT_FORM = "submit_form"
    VERIFY_RESULT = "verify_result"
    GENERIC_ACTION = "generic_action"


class TrustClassification(str, Enum):
    TRUSTED_SYSTEM = "trusted_system"
    TRUSTED_USER = "trusted_user"
    TRUSTED_MEMORY = "trusted_memory"
    UNTRUSTED_WEB = "untrusted_web"
    UNTRUSTED_DOCUMENT = "untrusted_document"
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool_output"


class ModelComplexity(str, Enum):
    SIMPLE = "simple"
    STRUCTURED = "structured"
    REASONING = "reasoning"
    VISUAL = "visual"


@dataclass(frozen=True)
class UserRequest:
    text: str
    source: str = "user"
    trust: TrustClassification = TrustClassification.TRUSTED_USER


@dataclass(frozen=True)
class TaskIntent:
    goal: TaskGoal = TaskGoal.UNKNOWN
    ability: str | None = None
    requested_ability: str | None = None
    entities: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    expected_result: str = ""
    time_constraints: tuple[str, ...] = ()
    contains_consequential_action: bool = False
    possible_consequential_actions: tuple[str, ...] = ()
    risk: str = "read"
    ambiguity: str = ""
    original_request: str = ""


@dataclass(frozen=True)
class ModelRequest:
    prompt: str
    task_type: str = "classification"
    required_capabilities: tuple[str, ...] = ()
    latency_budget_ms: int = 2000
    cost_budget: float = 0.0
    max_attempts: int = 2
    strict_schema: bool = True
    max_tokens: int = 1024


@dataclass(frozen=True)
class ModelUsage:
    provider: str
    model: str
    attempt: int
    latency_ms: int
    token_usage: int | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost: float = 0.0
    cost_available: bool = False
    failure_reason: str | None = None


@dataclass(frozen=True)
class ModelResponse:
    provider: str
    model: str
    content: str
    usage: ModelUsage | None = None
    structured: dict[str, Any] | None = None


@dataclass(frozen=True)
class PlanStep:
    ability: str
    action: str
    step_id: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    preconditions: tuple[str, ...] = ()
    expected_result: str = ""
    verification: tuple[str, ...] = ()
    risk: str = "read"
    reason: str = ""
    requires_approval: bool = False
    dependencies: tuple[str, ...] = ()
    execution_id: str = ""


@dataclass(frozen=True)
class Plan:
    task_id: UUID | None = None
    goal: TaskGoal = TaskGoal.UNKNOWN
    steps: tuple[PlanStep, ...] = ()
    explanation: str = ""
    total_risk: str = "read"
    budget: dict[str, int] = field(default_factory=lambda: {
        "max_plan_steps": 8,
        "max_replans": 2,
        "max_model_calls": 3,
        "max_total_tokens": 4096,
        "max_task_duration_ms": 30_000,
    })


@dataclass(frozen=True)
class PlanExplanation:
    summary: str
    dependencies: tuple[str, ...] = ()


@dataclass
class AgentDecision:
    decision_id: UUID = field(default_factory=uuid4)
    intent: TaskIntent | None = None
    selected_ability: str | None = None
    risk: str = "read"
    policy_result: str = "pending"
    approval_result: str = "pending"
    verification_result: str = "pending"


@dataclass(frozen=True)
class AgentResult:
    success: bool
    task_id: UUID
    intent: TaskIntent | None = None
    plan: Plan | None = None
    reason: str = ""
    decision: AgentDecision | None = None
    replan_count: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float | None = None


__all__ = [
    "AgentDecision",
    "AgentResult",
    "ModelComplexity",
    "ModelRequest",
    "ModelResponse",
    "ModelUsage",
    "Plan",
    "PlanExplanation",
    "PlanStep",
    "TaskGoal",
    "TaskIntent",
    "TrustClassification",
    "UserRequest",
]

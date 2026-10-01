"""Planner interfaces and deterministic planning logic for the agent brain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from abilities.registry import AbilityRegistry

from .models import Plan, PlanStep, TaskGoal, TaskIntent


class AgentPlanner(Protocol):
    def plan(self, intent: TaskIntent, *, registry: AbilityRegistry | None = None) -> Plan: ...


@dataclass(frozen=True)
class DeterministicAgentPlanner:
    max_steps: int = 8
    max_replans: int = 2

    def plan(self, intent: TaskIntent, *, registry: AbilityRegistry | None = None) -> Plan:
        if not intent.original_request:
            raise ValueError("intent original request is required")

        ability = self._choose_ability(intent, registry)
        steps: list[PlanStep] = []

        if ability == "browser":
            steps.append(
                PlanStep(
                    ability="browser",
                    action="navigate",
                    step_id="navigate",
                    arguments={"url": self._url_hint(intent.original_request)},
                    preconditions=("browser available",),
                    expected_result="page is available",
                    verification=("page loaded",),
                    risk="read",
                    reason="Open the requested page before interacting with it.",
                )
            )
            steps.append(
                PlanStep(
                    ability="browser",
                    action="observe",
                    step_id="observe-page",
                    arguments={"target": "page"},
                    preconditions=("page loaded",),
                    expected_result="page content inspected",
                    verification=("observation captured",),
                    risk="read",
                    reason="Inspect the page to identify the required target or form.",
                )
            )
            if intent.goal in {TaskGoal.FILL_FORM, TaskGoal.SUBMIT_FORM}:
                steps.append(
                    PlanStep(
                        ability="browser",
                        action="fill",
                        step_id="fill-name",
                        arguments={"target_id": "name", "value": "demo-user"},
                        preconditions=("registration form available",),
                        expected_result="form field populated",
                        verification=("field value matches",),
                        risk="medium",
                        reason="Fill the required field with a validated value.",
                    )
                )
            if intent.goal is TaskGoal.SUBMIT_FORM:
                steps.append(
                    PlanStep(
                        ability="browser",
                        action="submit",
                        step_id="submit-form",
                        arguments={"target_id": "submit"},
                        preconditions=("form validated",),
                        expected_result="submission completed safely",
                        verification=("confirmation observed", "submission verified"),
                        risk="high",
                        reason="A consequential submit is gated by approval and verification.",
                        requires_approval=True,
                    )
                )
            else:
                steps.append(
                    PlanStep(
                        ability="browser",
                        action="observe",
                        step_id="observe-target",
                        arguments={"target": "target"},
                        preconditions=("required information visible",),
                        expected_result="target information captured",
                        verification=("target found",),
                        risk="read",
                        reason="Find the required information before responding.",
                    )
                )
        elif ability == "desktop":
            steps.append(
                PlanStep(
                    ability="desktop",
                    action="observe_window",
                    step_id="observe-window",
                    arguments={"window": "target app"},
                    preconditions=("window available",),
                    expected_result="application window observed",
                    verification=("window captured",),
                    risk="medium",
                    reason="Inspect the target desktop application before interacting with it.",
                )
            )
            steps.append(
                PlanStep(
                    ability="desktop",
                    action="click",
                    step_id="click-target",
                    arguments={"window": "target app", "name": "submit"},
                    preconditions=("target control visible",),
                    expected_result="interaction executed",
                    verification=("control state changed",),
                    risk="high",
                    reason="Desktop interaction is high risk and must be policy-gated.",
                    requires_approval=True,
                )
            )
        else:
            raise ValueError(f"unsupported ability: {ability}")

        if len(steps) > self.max_steps:
            raise ValueError("plan exceeds configured maximum steps")

        return Plan(
            task_id=UUID(int=0),
            goal=intent.goal,
            steps=tuple(steps),
            explanation="Deterministic plan generated from the task intent and available abilities.",
            total_risk=(intent.risk if intent.risk else "read"),
            budget={
                "max_plan_steps": self.max_steps,
                "max_replans": self.max_replans,
                "max_model_calls": 3,
                "max_total_tokens": 4096,
                "max_task_duration_ms": 30_000,
            },
        )

    def _choose_ability(self, intent: TaskIntent, registry: AbilityRegistry | None) -> str:
        if intent.ability:
            return intent.ability
        if registry is not None:
            available = registry.available()
            for candidate in ("browser", "desktop"):
                if candidate in available:
                    return candidate
            if available:
                return available[0]
        return "browser"

    def _url_hint(self, request: str) -> str:
        lowered = request.lower()
        if "example" in lowered or "test site" in lowered:
            return "https://example.test/"
        for prefix in ("http://", "https://"):
            start = request.find(prefix)
            if start >= 0:
                end = request.find(" ", start)
                if end == -1:
                    return request[start:]
                return request[start:end]
        return "https://example.test/"


__all__ = ["AgentPlanner", "DeterministicAgentPlanner"]

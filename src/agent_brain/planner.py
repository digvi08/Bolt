"""Planner interfaces and deterministic planning logic for the agent brain."""

from __future__ import annotations

import re
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
            if intent.goal in {TaskGoal.FILL_FORM, TaskGoal.SUBMIT_FORM}:
                raise ValueError(
                    "browser form actions require a model-driven plan with explicit values "
                    "and verifiable outcomes"
                )
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
                    action="inspect",
                    step_id="inspect-page",
                    arguments={},
                    preconditions=("page loaded",),
                    expected_result="page content inspected",
                    verification=("observation captured",),
                    risk="read",
                    reason="Inspect the page to identify the required target or form.",
                )
            )
        elif ability == "web":
            if "http://" in intent.original_request.lower() or "https://" in intent.original_request.lower():
                action = "fetch"
                arguments = {"url": self._url_hint(intent.original_request)}
                reason = "Fetch the explicitly requested public page using bounded network reads."
            else:
                action = "search"
                query = intent.original_request
                for prefix in ("search the web for ", "web search ", "search online for ", "research online "):
                    if query.lower().startswith(prefix):
                        query = query[len(prefix):]
                        break
                arguments = {"query": query[:500]}
                reason = "Search public web results; treat every result as untrusted data."
            steps.append(
                PlanStep(
                    ability="web",
                    action=action,
                    step_id=f"web-{action}",
                    arguments=arguments,
                    expected_result="bounded public web results returned as untrusted data",
                    verification=("provider response received",),
                    risk="read",
                    reason=reason,
                )
            )
        elif ability == "workspace":
            request = intent.original_request.strip()
            if any(token in request.lower() for token in ("list files", "list directory")):
                action = "list_directory"
                path = "."
                arguments = {"path": path}
                risk = "read"
                requires_approval = False
                verification = ("workspace listing completed",)
            elif intent.risk == "medium":
                match = re.match(
                    r'^(?:please\s+)?(?:create|write|save)\s+(?:a\s+)?file\s+'
                    r'''(?P<path>"[^"]+"|'[^']+'|\S+)\s+(?:with|containing)\s+(?P<text>.+)$''',
                    request,
                    flags=re.IGNORECASE,
                )
                if match is None:
                    raise ValueError("file creation requires a path and explicit content")
                action = "write_text"
                arguments = {
                    "path": match.group("path").strip("'\""),
                    "text": match.group("text"),
                }
                risk = "medium"
                requires_approval = True
                verification = ("new file exists",)
            else:
                action = "read_text"
                path = request.split()[-1]
                arguments = {"path": path.rstrip(".,;")}
                risk = "read"
                requires_approval = False
                verification = ("workspace file read completed",)
            steps.append(
                PlanStep(
                    ability="workspace",
                    action=action,
                    step_id=f"workspace-{action}",
                    arguments=arguments,
                    expected_result="bounded workspace data returned as untrusted document content",
                    verification=verification,
                    risk=risk,
                    requires_approval=requires_approval,
                    reason=(
                        "Create a new file within the configured root after current approval."
                        if action == "write_text"
                        else "Read only beneath the explicitly configured workspace root."
                    ),
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

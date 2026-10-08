"""Deterministic human-task interpreter for the agent brain."""

from __future__ import annotations

import re

from .models import TaskGoal, TaskIntent, UserRequest


class TaskInterpreter:
    def interpret(self, request: str | UserRequest) -> TaskIntent:
        raise NotImplementedError


class DeterministicTaskInterpreter(TaskInterpreter):
    def interpret(self, request: str | UserRequest) -> TaskIntent:
        user_request = request.text if isinstance(request, UserRequest) else str(request)
        text = user_request.strip()
        if not text:
            raise ValueError("user request is required")

        lower = text.lower()
        goal = TaskGoal.UNKNOWN
        ability = None
        risk = "read"
        contains_consequential_action = False
        possible_consequential_actions: list[str] = []
        constraints: list[str] = []

        if "browser" in lower and any(
            token in lower for token in ("https://", "http://", "navigate", "visit", "open", "inspect")
        ):
            goal = TaskGoal.NAVIGATE if any(token in lower for token in ("navigate", "visit", "open")) else TaskGoal.FIND_INFORMATION
            ability = "browser"
            risk = "read"
        elif any(token in lower for token in ("submit", "confirm", "send", "purchase", "book", "pay", "place order")):
            goal = TaskGoal.SUBMIT_FORM
            ability = "browser"
            risk = "high"
            contains_consequential_action = True
            possible_consequential_actions.extend(["submit", "confirm"])
        elif any(token in lower for token in ("fill", "enter", "type", "complete")):
            goal = TaskGoal.FILL_FORM
            ability = "browser"
            risk = "medium"
            contains_consequential_action = True
            possible_consequential_actions.append("fill")
        elif "https://" in lower or "http://" in lower or any(
            token in lower
            for token in ("search the web", "web search", "search online", "research online")
        ):
            goal = TaskGoal.FIND_INFORMATION
            ability = "web"
            risk = "read"
        elif any(token in lower for token in ("list files", "list directory", "read file", "workspace file")):
            goal = TaskGoal.GENERIC_ACTION
            ability = "workspace"
            risk = "read"
        elif any(token in lower for token in ("create file ", "write file ", "save file ")):
            goal = TaskGoal.GENERIC_ACTION
            ability = "workspace"
            risk = "medium"
            contains_consequential_action = True
            possible_consequential_actions.append("create file")
            constraints.append("workspace write requires current approval")
        elif any(token in lower for token in ("find", "search", "lookup", "look up", "inspect", "observe", "open")):
            goal = TaskGoal.FIND_INFORMATION
            ability = "browser"
            risk = "read"
        elif any(token in lower for token in ("navigate", "open", "go to", "visit")):
            goal = TaskGoal.NAVIGATE
            ability = "browser"
            risk = "read"
        else:
            goal = TaskGoal.GENERIC_ACTION
            ability = "browser"

        entities = tuple(sorted({match.strip("'\" ") for match in re.findall(r'"([^"]+)"|\b[a-zA-Z0-9_.-]+\b', text) if match.strip()}))
        if contains_consequential_action:
            constraints.append("approval required for consequential action")
        if "today" in lower or "now" in lower:
            constraints.append("time-sensitive")

        return TaskIntent(
            goal=goal,
            ability=ability,
            requested_ability=ability,
            entities=entities,
            constraints=tuple(constraints),
            expected_result="browser task completed safely",
            time_constraints=tuple(sorted({token for token in ("immediate", "due") if token in lower})),
            contains_consequential_action=contains_consequential_action,
            possible_consequential_actions=tuple(possible_consequential_actions),
            risk=risk,
            ambiguity="" if goal is not TaskGoal.UNKNOWN else "task could not be classified deterministically",
            original_request=text,
        )


__all__ = ["DeterministicTaskInterpreter", "TaskInterpreter"]

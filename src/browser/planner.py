"""Project-owned browser planner abstractions and deterministic reference implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from .models import (
    BrowserAction,
    BrowserActionType,
    BrowserPlan,
    BrowserPrecondition,
    ExpectedElement,
    ExpectedText,
    ExpectedURL,
)


class BrowserPlanner(Protocol):
    def plan(self, task: str) -> BrowserPlan: ...


@dataclass(frozen=True)
class DeterministicBrowserPlanner:
    """Reference planner: deterministic and free from direct Playwright execution."""

    default_domain: str = "example.test"

    def plan(self, task: str) -> BrowserPlan:
        instructions = task.strip()
        if not instructions:
            raise ValueError("task description is required")

        session_id = uuid4()
        tab_id = uuid4()
        actions: list[BrowserAction] = []
        lower = instructions.lower()

        if any(token in lower for token in ("open ", "navigate", "go to", "visit")):
            url = self._extract_url(instructions) or f"https://{self.default_domain}/"
            actions.append(
                BrowserAction(
                    BrowserActionType.NAVIGATE,
                    session_id=session_id,
                    tab_id=tab_id,
                    url=url,
                    preconditions=(BrowserPrecondition(expected_url_domain=self.default_domain),),
                    verification=(ExpectedURL(url, exact=True),),
                )
            )

        if any(token in lower for token in ("observe", "inspect", "look at")):
            actions.append(BrowserAction(BrowserActionType.OBSERVE, session_id=session_id, tab_id=tab_id))

        if any(token in lower for token in ("fill", "enter", "type")):
            actions.append(
                BrowserAction(
                    BrowserActionType.FILL,
                    session_id=session_id,
                    tab_id=tab_id,
                    target_id="name",
                    value="demo-user",
                    preconditions=(BrowserPrecondition(expected_role="textbox", expected_name="Name"),),
                    verification=(ExpectedText("demo-user"),),
                )
            )

        if any(token in lower for token in ("select", "choose")):
            actions.append(
                BrowserAction(
                    BrowserActionType.SELECT_OPTION,
                    session_id=session_id,
                    tab_id=tab_id,
                    target_id="plan",
                    option="basic",
                    preconditions=(BrowserPrecondition(expected_label="Plan"),),
                )
            )

        if any(token in lower for token in ("submit", "confirm", "send")):
            actions.append(
                BrowserAction(
                    BrowserActionType.SUBMIT,
                    session_id=session_id,
                    tab_id=tab_id,
                    target_id="submit",
                    preconditions=(BrowserPrecondition(expected_name="Submit"),),
                    verification=(ExpectedElement(name="Submit"), ExpectedText("success")),
                )
            )

        if not actions:
            actions.append(BrowserAction(BrowserActionType.OBSERVE, session_id=session_id, tab_id=tab_id))

        return BrowserPlan(task=instructions, actions=tuple(actions), status="planned")

    def _extract_url(self, task: str) -> str | None:
        lower = task.lower()
        for prefix in ("http://", "https://"):
            start = lower.find(prefix)
            if start >= 0:
                end = task.find(" ", start)
                if end < 0:
                    return task[start:]
                return task[start:end]
        if "example.test" in lower:
            return "https://example.test/"
        return None


class FutureLLMBrowserPlanner(DeterministicBrowserPlanner):
    """Compatibility placeholder for a future model-backed planner."""

    def plan(self, task: str) -> BrowserPlan:
        return super().plan(task)


__all__ = [
    "BrowserPlanner",
    "DeterministicBrowserPlanner",
    "FutureLLMBrowserPlanner",
]

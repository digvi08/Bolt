"""Compatibility facade that submits browser tasks through the application service."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agent_core.models import Task
from agent_core.service import SubmitTaskRequest

from .models import BrowserTask

if TYPE_CHECKING:
    from agent_core.service import AgentService


@dataclass(frozen=True)
class BrowserExecutionResult:
    ok: bool
    task: BrowserTask | Task | str
    plan: object | None = None
    reason: str = ""


class BrowserTaskRunner:
    """Submit objectives; browser execution remains owned by AgentService."""

    def __init__(self, service: AgentService) -> None:
        self._service = service

    def run(self, task: str | BrowserTask | Task) -> BrowserExecutionResult:
        return self._run(task)

    async def run_async(self, task: str | BrowserTask | Task) -> BrowserExecutionResult:
        return await asyncio.to_thread(self._run, task)

    def _run(self, task: str | BrowserTask | Task) -> BrowserExecutionResult:
        if isinstance(task, BrowserTask):
            objective = task.description
        elif isinstance(task, Task):
            objective = task.objective or task.instruction.text
        else:
            objective = task
        result = self._service.submit_task(SubmitTaskRequest(objective))
        return BrowserExecutionResult(result.success, task, reason=result.error.message if result.error else "")


__all__ = ["BrowserExecutionResult", "BrowserTaskRunner"]

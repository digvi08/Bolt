"""Bounded browser task execution that preserves the runtime and policy boundary."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, cast

from agent_core.config import AgentConfig
from agent_core.models import ActionKind, Task, TaskStatus, TrustedInstruction
from agent_core.persistence import TaskStateStore
from agent_core.ports import ActionProvider, ApprovalProvider, AuditSink, KillSwitch
from agent_core.runtime import ActionReconciler, AgentRuntime

from .models import BrowserPlan, BrowserTask
from .planner import BrowserPlanner, DeterministicBrowserPlanner
from .playwright_provider import BrowserActionProvider
from .ports import BrowserProvider


@dataclass(frozen=True)
class BrowserExecutionResult:
    ok: bool
    task: BrowserTask | Task | str
    plan: object | None = None
    reason: str = ""


class BrowserTaskRunner:
    def __init__(
        self,
        planner: BrowserPlanner | None = None,
        browser: BrowserProvider | None = None,
        config: AgentConfig | None = None,
        approval_provider: ApprovalProvider | None = None,
        kill_switch: KillSwitch | None = None,
        audit_sink: AuditSink | None = None,
        state_store: TaskStateStore | None = None,
        action_reconciler: ActionReconciler | None = None,
    ) -> None:
        self._planner = planner or DeterministicBrowserPlanner()
        self._browser = browser
        self._config = config or AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER}))
        self._approval = approval_provider
        self._kill_switch = kill_switch
        self._audit = audit_sink
        self._state_store = state_store
        self._action_reconciler = action_reconciler

    def run(self, task: str | BrowserTask | Task, *, browser: BrowserProvider | None = None) -> BrowserExecutionResult:
        return asyncio.run(self.run_async(task, browser=browser))

    async def run_async(
        self, task: str | BrowserTask | Task, *, browser: BrowserProvider | None = None
    ) -> BrowserExecutionResult:
        browser_task = self._coerce_task(task)
        plan = self._planner.plan(browser_task.description) if not browser_task.plan else BrowserPlan(
            task=browser_task.description,
            actions=tuple(browser_task.plan),
            status=browser_task.status,
        )
        if browser is None and self._browser is None:
            return BrowserExecutionResult(True, browser_task, plan=plan, reason="planned without execution")

        effective_browser = browser or self._browser
        if effective_browser is None:
            return BrowserExecutionResult(False, browser_task, plan=plan, reason="no browser provider configured")

        provider = BrowserActionProvider(cast(Any, effective_browser), self._audit)
        runtime = AgentRuntime(
            config=self._config,
            action_provider=cast(ActionProvider, provider),
            audit_sink=self._audit or _NoAuditSink(),
            kill_switch=self._kill_switch or _PassthroughKillSwitch(),
            approval_provider=self._approval,
            state_store=self._state_store,
            action_reconciler=self._action_reconciler,
        )

        task_model = task if isinstance(task, Task) else Task(TrustedInstruction(browser_task.description))
        if task_model.status is TaskStatus.CREATED:
            task_model.status = TaskStatus.PLANNED
        for action in plan.actions:
            request = provider.register(action, task_model.id)
            result = await runtime.run_async(task_model, request)
            if not result.success:
                return BrowserExecutionResult(False, browser_task, plan=plan, reason=result.reason)
        runtime.complete_task(task_model)
        return BrowserExecutionResult(True, browser_task, plan=plan, reason="task completed")

    def _coerce_task(self, task: str | BrowserTask | Task) -> BrowserTask:
        if isinstance(task, str):
            return BrowserTask(description=task)
        if isinstance(task, BrowserTask):
            return task
        return BrowserTask(description=task.instruction.text, plan=(), status=task.status.value)


class _NoAuditSink:
    def record(self, event: object) -> None:  # pragma: no cover - no-op audit sink for tests
        return None


class _PassthroughKillSwitch:
    def is_engaged(self) -> bool:
        return False


__all__ = ["BrowserExecutionResult", "BrowserTaskRunner"]

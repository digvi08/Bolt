import asyncio
from uuid import uuid4

from agent_core.config import AgentConfig
from agent_core.models import ActionKind, Task, TrustedInstruction
from agent_core.runtime import AgentRuntime
from browser.models import BrowserAction, BrowserActionType
from browser.playwright_provider import BrowserActionProvider


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


class Switch:
    def __init__(self, engaged=False):
        self.engaged = engaged

    def is_engaged(self):
        return self.engaged


class Approval:
    def __init__(self, result):
        self.result = result

    def approve(self, request):
        return self.result


def run(coro):
    return asyncio.run(coro)


def test_browser_high_risk_submit_requires_approval():
    provider = BrowserActionProvider(None)  # type: ignore[arg-type]
    action = BrowserAction(BrowserActionType.SUBMIT, uuid4(), tab_id=uuid4(), target_id="submit")
    task = Task(TrustedInstruction("submit"))
    request = provider.register(action, task.id)
    audit = Audit()
    runtime = AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        provider,
        audit,
        Switch(),
        approval_provider=Approval(False),
    )
    result = run(runtime.run_async(task, request))
    assert not result.success
    assert "approval" in result.reason


def test_browser_kill_switch_prevents_execution():
    provider = BrowserActionProvider(None)  # type: ignore[arg-type]
    action = BrowserAction(BrowserActionType.OBSERVE, uuid4(), tab_id=uuid4())
    request = provider.register(action)
    audit = Audit()
    runtime = AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        provider,
        audit,
        Switch(True),
    )
    result = run(runtime.run_async(Task(TrustedInstruction("observe")), request))
    assert not result.success
    assert "kill switch" in result.reason
    assert provider._actions != {}

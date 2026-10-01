from uuid import uuid4

from agent_core.config import AgentConfig
from agent_core.models import (
    ActionKind,
    ActionRequest,
    ApprovalRequest,
    Task,
    TaskStatus,
    TrustedInstruction,
    VerificationResult,
)
from agent_core.runtime import AgentRuntime


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


class Actions:
    def __init__(self, value="ok", error=None):
        self.calls = 0
        self.value = value
        self.error = error

    def execute(self, action):
        self.calls += 1
        if self.error:
            raise self.error
        return self.value


class Approval:
    def __init__(self, result):
        self.result = result
        self.requests = []

    def approve(self, request: ApprovalRequest):
        self.requests.append(request)
        return self.result


class Verifier:
    def __init__(self, result):
        self.result = result

    def verify(self, action, result):
        return self.result


class Recovery:
    def __init__(self):
        self.calls = []

    def recover(self, task_id, error):
        self.calls.append((task_id, error))


def task():
    return Task(TrustedInstruction("read a status"))


def action(kind=ActionKind.READ_ONLY, *, task_id=None):
    return ActionRequest(task_id or uuid4(), "status", kind)


def runtime(actions, switch=None, approval=None, verifier=None, recovery=None):
    return AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.READ_ONLY, ActionKind.WRITE_FILE})),
        actions,
        audit := Audit(),
        switch or Switch(),
        approval,
        verifier,
        recovery,
    ), audit


def test_low_risk_action_executes_and_is_audited():
    actions = Actions()
    runtime_instance, audit = runtime(actions)
    current_task = task()
    result = runtime_instance.run(current_task, action(task_id=current_task.id))
    assert result.success and result.value == "ok"
    assert current_task.status is TaskStatus.SUCCEEDED
    assert actions.calls == 1
    assert [event.event_type for event in audit.events] == [
        "task.started", "policy.evaluated", "task.succeeded"
    ]


def test_kill_switch_prevents_provider_call():
    actions = Actions()
    runtime_instance, audit = runtime(actions, Switch(engaged=True))
    current_task = task()
    result = runtime_instance.run(current_task, action(task_id=current_task.id))
    assert not result.success and "kill switch" in result.reason
    assert current_task.status is TaskStatus.STOPPED
    assert actions.calls == 0
    assert audit.events[-1].event_type == "task.stopped"


def test_denied_high_risk_never_reaches_provider():
    actions = Actions()
    runtime_instance, _ = runtime(actions)
    current_task = task()
    result = runtime_instance.run(current_task, action(ActionKind.NETWORK, task_id=current_task.id))
    assert not result.success
    assert actions.calls == 0


def test_medium_risk_requires_and_honors_approval():
    actions = Actions()
    approval = Approval(True)
    runtime_instance, _ = runtime(actions, approval=approval)
    current_task = task()
    result = runtime_instance.run(current_task, action(ActionKind.WRITE_FILE, task_id=current_task.id))
    assert result.success
    assert len(approval.requests) == 1


def test_missing_approval_denies_medium_risk():
    actions = Actions()
    runtime_instance, _ = runtime(actions)
    current_task = task()
    result = runtime_instance.run(current_task, action(ActionKind.WRITE_FILE, task_id=current_task.id))
    assert not result.success and "approval" in result.reason
    assert actions.calls == 0


def test_verification_failure_triggers_recovery_without_exposing_error():
    actions = Actions()
    recovery = Recovery()
    runtime_instance, audit = runtime(
        actions,
        verifier=Verifier(VerificationResult(False, "state mismatch")),
        recovery=recovery,
    )
    current_task = task()
    result = runtime_instance.run(current_task, action(task_id=current_task.id))
    assert not result.success and result.reason == "execution failed"
    assert len(recovery.calls) == 1
    assert audit.events[-1].event_type == "recovery.started"

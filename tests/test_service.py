import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult
from abilities.registry import AbilityRegistry
from agent_brain.executor import AgentExecutionLoop
from agent_core.config import AgentConfig
from agent_core.models import (
    ActionKind,
    ActionRequest,
    AuditEvent,
    TaskStatus,
)
from agent_core.persistence import (
    ActionExecutionRecord,
    ActionExecutionStatus,
    ScheduleStatus,
    ScheduleType,
    SQLiteTaskStore,
    TaskRecord,
    VerificationStatus,
)
from agent_core.runtime import (
    ActionReconciliationOutcome,
    ActionReconciliationResult,
    AgentRuntime,
)
from agent_core.scheduler import TaskScheduler
from agent_core.service import (
    AgentService,
    AgentServiceError,
    CancelTaskRequest,
    ScheduleRequest,
    ServiceErrorCode,
    SubmitTaskRequest,
)


class Audit:
    def record(self, _event: AuditEvent) -> None:
        return None


class Switch:
    def __init__(self, engaged: bool = False) -> None:
        self.engaged = engaged

    def is_engaged(self) -> bool:
        return self.engaged


class Provider:
    ability = "browser"
    descriptor = AbilityDescriptor(
        name="browser",
        description="test provider",
        supported_actions=("navigate", "observe", "fill", "submit"),
        risk_classes=("low", "medium", "high"),
        provider="test",
    )

    def __init__(
        self,
        *,
        started: threading.Event | None = None,
        release: threading.Event | None = None,
        result_value: object | None = None,
    ) -> None:
        self.calls = 0
        self.started = started
        self.release = release
        self.result_value = result_value

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        self.calls += 1
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            self.release.wait(timeout=2)
        return AbilityResult(True, value=self.result_value or {"ok": True})


class Approval:
    def approve(self, _request) -> bool:
        return True


class AsyncProvider:
    def __init__(self, gate: asyncio.Event | None = None) -> None:
        self.calls = 0
        self.gate = gate
        self.started: asyncio.Event | None = None

    async def execute_async(self, _action: ActionRequest) -> object:
        self.calls += 1
        if self.started is not None:
            self.started.set()
        if self.gate is not None:
            await self.gate.wait()
        return {"ok": True}


class Reconciler:
    def __init__(self, outcome: ActionReconciliationOutcome) -> None:
        self.outcome = outcome
        self.calls = 0

    def reconcile(self, _request):
        self.calls += 1
        time.sleep(0.02)
        return ActionReconciliationResult(self.outcome, "independent evidence")


def make_service(
    tmp_path,
    *,
    switch: Switch | None = None,
    reconciler=None,
    async_provider: AsyncProvider | None = None,
    runtime_allowed: frozenset[ActionKind] = frozenset({ActionKind.READ_ONLY}),
    executor_allowed: frozenset[ActionKind] = frozenset({ActionKind.BROWSER}),
    provider: Provider | None = None,
):
    store = SQLiteTaskStore(tmp_path / "service.db")
    switch = switch or Switch()
    provider = provider or Provider()
    registry = AbilityRegistry()
    registry.register(provider)
    executor = AgentExecutionLoop(
        registry,
        approval_provider=Approval(),
        kill_switch=switch,
        config=AgentConfig(allowed_actions=executor_allowed),
        state_store=store,
    )
    runtime = AgentRuntime(
        AgentConfig(allowed_actions=runtime_allowed),
        async_provider or AsyncProvider(),
        Audit(),
        switch,
        state_store=store,
        action_reconciler=reconciler,
    )
    scheduler = TaskScheduler(store, runtime)
    return (
        AgentService(store, executor, runtime, scheduler, scheduler_poll_interval_seconds=0.005),
        store,
        provider,
        runtime,
        scheduler,
    )


def persist_uncertain_action(store, runtime, task_id):
    store.save_task(TaskRecord(task_id=task_id, objective="reconcile"))
    action = ActionRequest(
        task_id,
        "test.read",
        ActionKind.READ_ONLY,
        parameters={"query": "status"},
        execution_id="execution-uncertain",
    )
    store.save_action(
        ActionExecutionRecord(
            action_id=action.execution_id,
            task_id=task_id,
            name=action.name,
            metadata={
                "kind": ActionKind.READ_ONLY.value,
                "provider_identity": "test",
                "parameters": action.parameters,
                "identity_fingerprint": runtime._action_fingerprint(action),
            },
        )
    )
    record = store.get_action(task_id, action.execution_id)
    assert record is not None
    record.status = ActionExecutionStatus.EXECUTING
    record.attempts = 1
    store.save_action(record)
    record.status = ActionExecutionStatus.UNCERTAIN
    store.save_action(record)
    return action


def test_task_submission_and_idempotency_reuse_one_execution(tmp_path):
    service, store, provider, _, _ = make_service(tmp_path)
    request = SubmitTaskRequest(
        "Open the test site and inspect the page.",
        idempotency_key="request-1",
    )

    first = service.submit_task(request)
    second = service.submit_task(request)

    assert first.success
    assert first.task.task_id == second.task.task_id
    assert first.duplicate is False and second.duplicate is True
    assert provider.calls == len(first.task.actions)
    assert store.list_task_records() and len(store.list_task_records()) == 1
    store.close()


def test_concurrent_duplicate_submissions_are_serialized_and_idempotent(tmp_path):
    service, store, provider, _, _ = make_service(tmp_path)
    request = SubmitTaskRequest(
        "Open the test site and inspect the page.",
        idempotency_key="concurrent-request",
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: service.submit_task(request), range(2)))

    assert results[0].task.task_id == results[1].task.task_id
    assert sum(not result.duplicate for result in results) == 1
    assert len(store.list_task_records()) == 1
    assert provider.calls == len(results[0].task.actions)
    store.close()


def test_running_synchronous_task_rejects_cancellation_without_faking_stop(tmp_path):
    started = threading.Event()
    release = threading.Event()
    provider = Provider(started=started, release=release)
    service, store, _, _, _ = make_service(tmp_path, provider=provider)
    request = SubmitTaskRequest(
        "Open the test site and inspect the page.",
        idempotency_key="running-task",
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(service.submit_task, request)
        assert started.wait(timeout=2)
        task_record = store.list_task_records()[0]
        assert task_record.status is TaskStatus.EXECUTING
        with pytest.raises(AgentServiceError) as error:
            service.cancel_task(CancelTaskRequest(task_record.task_id))
        assert error.value.code is ServiceErrorCode.CANCELLATION_REJECTED
        release.set()
        completed = pending.result(timeout=2)

    assert completed.success
    assert service.get_task(task_record.task_id).status is TaskStatus.SUCCEEDED
    assert provider.calls == len(completed.task.actions)
    store.close()


def test_idempotency_survives_service_restart_without_reexecution(tmp_path):
    service, store, provider, _, _ = make_service(tmp_path)
    request = SubmitTaskRequest(
        "Open the test site and inspect the page.",
        idempotency_key="durable-request",
    )
    first = service.submit_task(request)
    calls = provider.calls
    store.close()

    service2, reopened, provider2, _, _ = make_service(tmp_path)
    second = service2.submit_task(request)

    assert second.duplicate is True
    assert second.task.task_id == first.task.task_id
    assert second.success is True
    assert provider2.calls == 0
    assert calls == len(first.task.actions)
    reopened.close()


def test_idempotency_key_conflict_and_different_keys_are_independent(tmp_path):
    service, store, provider, _, _ = make_service(tmp_path)
    first = service.submit_task(
        SubmitTaskRequest("Open the test site and inspect the page.", idempotency_key="key-a")
    )
    with pytest.raises(AgentServiceError) as error:
        service.submit_task(
            SubmitTaskRequest("Open a different site and inspect it.", idempotency_key="key-a")
        )
    assert error.value.code is ServiceErrorCode.CONFLICT
    second = service.submit_task(
        SubmitTaskRequest("Open the test site and inspect the page.", idempotency_key="key-b")
    )
    assert first.task.task_id != second.task.task_id
    assert len(store.list_task_records()) == 2
    assert provider.calls == len(first.task.actions) + len(second.task.actions)
    store.close()


def test_status_and_audit_are_typed_filtered_and_sanitized(tmp_path):
    provider = Provider(
        result_value={
            "cookie": "session-secret-value",
            "authorization": "Bearer provider-secret-value",
        }
    )
    service, store, _, _, _ = make_service(tmp_path, provider=provider)
    result = service.submit_task(
        SubmitTaskRequest(
            "Open the page with password=supersecret and inspect it.",
            idempotency_key="private",
        )
    )
    status = service.get_task_status(result.task.task_id)
    assert status.task_id == result.task.task_id
    assert "supersecret" not in status.objective
    action = status.actions[0]
    events = service.list_audit_events(
        task_id=status.task_id,
        action_id=action.action_id,
        limit=20,
    )
    assert events
    assert all(event.task_id == status.task_id for event in events)
    assert all("supersecret" not in str(dict(event.details)) for event in events)
    response_text = str(status) + str(events)
    assert "session-secret-value" not in response_text
    assert "provider-secret-value" not in response_text
    assert service.scheduler_status().kill_switch_active is False
    store.close()


def test_task_cancellation_is_durable_and_terminal_cancellation_is_rejected(tmp_path):
    service, store, _, _, _ = make_service(tmp_path)
    task_id = uuid4()
    store.save_task(TaskRecord(task_id=task_id, objective="queued work"))

    cancelled = service.cancel_task(CancelTaskRequest(task_id))

    assert cancelled.task.status is TaskStatus.STOPPED
    assert cancelled.cancellation_requested is False
    with pytest.raises(AgentServiceError) as error:
        service.cancel_task(CancelTaskRequest(task_id))
    assert error.value.code is ServiceErrorCode.ALREADY_COMPLETED
    store.close()


def test_schedule_api_exposes_state_and_explicitly_rejects_cron(tmp_path):
    service, store, _, _, _ = make_service(tmp_path)
    run_at = datetime.now(UTC) + timedelta(hours=1)
    request = ScheduleRequest(
        objective="scheduled test",
        action_name="browser.observe",
        action_kind=ActionKind.BROWSER,
        run_at=run_at,
        parameters={},
        schedule_type=ScheduleType.INTERVAL,
        interval_seconds=3600,
    )
    created = service.create_schedule(request)
    assert service.get_schedule(created.schedule_id) == created
    disabled = service.disable_schedule(created.schedule_id)
    assert disabled.enabled is False
    enabled = service.enable_schedule(created.schedule_id)
    assert enabled.enabled is True
    cancelled = service.cancel_schedule(created.schedule_id)
    assert cancelled.status is ScheduleStatus.CANCELLED
    with pytest.raises(AgentServiceError) as error:
        service.create_schedule(
            ScheduleRequest(
                objective="cron",
                action_name="browser.observe",
                action_kind=ActionKind.BROWSER,
                run_at=run_at,
                parameters={},
                schedule_type=ScheduleType.CRON,
            )
        )
    assert error.value.code is ServiceErrorCode.UNSUPPORTED_CAPABILITY
    store.close()


def test_queued_scheduled_task_cancellation_cancels_schedule_without_execution(tmp_path):
    service, store, provider, _, _ = make_service(tmp_path)
    scheduled = service.create_schedule(
        ScheduleRequest(
            objective="cancel this future work",
            action_name="browser.observe",
            action_kind=ActionKind.BROWSER,
            run_at=datetime.now(UTC) + timedelta(hours=1),
            parameters={},
        )
    )

    result = service.cancel_task(CancelTaskRequest(scheduled.task_id))

    assert result.task.status is TaskStatus.STOPPED
    assert result.cancellation_requested is False
    assert service.get_schedule(scheduled.schedule_id).status is ScheduleStatus.CANCELLED
    assert provider.calls == 0
    store.close()


def test_schedule_cancellation_before_runtime_dispatch_wins(tmp_path):
    async def scenario():
        provider = AsyncProvider()
        service, store, _, _, scheduler = make_service(
            tmp_path,
            async_provider=provider,
        )
        schedule = service.create_schedule(
            ScheduleRequest(
                objective="cancel just before dispatch",
                action_name="test.read",
                action_kind=ActionKind.READ_ONLY,
                run_at=datetime.now(UTC) - timedelta(seconds=1),
                parameters={},
            )
        )
        entered = asyncio.Event()
        continue_dispatch = asyncio.Event()
        original_dispatch = scheduler._dispatch

        async def delayed_dispatch(record, occurrence, now):
            entered.set()
            await continue_dispatch.wait()
            return await original_dispatch(record, occurrence, now)

        scheduler._dispatch = delayed_dispatch
        polling = asyncio.create_task(service.run_scheduler_once())
        await asyncio.wait_for(entered.wait(), timeout=1)
        cancellation = service.cancel_task(CancelTaskRequest(schedule.task_id))
        assert cancellation.cancellation_requested
        continue_dispatch.set()
        results = await polling

        assert provider.calls == 0
        assert results[0].status.value == "cancelled"
        assert service.get_task(schedule.task_id).status is TaskStatus.STOPPED
        store.close()

    asyncio.run(scenario())


def test_uncertain_action_reconciliation_delegates_without_execution(tmp_path):
    reconciler = Reconciler(ActionReconciliationOutcome.CONFIRMED_COMPLETED)
    service, store, _, runtime, _ = make_service(
        tmp_path,
        reconciler=reconciler,
    )
    task_id = uuid4()
    action = persist_uncertain_action(store, runtime, task_id)

    response = service.request_reconciliation(task_id, action.execution_id)

    assert response.outcome is ActionReconciliationOutcome.CONFIRMED_COMPLETED
    assert response.uncertain is False
    saved = store.get_action(task_id, action.execution_id)
    assert saved is not None
    assert saved.status is ActionExecutionStatus.COMPLETED
    assert saved.verification_status is VerificationStatus.VERIFIED
    assert reconciler.calls == 1
    store.close()


def test_reconciliation_obeys_live_kill_switch_and_policy(tmp_path):
    switch = Switch()
    reconciler = Reconciler(ActionReconciliationOutcome.CONFIRMED_COMPLETED)
    service, store, _, runtime, _ = make_service(
        tmp_path,
        switch=switch,
        reconciler=reconciler,
    )
    task_id = uuid4()
    action = persist_uncertain_action(store, runtime, task_id)
    switch.engaged = True

    blocked = service.request_reconciliation(task_id, action.execution_id)

    assert blocked.outcome is ActionReconciliationOutcome.STILL_UNCERTAIN
    assert blocked.uncertain
    assert reconciler.calls == 0
    assert store.get_action(task_id, action.execution_id).status is ActionExecutionStatus.UNCERTAIN
    assert any(
        event.event_type == "reconciliation.blocked_by_kill_switch"
        for event in store.audit_events(task_id)
    )
    store.close()

    reconciler2 = Reconciler(ActionReconciliationOutcome.CONFIRMED_COMPLETED)
    service2, store2, _, runtime2, _ = make_service(
        tmp_path / "policy",
        reconciler=reconciler2,
        runtime_allowed=frozenset(),
    )
    task_id2 = uuid4()
    action2 = persist_uncertain_action(store2, runtime2, task_id2)
    policy_blocked = service2.request_reconciliation(task_id2, action2.execution_id)
    assert policy_blocked.outcome is ActionReconciliationOutcome.STILL_UNCERTAIN
    assert policy_blocked.uncertain
    assert reconciler2.calls == 0
    assert any(
        event.event_type == "reconciliation.blocked_by_current_policy"
        for event in store2.audit_events(task_id2)
    )
    store2.close()


def test_concurrent_reconciliation_requests_are_serialized(tmp_path):
    reconciler = Reconciler(ActionReconciliationOutcome.CONFIRMED_COMPLETED)
    service, store, _, runtime, _ = make_service(tmp_path, reconciler=reconciler)
    task_id = uuid4()
    action = persist_uncertain_action(store, runtime, task_id)

    def request():
        try:
            return service.request_reconciliation(task_id, action.execution_id)
        except AgentServiceError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: request(), range(2)))

    assert reconciler.calls == 1
    assert sum(
        item is not ServiceErrorCode.UNCERTAIN for item in outcomes
    ) == 1
    assert store.get_action(task_id, action.execution_id).status is ActionExecutionStatus.COMPLETED
    store.close()


def test_uncertain_action_cannot_be_cancelled_or_force_completed(tmp_path):
    runtime_provider = AsyncProvider()
    service, store, _, _, _scheduler = make_service(
        tmp_path,
        async_provider=runtime_provider,
    )
    task_id = uuid4()
    store.save_task(TaskRecord(task_id=task_id, objective="uncertain"))
    action_id = "uncertain-1"
    store.save_action(
        ActionExecutionRecord(
            action_id=action_id,
            task_id=task_id,
            name="test.read",
        )
    )
    record = store.get_action(task_id, action_id)
    assert record is not None
    record.status = ActionExecutionStatus.EXECUTING
    record.attempts = 1
    store.save_action(record)
    record.status = ActionExecutionStatus.UNCERTAIN
    store.save_action(record)

    with pytest.raises(AgentServiceError) as error:
        service.cancel_task(CancelTaskRequest(task_id))
    assert error.value.code is ServiceErrorCode.UNCERTAIN
    assert store.get_action(task_id, action_id).status is ActionExecutionStatus.UNCERTAIN
    assert service.get_uncertain_actions()[0].action_id == action_id

    pending_task_id = uuid4()
    store.save_task(TaskRecord(task_id=pending_task_id, objective="verification pending"))
    store.save_action(
        ActionExecutionRecord(
            action_id="verification-pending",
            task_id=pending_task_id,
            name="test.read",
        )
    )
    pending_record = store.get_action(pending_task_id, "verification-pending")
    assert pending_record is not None
    pending_record.status = ActionExecutionStatus.EXECUTING
    pending_record.attempts = 1
    store.save_action(pending_record)
    pending_record.status = ActionExecutionStatus.COMPLETED
    store.save_action(pending_record)
    with pytest.raises(AgentServiceError) as pending_error:
        service.cancel_task(CancelTaskRequest(pending_task_id))
    assert pending_error.value.code is ServiceErrorCode.UNCERTAIN
    assert runtime_provider.calls == 0
    store.close()


def test_scheduler_lifecycle_is_single_loop_restartable_and_shutdown_waits(tmp_path):
    async def scenario():
        gate = asyncio.Event()
        provider = AsyncProvider(gate)
        provider.started = asyncio.Event()
        service, store, _, _, _scheduler = make_service(
            tmp_path,
            async_provider=provider,
        )
        schedule = service.create_schedule(
            ScheduleRequest(
                objective="scheduled",
                action_name="test.read",
                action_kind=ActionKind.READ_ONLY,
                run_at=datetime.now(UTC) - timedelta(seconds=1),
                parameters={},
            )
        )

        first = await service.start_scheduler()
        same = await service.start_scheduler()
        assert first.running and same.running
        await asyncio.wait_for(provider.started.wait(), timeout=1)
        cancellation = service.cancel_task(CancelTaskRequest(schedule.task_id))
        assert cancellation.cancellation_requested is True
        assert service.get_schedule(schedule.schedule_id).cancellation_pending is True
        stopping = asyncio.create_task(service.stop_scheduler())
        await asyncio.sleep(0)
        assert not stopping.done()
        gate.set()
        stopped = await stopping
        assert stopped.running is False
        assert (await service.stop_scheduler()).running is False
        restarted = await service.start_scheduler()
        assert restarted.running
        await service.stop_scheduler()
        provider.gate = asyncio.Event()
        provider.started = asyncio.Event()
        pending_shutdown_schedule = service.create_schedule(
            ScheduleRequest(
                objective="wait for safe shutdown",
                action_name="test.read",
                action_kind=ActionKind.READ_ONLY,
                run_at=datetime.now(UTC) - timedelta(seconds=1),
                parameters={},
            )
        )
        await service.start_scheduler()
        await asyncio.wait_for(provider.started.wait(), timeout=1)
        shutting_down = asyncio.create_task(service.shutdown())
        await asyncio.sleep(0)
        assert not shutting_down.done()
        provider.gate.set()
        await shutting_down
        assert service.scheduler_status().shutdown
        assert store.list_occurrences(schedule.schedule_id)[0].status.value == "completed"
        assert (
            store.list_occurrences(pending_shutdown_schedule.schedule_id)[0].status.value
            == "completed"
        )
        store.close()

    asyncio.run(scenario())


def test_safety_status_and_invalid_requests_use_typed_errors(tmp_path):
    service, store, _, _, _ = make_service(tmp_path, switch=Switch(True))
    assert service.scheduler_status().kill_switch_active
    with pytest.raises(AgentServiceError) as invalid:
        service.submit_task(SubmitTaskRequest(""))
    assert invalid.value.code is ServiceErrorCode.INVALID_REQUEST
    with pytest.raises(AgentServiceError) as missing:
        service.get_task(uuid4())
    assert missing.value.code is ServiceErrorCode.TASK_NOT_FOUND
    store.close()


def test_task_submission_reports_live_kill_switch_and_policy_denials(tmp_path):
    blocked, store, provider, _, _ = make_service(tmp_path, switch=Switch(True))
    stopped = blocked.submit_task(
        SubmitTaskRequest(
            "Open the test site and inspect the page.",
            idempotency_key="blocked-kill",
        )
    )
    assert not stopped.success
    assert stopped.error.code is ServiceErrorCode.KILL_SWITCH_ACTIVE
    assert provider.calls == 0
    store.close()

    denied, store2, provider2, _, _ = make_service(
        tmp_path / "denied",
        executor_allowed=frozenset(),
    )
    result = denied.submit_task(
        SubmitTaskRequest(
            "Open the test site and inspect the page.",
            idempotency_key="blocked-policy",
        )
    )
    assert not result.success
    assert result.error.code is ServiceErrorCode.POLICY_DENIED
    assert provider2.calls == 0
    store2.close()

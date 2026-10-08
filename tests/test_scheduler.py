from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

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
from agent_core.persistence import (
    OccurrenceStatus,
    ScheduleStatus,
    ScheduleType,
    SQLiteTaskStore,
)
from agent_core.runtime import AgentRuntime, ExecutionResult
from agent_core.scheduler import ScheduledTask, TaskScheduler


class Audit:
    def __init__(self) -> None:
        self.events = []

    def record(self, event) -> None:
        self.events.append(event)


class Switch:
    def __init__(self, engaged: bool = False) -> None:
        self.engaged = engaged

    def is_engaged(self) -> bool:
        return self.engaged


class AsyncProvider:
    def __init__(self, *, gate: asyncio.Event | None = None, delay: float = 0) -> None:
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.gate = gate
        self.delay = delay

    async def execute_async(self, action):
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.gate is not None:
                await self.gate.wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            return {"ok": True}
        finally:
            self.active -= 1


class Approval:
    def __init__(self, approved: bool) -> None:
        self.approved = approved
        self.calls = 0

    def approve(self, request: ApprovalRequest) -> bool:
        self.calls += 1
        return self.approved


class Verifier:
    def __init__(self) -> None:
        self.calls = 0

    def verify(self, action, result) -> VerificationResult:
        self.calls += 1
        return VerificationResult(True, "independently verified")


def make_runtime(
    store: SQLiteTaskStore,
    provider: AsyncProvider,
    *,
    audit: Audit | None = None,
    switch: Switch | None = None,
    approval: Approval | None = None,
    allowed: frozenset[ActionKind] = frozenset({ActionKind.READ_ONLY}),
    verifier: Verifier | None = None,
) -> AgentRuntime:
    return AgentRuntime(
        AgentConfig(allowed_actions=allowed),
        provider,
        audit or Audit(),
        switch or Switch(),
        approval_provider=approval,
        verifier=verifier,
        state_store=store,
    )


def scheduled(
    *,
    run_at: datetime,
    kind: ActionKind = ActionKind.READ_ONLY,
    schedule_type: ScheduleType = ScheduleType.RUN_AT,
    interval_seconds: int | None = None,
    deadline_at: datetime | None = None,
    timeout: float | None = None,
    cron_expression: str | None = None,
    timezone_policy: str = "UTC",
) -> ScheduledTask:
    task_id = uuid4()
    return ScheduledTask(
        objective="perform scheduled test action",
        action=ActionRequest(
            task_id,
            "test.action",
            kind,
            parameters={"value": "test"},
        ),
        run_at=run_at,
        schedule_type=schedule_type,
        interval_seconds=interval_seconds,
        deadline_at=deadline_at,
        execution_timeout_seconds=timeout,
        cron_expression=cron_expression,
        timezone_policy=timezone_policy,
    )


def test_schedule_survives_restart_and_future_is_dormant(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(store, make_runtime(store, provider), clock=lambda: now)
    record = scheduler.create(scheduled(run_at=now + timedelta(hours=1)))
    store.close()

    reopened = SQLiteTaskStore(tmp_path / "state.db")
    scheduler = TaskScheduler(
        reopened,
        make_runtime(reopened, provider),
        clock=lambda: now,
    )
    assert reopened.load_schedule(record.schedule_id).next_run_at == now + timedelta(hours=1)
    assert asyncio.run(scheduler.run_once()) == []
    assert provider.calls == 0
    reopened.close()


def test_due_occurrence_runs_once_through_runtime_and_survives_reopen(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    verifier = Verifier()
    scheduler = TaskScheduler(
        store,
        make_runtime(store, provider, verifier=verifier),
        clock=lambda: now,
    )
    schedule = scheduler.create(scheduled(run_at=now))

    results = asyncio.run(scheduler.run_once())
    again = asyncio.run(scheduler.run_once())

    assert len(results) == 1 and results[0][1].success
    assert again == []
    assert provider.calls == 1
    assert verifier.calls == 1
    occurrence = store.list_occurrences(schedule.schedule_id)[0]
    assert occurrence.status is OccurrenceStatus.COMPLETED
    assert occurrence.execution_id == results[0][0].execution_id
    store.close()

    reopened = SQLiteTaskStore(tmp_path / "state.db")
    assert reopened.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.COMPLETED
    reopened.close()


def test_restart_with_dispatched_occurrence_and_completed_runtime_journal_does_not_redeliver(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(store, make_runtime(store, provider), clock=lambda: now)
    schedule = scheduler.create(scheduled(run_at=now))
    occurrence = store.create_due_occurrence(schedule.schedule_id, now)
    assert occurrence is not None
    occurrence.status = OccurrenceStatus.DISPATCHING
    store.update_occurrence(occurrence)
    runtime = make_runtime(store, provider)
    task_model = Task(
        instruction=TrustedInstruction(schedule.objective),
        id=schedule.task_id,
        status=TaskStatus.CREATED,
    )
    action_request = ActionRequest(
        task_id=schedule.task_id,
        name=schedule.action_name,
        kind=ActionKind.READ_ONLY,
        parameters=schedule.parameters,
        execution_id=occurrence.execution_id,
    )
    result = asyncio.run(runtime.run_async(task_model, action_request))
    assert result.success and provider.calls == 1
    occurrence.status = OccurrenceStatus.RUNNING
    store.update_occurrence(occurrence)
    store.close()

    reopened = SQLiteTaskStore(tmp_path / "state.db")
    fresh_provider = AsyncProvider()
    fresh_scheduler = TaskScheduler(
        reopened,
        make_runtime(reopened, fresh_provider),
        clock=lambda: now,
    )
    recovered = reopened.list_occurrences(schedule.schedule_id)[0]
    assert recovered.status is OccurrenceStatus.COMPLETED
    assert reopened.load_schedule(schedule.schedule_id).status is ScheduleStatus.COMPLETED
    assert asyncio.run(fresh_scheduler.run_once()) == []
    assert provider.calls == 1
    assert fresh_provider.calls == 0
    reopened.close()


def test_crash_after_external_success_before_occurrence_completion_is_recovered(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(store, make_runtime(store, provider), clock=lambda: now)
    schedule = scheduler.create(scheduled(run_at=now))
    original_update = store.update_occurrence

    def crash_before_occurrence_terminal(occurrence):
        if occurrence.status is OccurrenceStatus.COMPLETED:
            raise OSError("simulated scheduler crash")
        original_update(occurrence)

    store.update_occurrence = crash_before_occurrence_terminal
    with pytest.raises(OSError, match="simulated scheduler crash"):
        asyncio.run(scheduler.run_once())
    assert provider.calls == 1
    store.close()

    reopened = SQLiteTaskStore(tmp_path / "state.db")
    recovered_provider = AsyncProvider()
    recovered_scheduler = TaskScheduler(
        reopened,
        make_runtime(reopened, recovered_provider),
        clock=lambda: now,
    )
    assert reopened.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.COMPLETED
    assert reopened.load_schedule(schedule.schedule_id).status is ScheduleStatus.COMPLETED
    assert asyncio.run(recovered_scheduler.run_once()) == []
    assert recovered_provider.calls == 0
    reopened.close()


def test_recurring_schedule_advances_and_skips_backlog(tmp_path):
    start = datetime(2030, 1, 1, tzinfo=UTC)
    now = start + timedelta(seconds=35)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(
        store,
        make_runtime(store, provider),
        clock=lambda: now,
        misfire_grace_seconds=60,
    )
    schedule = scheduler.create(
        scheduled(
            run_at=start,
            schedule_type=ScheduleType.INTERVAL,
            interval_seconds=10,
        )
    )

    results = asyncio.run(scheduler.run_once())

    assert len(results) == 1 and results[0][1].success
    saved = store.load_schedule(schedule.schedule_id)
    assert saved is not None
    assert saved.next_run_at == start + timedelta(seconds=40)
    assert provider.calls == 1
    assert len(store.list_occurrences(schedule.schedule_id)) == 1
    assert any(event.event_type == "schedule.occurrence_created" for event in store.audit_events())
    store.close()


def test_missed_run_is_recorded_and_not_caught_up(tmp_path):
    start = datetime(2030, 1, 1, tzinfo=UTC)
    now = start + timedelta(hours=2)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(
        store,
        make_runtime(store, provider),
        clock=lambda: now,
        misfire_grace_seconds=5,
    )
    schedule = scheduler.create(scheduled(run_at=start))

    results = asyncio.run(scheduler.run_once())

    assert len(results) == 1
    assert results[0][0].status is OccurrenceStatus.MISSED
    assert results[0][1] is None
    assert provider.calls == 0
    assert store.load_schedule(schedule.schedule_id).status is ScheduleStatus.COMPLETED
    store.close()


def test_interval_schedule_persists_cancelled_state(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(store, make_runtime(store, provider), clock=lambda: now)
    schedule = scheduler.create(
        scheduled(
            run_at=now + timedelta(days=1),
            schedule_type=ScheduleType.INTERVAL,
            interval_seconds=3600,
        )
    )
    scheduler.cancel(schedule.schedule_id)
    store.close()

    reopened = SQLiteTaskStore(tmp_path / "state.db")
    cancelled = reopened.load_schedule(schedule.schedule_id)
    assert cancelled is not None
    assert cancelled.status is ScheduleStatus.CANCELLED
    assert not cancelled.enabled
    reopened.close()


def test_concurrency_capacity_is_bounded_and_released(tmp_path):
    async def scenario():
        now = datetime(2030, 1, 1, tzinfo=UTC)
        gate = asyncio.Event()
        store = SQLiteTaskStore(tmp_path / "state.db")
        provider = AsyncProvider(gate=gate)
        scheduler = TaskScheduler(
            store,
            make_runtime(store, provider),
            max_concurrent_tasks=2,
            clock=lambda: now,
        )
        schedules = [
            scheduler.create(scheduled(run_at=now))
            for _ in range(3)
        ]
        cycle = asyncio.create_task(scheduler.run_once())
        for _ in range(100):
            if provider.calls == 2:
                break
            await asyncio.sleep(0)
        assert provider.calls == 2
        assert provider.max_active == 2
        gate.set()
        await cycle
        assert provider.calls == 2

        await scheduler.run_once()
        assert provider.calls == 3
        assert provider.max_active <= 2
        assert all(
            store.list_occurrences(item.schedule_id)[0].status is OccurrenceStatus.COMPLETED
            for item in schedules
        )
        store.close()

    asyncio.run(scenario())


def test_kill_switch_blocks_scheduled_execution(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    audit = Audit()
    scheduler = TaskScheduler(
        store,
        make_runtime(store, provider, audit=audit, switch=Switch(True)),
        clock=lambda: now,
    )
    schedule = scheduler.create(scheduled(run_at=now))

    results = asyncio.run(scheduler.run_once())

    assert not results[0][1].success
    assert provider.calls == 0
    assert store.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.FAILED
    assert any(event.event_type == "schedule.dispatch_denied" for event in store.audit_events())
    store.close()


def test_current_policy_and_approval_cannot_be_bypassed_by_schedule_data(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    approval = Approval(False)
    scheduler = TaskScheduler(
        store,
        make_runtime(
            store,
            provider,
            approval=approval,
            allowed=frozenset({ActionKind.BROWSER}),
        ),
        clock=lambda: now,
    )
    schedule = scheduler.create(scheduled(run_at=now, kind=ActionKind.BROWSER))

    result = asyncio.run(scheduler.run_once())[0][1]

    assert result is not None and not result.success
    assert provider.calls == 0
    assert approval.calls == 1
    assert store.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.FAILED
    store.close()


def test_execution_timeout_marks_uncertain_without_cancelling_external_work(tmp_path):
    async def scenario():
        now = datetime(2030, 1, 1, tzinfo=UTC)
        gate = asyncio.Event()
        store = SQLiteTaskStore(tmp_path / "state.db")
        provider = AsyncProvider(gate=gate)
        scheduler = TaskScheduler(
            store,
            make_runtime(store, provider),
            clock=lambda: now,
        )
        schedule = scheduler.create(
            scheduled(run_at=now, timeout=0.001)
        )

        result = await scheduler.run_once()
        occurrence = store.list_occurrences(schedule.schedule_id)[0]
        assert result[0][1] is not None and not result[0][1].success
        assert occurrence.status is OccurrenceStatus.UNCERTAIN
        assert provider.calls == 1

        gate.set()
        await scheduler.close()
        assert store.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.COMPLETED
        assert store.load_schedule(schedule.schedule_id).status is ScheduleStatus.COMPLETED
        store.close()

    asyncio.run(scenario())


def test_running_cancellation_is_cooperative_and_never_fabricates_success(tmp_path):
    async def scenario():
        now = datetime(2030, 1, 1, tzinfo=UTC)
        gate = asyncio.Event()
        store = SQLiteTaskStore(tmp_path / "state.db")
        provider = AsyncProvider(gate=gate)
        scheduler = TaskScheduler(
            store,
            make_runtime(store, provider),
            clock=lambda: now,
        )
        schedule = scheduler.create(scheduled(run_at=now))
        cycle = asyncio.create_task(scheduler.run_once())
        for _ in range(100):
            if provider.calls:
                break
            await asyncio.sleep(0)
        scheduler.cancel(schedule.schedule_id)
        assert store.list_occurrences(schedule.schedule_id)[0].cancellation_requested
        gate.set()
        await cycle
        assert store.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.COMPLETED
        assert provider.calls == 1
        store.close()

    asyncio.run(scenario())


def test_run_forever_dispatches_due_schedule_until_stopped(tmp_path):
    async def scenario():
        now = datetime(2030, 1, 1, tzinfo=UTC)
        store = SQLiteTaskStore(tmp_path / "state.db")
        provider = AsyncProvider()
        scheduler = TaskScheduler(
            store,
            make_runtime(store, provider),
            clock=lambda: now,
        )
        schedule = scheduler.create(scheduled(run_at=now))
        stop_event = asyncio.Event()
        worker = asyncio.create_task(
            scheduler.run_forever(poll_interval_seconds=0.001, stop_event=stop_event)
        )

        for _ in range(100):
            if provider.calls:
                break
            await asyncio.sleep(0.001)
        stop_event.set()
        await worker

        assert provider.calls == 1
        assert store.list_occurrences(schedule.schedule_id)[0].status is OccurrenceStatus.COMPLETED
        store.close()

    asyncio.run(scenario())


def test_weekday_cron_schedule_is_persisted_without_a_cron_dependency(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    store = SQLiteTaskStore(tmp_path / "state.db")
    provider = AsyncProvider()
    scheduler = TaskScheduler(store, make_runtime(store, provider), clock=lambda: now)

    schedule = scheduler.create(
        scheduled(
            run_at=now,
            schedule_type=ScheduleType.CRON,
            cron_expression="0 8 * * 1-5",
            timezone_policy="UTC",
        )
    )
    assert schedule.next_run_at == datetime(2030, 1, 1, 8, tzinfo=UTC)
    assert schedule.cron_expression == "0 8 * * 1-5"
    assert schedule.timezone_policy == "UTC"
    assert provider.calls == 0
    store.close()


def test_interrupted_objective_planning_is_uncertain_and_not_redelivered(tmp_path):
    now = datetime(2030, 1, 1, tzinfo=UTC)
    database_path = tmp_path / "state.db"
    store = SQLiteTaskStore(database_path)
    provider = AsyncProvider()
    scheduler = TaskScheduler(store, make_runtime(store, provider), clock=lambda: now)
    schedule = scheduler.create(
        ScheduledTask(
            objective="research a topic and save a report",
            action=None,
            run_at=now,
            execution_mode="objective",
            caller_id="research-operator",
        )
    )
    occurrence = store.create_due_occurrence(schedule.schedule_id, now)
    assert occurrence is not None
    occurrence.status = OccurrenceStatus.DISPATCHING
    store.update_occurrence(occurrence)
    occurrence.status = OccurrenceStatus.RUNNING
    store.update_occurrence(occurrence)
    store.save_task(
        Task(
            instruction=TrustedInstruction("research a topic and save a report"),
            id=occurrence.task_id,
            objective="research a topic and save a report",
            caller_id="research-operator",
            current_phase="planning",
        )
    )
    store.close()

    reopened = SQLiteTaskStore(database_path)
    fresh_provider = AsyncProvider()
    recovered_scheduler = TaskScheduler(
        reopened,
        make_runtime(reopened, fresh_provider),
        clock=lambda: now,
    )
    dispatches = []
    recovered_scheduler.set_objective_executor(
        lambda objective, task_id, caller_id: (
            dispatches.append((objective, task_id, caller_id))
            or ExecutionResult(True)
        )
    )

    recovered = reopened.list_occurrences(schedule.schedule_id)[0]
    assert recovered.status is OccurrenceStatus.UNCERTAIN
    assert "restarted during dispatch" in recovered.failure_reason
    assert asyncio.run(recovered_scheduler.run_once()) == []
    assert dispatches == []
    assert fresh_provider.calls == 0
    reopened.close()

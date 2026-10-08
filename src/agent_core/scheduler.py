"""Durable, bounded task scheduling through the existing AgentRuntime gate."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from .models import (
    ActionKind,
    ActionRequest,
    AuditEvent,
    CredentialCallerId,
    Task,
    TaskStatus,
    TrustedInstruction,
)
from .persistence import (
    OccurrenceStatus,
    ScheduleOccurrence,
    ScheduleRecord,
    ScheduleStatus,
    ScheduleType,
    TaskStateStore,
    next_weekday_cron_time,
)
from .runtime import AgentRuntime, ExecutionResult
from .secrets import sanitize_value


@dataclass(frozen=True)
class ScheduledTask:
    objective: str
    action: ActionRequest | None
    run_at: datetime
    schedule_type: ScheduleType = ScheduleType.RUN_AT
    interval_seconds: int | None = None
    end_at: datetime | None = None
    deadline_at: datetime | None = None
    execution_timeout_seconds: float | None = None
    schedule_id: str = ""
    task_id: UUID | None = None
    execution_mode: str = "action"
    caller_id: str = "local"
    cron_expression: str | None = None
    timezone_policy: str = "UTC"


class TaskScheduler:
    """Bounded async lifecycle owner; each action is delegated to AgentRuntime."""

    def __init__(
        self,
        store: TaskStateStore,
        runtime: AgentRuntime,
        *,
        max_concurrent_tasks: int = 1,
        clock: Callable[[], datetime] | None = None,
        misfire_grace_seconds: int = 60,
    ) -> None:
        if max_concurrent_tasks < 1:
            raise ValueError("max_concurrent_tasks must be positive")
        if misfire_grace_seconds < 0:
            raise ValueError("misfire_grace_seconds cannot be negative")
        self._store = store
        self._runtime = runtime
        self._objective_executor: Callable[[str, UUID, str], ExecutionResult] | None = None
        self._max_concurrent_tasks = max_concurrent_tasks
        self._clock = clock or (lambda: datetime.now(UTC))
        self._misfire_grace_seconds = misfire_grace_seconds
        self._accepting = True
        self._claim_lock = asyncio.Lock()
        self._active_occurrences: set[str] = set()
        self._background: set[asyncio.Task[None]] = set()
        self._workers: set[asyncio.Task[tuple[ScheduleOccurrence, ExecutionResult | None]]] = set()
        self.recover()

    def create(self, scheduled: ScheduledTask) -> ScheduleRecord:
        if scheduled.run_at.tzinfo is None:
            raise ValueError("scheduled time must be timezone-aware")
        if scheduled.execution_mode not in {"action", "objective"}:
            raise ValueError("unsupported scheduled execution mode")
        if scheduled.execution_mode == "action" and scheduled.action is None:
            raise ValueError("action schedules require an action request")
        if scheduled.execution_mode == "objective" and scheduled.action is not None:
            raise ValueError("objective schedules cannot contain a direct action")
        if (
            scheduled.action is not None
            and scheduled.action.task_id != (scheduled.task_id or scheduled.action.task_id)
        ):
            raise ValueError("scheduled action/task identity mismatch")
        if scheduled.schedule_type is ScheduleType.INTERVAL and (
            scheduled.interval_seconds is None or scheduled.interval_seconds < 1
        ):
            raise ValueError("interval schedules require a positive interval")
        if scheduled.schedule_type is ScheduleType.RUN_AT and scheduled.interval_seconds is not None:
            raise ValueError("run-at schedules cannot have an interval")
        if scheduled.schedule_type is ScheduleType.CRON:
            if scheduled.interval_seconds is not None or not scheduled.cron_expression:
                raise ValueError("cron schedules require a supported expression")
            next_run_at = next_weekday_cron_time(
                min(self._aware_now(), scheduled.run_at.astimezone(UTC) - timedelta(microseconds=1)),
                scheduled.cron_expression,
                scheduled.timezone_policy,
            )
        else:
            if scheduled.cron_expression is not None:
                raise ValueError("cron expression is valid only for cron schedules")
            next_run_at = scheduled.run_at.astimezone(UTC)
        if scheduled.execution_timeout_seconds is not None and scheduled.execution_timeout_seconds <= 0:
            raise ValueError("execution timeout must be positive")

        task_id = scheduled.task_id or (
            scheduled.action.task_id if scheduled.action is not None else uuid4()
        )
        task = self._store.load_task(task_id)
        if task is None:
            self._store.save_task(
                Task(
                    instruction=TrustedInstruction(scheduled.objective),
                    id=task_id,
                    objective=scheduled.objective,
                    caller_id=CredentialCallerId(scheduled.caller_id),
                    status=TaskStatus.CREATED,
                    current_phase="scheduled",
                )
            )
        schedule = ScheduleRecord(
            schedule_id=scheduled.schedule_id or str(uuid4()),
            task_id=task_id,
            objective=scheduled.objective,
            action_name=scheduled.action.name if scheduled.action is not None else "agent.execute_objective",
            action_kind=(
                scheduled.action.kind.value
                if scheduled.action is not None and isinstance(scheduled.action.kind, ActionKind)
                else str(scheduled.action.kind) if scheduled.action is not None else ActionKind.UNKNOWN.value
            ),
            parameters=sanitize_value(scheduled.action.parameters) if scheduled.action is not None else {},
            schedule_type=scheduled.schedule_type,
            next_run_at=next_run_at,
            interval_seconds=scheduled.interval_seconds,
            end_at=scheduled.end_at.astimezone(UTC) if scheduled.end_at else None,
            deadline_at=scheduled.deadline_at.astimezone(UTC) if scheduled.deadline_at else None,
            execution_timeout_seconds=scheduled.execution_timeout_seconds,
            execution_mode=scheduled.execution_mode,
            caller_id=scheduled.caller_id,
            cron_expression=scheduled.cron_expression,
            timezone_policy=scheduled.timezone_policy,
        )
        return self._store.save_schedule(schedule)

    def set_objective_executor(
        self, executor: Callable[[str, UUID, str], ExecutionResult]
    ) -> None:
        self._objective_executor = executor

    def enable(self, schedule_id: str, enabled: bool = True) -> ScheduleRecord:
        schedule = self._require_schedule(schedule_id)
        if schedule.status in {ScheduleStatus.CANCELLED, ScheduleStatus.COMPLETED}:
            raise ValueError("terminal schedule cannot be enabled")
        schedule.enabled = enabled
        schedule.status = ScheduleStatus.SCHEDULED if enabled else ScheduleStatus.DISABLED
        return self._store.save_schedule(schedule)

    def cancel(self, schedule_id: str) -> ScheduleRecord | None:
        return self._store.cancel_schedule(schedule_id)

    def shutdown(self) -> None:
        self._accepting = False

    def kill_switch_active(self) -> bool:
        return self._runtime.kill_switch_active()

    async def close(self) -> None:
        self.shutdown()
        pending: list[asyncio.Task[Any]] = [
            *self._background,
            *self._workers,
        ]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def recover(self) -> list[ScheduleOccurrence]:
        """Fail closed on any occurrence that was in dispatch when the process stopped."""
        recovered: list[ScheduleOccurrence] = []
        for occurrence in self._store.list_occurrences():
            if occurrence.status not in {
                OccurrenceStatus.DISPATCHING,
                OccurrenceStatus.RUNNING,
            }:
                continue
            action = self._store.get_action(occurrence.task_id, occurrence.execution_id)
            if (
                action is not None
                and action.status.value == "completed"
                and action.verification_status.value in {"verified", "not_configured"}
            ):
                occurrence.status = OccurrenceStatus.COMPLETED
                occurrence.failure_reason = ""
                schedule = self._store.load_schedule(occurrence.schedule_id)
                if schedule is not None:
                    self._finish_run_at(schedule)
            else:
                occurrence.status = OccurrenceStatus.UNCERTAIN
                occurrence.failure_reason = "process restarted during dispatch; runtime reconciliation required"
            self._store.update_occurrence(occurrence)
            self._store.record_audit_event(
                AuditEvent(
                    "schedule.recovered_after_restart",
                    occurrence.task_id,
                    details={
                        "schedule_id": occurrence.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                        "state": occurrence.status.value,
                    },
                )
            )
            recovered.append(occurrence)
        return recovered

    async def run_once(self) -> list[tuple[ScheduleOccurrence, ExecutionResult | None]]:
        if not self._accepting:
            return []
        now = self._aware_now()
        claimed: list[tuple[ScheduleRecord, ScheduleOccurrence]] = []
        results: list[tuple[ScheduleOccurrence, ExecutionResult | None]] = []
        async with self._claim_lock:
            capacity = max(0, self._max_concurrent_tasks - len(self._active_occurrences))
            due_schedules = [
                schedule
                for schedule in self._store.list_schedules()
                if schedule.enabled
                and schedule.status is ScheduleStatus.SCHEDULED
                and schedule.next_run_at <= now
            ][:capacity]
            for schedule in due_schedules:
                lateness = max(0.0, (now - schedule.next_run_at).total_seconds())
                skipped = (
                    int(lateness // schedule.interval_seconds)
                    if schedule.schedule_type is ScheduleType.INTERVAL
                    and schedule.interval_seconds is not None
                    else 0
                )
                missed = lateness > self._misfire_grace_seconds
                if schedule.deadline_at is not None and now >= schedule.deadline_at:
                    missed = True
                occurrence = self._store.create_due_occurrence(
                    schedule.schedule_id,
                    now,
                    missed=missed,
                    skipped_intervals=skipped,
                )
                if occurrence is None:
                    continue
                if missed:
                    self._store.record_audit_event(
                        AuditEvent(
                            "schedule.occurrence_missed",
                            occurrence.task_id,
                            details={
                                "schedule_id": schedule.schedule_id,
                                "occurrence_id": occurrence.occurrence_id,
                                "skipped_intervals": skipped,
                            },
                        )
                    )
                    results.append((occurrence, None))
                    continue
                occurrence.status = OccurrenceStatus.DISPATCHING
                try:
                    self._store.update_occurrence(occurrence)
                except ValueError:
                    current = self._get_occurrence(schedule.schedule_id, occurrence.occurrence_id)
                    if current is not None:
                        results.append((current, None))
                    continue
                self._active_occurrences.add(self._occurrence_key(occurrence))
                claimed.append((schedule, occurrence))

        async def dispatch_and_release(
            schedule: ScheduleRecord, occurrence: ScheduleOccurrence
        ) -> tuple[ScheduleOccurrence, ExecutionResult | None]:
            release_capacity = True
            try:
                dispatched, keep_slot = await self._dispatch(schedule, occurrence, now)
                release_capacity = not keep_slot
                return occurrence, dispatched
            finally:
                if release_capacity:
                    self._active_occurrences.discard(self._occurrence_key(occurrence))

        if claimed:
            workers = [
                asyncio.create_task(dispatch_and_release(schedule, occurrence))
                for schedule, occurrence in claimed
            ]
            self._workers.update(workers)
            for worker in workers:
                worker.add_done_callback(self._workers.discard)
            dispatched = await asyncio.gather(*workers)
            results.extend(dispatched)
        return results

    async def _dispatch(
        self,
        schedule: ScheduleRecord,
        occurrence: ScheduleOccurrence,
        now: datetime,
    ) -> tuple[ExecutionResult, bool]:
        current_occurrence = self._get_occurrence(
            occurrence.schedule_id, occurrence.occurrence_id
        )
        if current_occurrence is not None:
            occurrence.cancellation_requested = current_occurrence.cancellation_requested
        if occurrence.cancellation_requested:
            occurrence.status = OccurrenceStatus.CANCELLED
            occurrence.failure_reason = "cancelled before runtime dispatch"
            self._store.update_occurrence(occurrence)
            task_record = self._store.load_task(occurrence.task_id)
            if task_record is not None and task_record.status in {
                TaskStatus.CREATED,
                TaskStatus.PLANNED,
            }:
                task_record.status = TaskStatus.STOPPED
                task_record.current_phase = "cancelled"
                task_record.termination_reason = occurrence.failure_reason
                self._store.save_task(task_record)
            self._store.record_audit_event(
                AuditEvent(
                    "schedule.cancelled_before_dispatch",
                    occurrence.task_id,
                    details={
                        "schedule_id": occurrence.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                    },
                )
            )
            return (
                ExecutionResult(
                    False,
                    reason="scheduled work was cancelled before dispatch",
                    failure_type="cancelled",
                ),
                False,
            )
        task_record = self._store.load_task(schedule.task_id)
        if task_record is None:
            return self._fail_occurrence(occurrence, "scheduled task record is missing", "schedule.dispatch_denied"), False

        occurrence.status = OccurrenceStatus.RUNNING
        self._store.update_occurrence(occurrence)
        task = Task(
            instruction=TrustedInstruction(schedule.objective),
            id=schedule.task_id,
            objective=schedule.objective,
            status=task_record.status,
            current_phase=task_record.current_phase,
            current_plan_version=task_record.current_plan_version,
            current_step=task_record.current_step,
            completed_steps=list(task_record.completed_steps),
            failed_steps=list(task_record.failed_steps),
            retry_count=task_record.retry_count,
            replan_count=task_record.replan_count,
            approval_state=task_record.approval_state,
            verification_state=task_record.verification_state,
            last_error=task_record.last_error,
            termination_reason=task_record.termination_reason,
            created_at=task_record.created_at,
            updated_at=task_record.updated_at,
            execution_metadata=dict(task_record.execution_metadata),
        )
        timeout = schedule.execution_timeout_seconds
        if occurrence.deadline_at is not None:
            remaining = (occurrence.deadline_at - now).total_seconds()
            if remaining <= 0:
                return self._fail_occurrence(occurrence, "task deadline exceeded", "schedule.deadline_exceeded"), False
            timeout = remaining if timeout is None else min(timeout, remaining)
        if schedule.execution_mode == "objective":
            executor = self._objective_executor
            if executor is None:
                return self._fail_occurrence(
                    occurrence,
                    "scheduled objective executor is unavailable",
                    "schedule.dispatch_denied",
                ), False
            objective_task = asyncio.create_task(
                asyncio.to_thread(
                    executor,
                    schedule.objective,
                    occurrence.task_id,
                    schedule.caller_id,
                )
            )
            if timeout is not None:
                done, _ = await asyncio.wait({objective_task}, timeout=timeout)
                if not done:
                    occurrence.status = OccurrenceStatus.UNCERTAIN
                    occurrence.failure_reason = (
                        "execution timeout; task pipeline outcome requires recovery"
                    )
                    self._store.update_occurrence(occurrence)
                    late_task = asyncio.create_task(
                        self._finish_late_dispatch(schedule, occurrence, objective_task)
                    )
                    self._background.add(late_task)
                    late_task.add_done_callback(self._background.discard)
                    return (
                        ExecutionResult(
                            False,
                            reason=occurrence.failure_reason,
                            failure_type="uncertain",
                        ),
                        True,
                    )
            try:
                result = (
                    objective_task.result()
                    if timeout is not None
                    else await objective_task
                )
            except asyncio.CancelledError:
                occurrence.status = OccurrenceStatus.UNCERTAIN
                occurrence.failure_reason = "scheduled task pipeline was cancelled while running"
                self._store.update_occurrence(occurrence)
                late_task = asyncio.create_task(
                    self._finish_late_dispatch(schedule, occurrence, objective_task)
                )
                self._background.add(late_task)
                late_task.add_done_callback(self._background.discard)
                return (
                    ExecutionResult(False, reason=occurrence.failure_reason, failure_type="uncertain"),
                    True,
                )
            except Exception as error:  # noqa: BLE001 - pipeline failure may have side effects
                occurrence.status = OccurrenceStatus.UNCERTAIN
                occurrence.failure_reason = sanitize_value(
                    f"{type(error).__name__}: {error}"
                )
                self._store.update_occurrence(occurrence)
                self._store.record_audit_event(
                    AuditEvent(
                        "schedule.occurrence_uncertain",
                        occurrence.task_id,
                        details={
                            "schedule_id": schedule.schedule_id,
                            "occurrence_id": occurrence.occurrence_id,
                        },
                    )
                )
                return (
                    ExecutionResult(
                        False,
                        reason="scheduled task pipeline outcome is uncertain",
                        failure_type="uncertain",
                    ),
                    False,
                )
            if result.success:
                occurrence.status = OccurrenceStatus.COMPLETED
                occurrence.failure_reason = ""
                self._store.update_occurrence(occurrence)
                self._finish_run_at(schedule)
                self._store.record_audit_event(
                    AuditEvent(
                        "schedule.task_completed",
                        occurrence.task_id,
                        details={
                            "schedule_id": schedule.schedule_id,
                            "occurrence_id": occurrence.occurrence_id,
                        },
                    )
                )
                return result, False
            task_record = self._store.load_task(occurrence.task_id)
            failure_type: str | None
            if task_record is not None and task_record.status is TaskStatus.AWAITING_APPROVAL:
                occurrence.status = OccurrenceStatus.AWAITING_APPROVAL
                event_type = "schedule.approval_pending"
                failure_type = "approval_pending"
            else:
                occurrence.status = (
                    OccurrenceStatus.UNCERTAIN
                    if result.failure_type in {"uncertain", "action_recovery_required"}
                    else OccurrenceStatus.FAILED
                )
                event_type = (
                    "schedule.occurrence_uncertain"
                    if occurrence.status is OccurrenceStatus.UNCERTAIN
                    else "schedule.task_failed"
                )
                failure_type = result.failure_type
            occurrence.failure_reason = sanitize_value(result.reason)
            self._store.update_occurrence(occurrence)
            self._store.record_audit_event(
                AuditEvent(
                    event_type,
                    occurrence.task_id,
                    details={
                        "schedule_id": schedule.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                        "failure_type": failure_type or "unknown",
                    },
                )
            )
            if occurrence.status is OccurrenceStatus.FAILED:
                self._finish_run_at(schedule, failed=True)
            return result, False

        if schedule.execution_mode != "action":
            return self._fail_occurrence(
                occurrence,
                "unsupported scheduled execution mode",
                "schedule.dispatch_denied",
            ), False
        try:
            action_kind = ActionKind(schedule.action_kind)
        except ValueError:
            action_kind = ActionKind.UNKNOWN
        action = ActionRequest(
            task_id=schedule.task_id,
            name=schedule.action_name,
            kind=action_kind,
            parameters=schedule.parameters,
            execution_id=occurrence.execution_id,
        )
        try:
            runtime_task = asyncio.create_task(self._runtime.run_async(task, action))
            if timeout is None:
                result = await runtime_task
            else:
                done, _ = await asyncio.wait({runtime_task}, timeout=timeout)
                if not done:
                    occurrence.status = OccurrenceStatus.UNCERTAIN
                    occurrence.failure_reason = "execution timeout; runtime action outcome requires recovery"
                    self._store.update_occurrence(occurrence)
                    self._store.record_audit_event(
                        AuditEvent(
                            "schedule.timeout",
                            occurrence.task_id,
                            details={
                                "schedule_id": occurrence.schedule_id,
                                "occurrence_id": occurrence.occurrence_id,
                            },
                        )
                    )
                    late_task = asyncio.create_task(
                        self._finish_late_dispatch(schedule, occurrence, runtime_task)
                    )
                    self._background.add(late_task)
                    late_task.add_done_callback(self._background.discard)
                    return (
                        ExecutionResult(
                            False,
                            reason=occurrence.failure_reason,
                            failure_type="uncertain",
                        ),
                        True,
                    )
                result = runtime_task.result()
        except asyncio.CancelledError:
            occurrence.status = OccurrenceStatus.UNCERTAIN
            occurrence.failure_reason = "scheduler dispatch cancelled while runtime action may be in flight"
            self._store.update_occurrence(occurrence)
            late_task = asyncio.create_task(
                self._finish_late_dispatch(schedule, occurrence, runtime_task)
            )
            self._background.add(late_task)
            late_task.add_done_callback(self._background.discard)
            return (
                ExecutionResult(
                    False,
                    reason=occurrence.failure_reason,
                    failure_type="uncertain",
                ),
                True,
            )
        except Exception as error:  # noqa: BLE001 - provider errors are represented as uncertain
            occurrence.status = OccurrenceStatus.UNCERTAIN
            occurrence.failure_reason = sanitize_value(f"{type(error).__name__}: {error}")
            self._store.update_occurrence(occurrence)
            return (
                ExecutionResult(
                    False,
                    reason="scheduled execution outcome uncertain",
                    failure_type="uncertain",
                ),
                False,
            )

        if result.success:
            occurrence.status = OccurrenceStatus.COMPLETED
            occurrence.failure_reason = ""
            self._store.update_occurrence(occurrence)
            self._finish_run_at(schedule)
            self._store.record_audit_event(
                AuditEvent(
                    "schedule.task_completed",
                    occurrence.task_id,
                    details={
                        "schedule_id": occurrence.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                    },
                )
            )
            return result, False

        occurrence.status = (
            OccurrenceStatus.UNCERTAIN
            if result.failure_type in {"uncertain", "action_recovery_required"}
            else OccurrenceStatus.FAILED
        )
        occurrence.failure_reason = sanitize_value(result.reason)
        event_type = (
            "schedule.dispatch_denied"
            if result.failure_type in {"policy_denied", "approval_denied", "kill_switch"}
            else "schedule.occurrence_uncertain"
            if occurrence.status is OccurrenceStatus.UNCERTAIN
            else "schedule.task_failed"
        )
        self._store.update_occurrence(occurrence)
        self._store.record_audit_event(
            AuditEvent(
                event_type,
                occurrence.task_id,
                details={
                    "schedule_id": occurrence.schedule_id,
                    "occurrence_id": occurrence.occurrence_id,
                    "failure_type": result.failure_type or "unknown",
                    "reason": occurrence.failure_reason,
                },
            )
        )
        if occurrence.status is OccurrenceStatus.FAILED:
            self._finish_run_at(schedule, failed=True)
        return result, False

    async def _finish_late_dispatch(
        self,
        schedule: ScheduleRecord,
        occurrence: ScheduleOccurrence,
        runtime_task: asyncio.Task[ExecutionResult],
    ) -> None:
        try:
            result = await runtime_task
        except asyncio.CancelledError:
            occurrence.failure_reason = "runtime task was cancelled; action outcome remains uncertain"
            self._store.update_occurrence(occurrence)
            self._store.record_audit_event(
                AuditEvent(
                    "schedule.occurrence_uncertain",
                    occurrence.task_id,
                    details={
                        "schedule_id": occurrence.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                        "reason": occurrence.failure_reason,
                    },
                )
            )
        except Exception as error:  # noqa: BLE001 - any late runtime failure leaves outcome uncertain
            occurrence.failure_reason = sanitize_value(f"{type(error).__name__}: {error}")
            self._store.update_occurrence(occurrence)
            self._store.record_audit_event(
                AuditEvent(
                    "schedule.occurrence_uncertain",
                    occurrence.task_id,
                    details={
                        "schedule_id": occurrence.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                        "reason": occurrence.failure_reason,
                    },
                )
            )
        else:
            if result.success:
                occurrence.status = OccurrenceStatus.COMPLETED
                occurrence.failure_reason = ""
                self._store.update_occurrence(occurrence)
                self._store.record_audit_event(
                    AuditEvent(
                        "schedule.task_completed",
                        occurrence.task_id,
                        details={
                            "schedule_id": occurrence.schedule_id,
                            "occurrence_id": occurrence.occurrence_id,
                            "completed_after_timeout": True,
                        },
                    )
                )
                self._finish_run_at(schedule)
        finally:
            self._active_occurrences.discard(self._occurrence_key(occurrence))

    async def retry_uncertain(
        self, schedule_id: str, occurrence_id: str
    ) -> ExecutionResult:
        """Request a retry; AgentRuntime remains the authority to allow or block it."""
        schedule = self._require_schedule(schedule_id)
        occurrence = self._get_occurrence(schedule_id, occurrence_id)
        if occurrence is None or occurrence.status is not OccurrenceStatus.UNCERTAIN:
            raise ValueError("only uncertain occurrences can be retried")
        if not self._accepting:
            raise RuntimeError("scheduler is shutting down")
        key = self._occurrence_key(occurrence)
        async with self._claim_lock:
            if key in self._active_occurrences:
                raise ValueError("occurrence is already active")
            if len(self._active_occurrences) >= self._max_concurrent_tasks:
                raise RuntimeError("scheduler concurrency capacity is full")
            self._active_occurrences.add(key)
            occurrence.status = OccurrenceStatus.DISPATCHING
            self._store.update_occurrence(occurrence)
        keep_slot = False
        try:
            result, keep_slot = await self._dispatch(schedule, occurrence, self._aware_now())
            return result
        finally:
            if not keep_slot:
                self._active_occurrences.discard(key)

    @staticmethod
    def _occurrence_key(occurrence: ScheduleOccurrence) -> str:
        return f"{occurrence.schedule_id}:{occurrence.occurrence_id}"

    def _fail_occurrence(
        self,
        occurrence: ScheduleOccurrence,
        reason: str,
        event_type: str,
    ) -> ExecutionResult:
        occurrence.status = OccurrenceStatus.FAILED
        occurrence.failure_reason = sanitize_value(reason)
        self._store.update_occurrence(occurrence)
        self._store.record_audit_event(
            AuditEvent(
                event_type,
                occurrence.task_id,
                details={
                    "schedule_id": occurrence.schedule_id,
                    "occurrence_id": occurrence.occurrence_id,
                    "reason": occurrence.failure_reason,
                },
            )
        )
        self._finish_run_at_by_id(occurrence.schedule_id, failed=True)
        return ExecutionResult(False, reason=occurrence.failure_reason)

    def _finish_run_at(self, schedule: ScheduleRecord, *, failed: bool = False) -> None:
        if schedule.schedule_type is not ScheduleType.RUN_AT:
            return
        current = self._store.load_schedule(schedule.schedule_id)
        if current is None or current.status is ScheduleStatus.CANCELLED:
            return
        current.enabled = False
        current.status = ScheduleStatus.FAILED if failed else ScheduleStatus.COMPLETED
        self._store.save_schedule(current)

    def _finish_run_at_by_id(self, schedule_id: str, *, failed: bool) -> None:
        schedule = self._store.load_schedule(schedule_id)
        if schedule is not None:
            self._finish_run_at(schedule, failed=failed)

    def _require_schedule(self, schedule_id: str) -> ScheduleRecord:
        schedule = self._store.load_schedule(schedule_id)
        if schedule is None:
            raise KeyError(f"unknown schedule: {schedule_id}")
        return schedule

    def _get_occurrence(
        self, schedule_id: str, occurrence_id: str
    ) -> ScheduleOccurrence | None:
        return next(
            (
                item
                for item in self._store.list_occurrences(schedule_id)
                if item.occurrence_id == occurrence_id
            ),
            None,
        )

    def _aware_now(self) -> datetime:
        current = self._clock()
        if current.tzinfo is None:
            raise ValueError("scheduler clock must return a timezone-aware datetime")
        return current.astimezone(UTC)

    async def run_forever(
        self,
        *,
        poll_interval_seconds: float = 1.0,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("poll interval must be positive")
        stop = stop_event or asyncio.Event()
        try:
            while self._accepting and not stop.is_set():
                await self.run_once()
                try:
                    await asyncio.wait_for(stop.wait(), timeout=poll_interval_seconds)
                except TimeoutError:
                    continue
        finally:
            await self.close()


__all__ = ["ScheduledTask", "TaskScheduler"]

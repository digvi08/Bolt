"""Backend-independent, untrusted-caller facade over agent execution and scheduling."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

from .models import ActionKind, ActionRequest, AuditEvent, TaskStatus
from .persistence import (
    ActionExecutionRecord,
    ActionExecutionStatus,
    IdempotencyConflict,
    OccurrenceStatus,
    ScheduleRecord,
    ScheduleStatus,
    ScheduleType,
    TaskRecord,
    TaskStateStore,
    VerificationStatus,
)
from .runtime import ActionReconciliationOutcome, AgentRuntime
from .scheduler import ScheduledTask, TaskScheduler
from .secrets import sanitize_text, sanitize_value

if TYPE_CHECKING:
    from agent_brain.context import ContextManager
    from agent_brain.models import AgentResult


class ServiceErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    TASK_NOT_FOUND = "task_not_found"
    SCHEDULE_NOT_FOUND = "schedule_not_found"
    AUTHORIZATION_REQUIRED = "authorization_required"
    POLICY_DENIED = "policy_denied"
    KILL_SWITCH_ACTIVE = "kill_switch_active"
    CANCELLATION_REJECTED = "cancellation_rejected"
    ALREADY_COMPLETED = "already_completed"
    UNCERTAIN = "uncertain"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    CONFLICT = "conflict"
    INTERNAL_FAILURE = "internal_failure"


class AgentServiceError(Exception):
    def __init__(self, code: ServiceErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = sanitize_text(message)


@dataclass(frozen=True)
class ServiceErrorInfo:
    code: ServiceErrorCode
    message: str


@dataclass(frozen=True)
class SubmitTaskRequest:
    objective: str
    idempotency_key: str | None = None
    caller_id: str = "local"


@dataclass(frozen=True)
class CancelTaskRequest:
    task_id: UUID | str


@dataclass(frozen=True)
class ActionStatusResponse:
    task_id: UUID
    action_id: str
    name: str
    status: ActionExecutionStatus
    verification_status: VerificationStatus
    attempts: int
    uncertain: bool
    created_at: datetime
    updated_at: datetime
    failure: str


@dataclass(frozen=True)
class TaskStatusResponse:
    task_id: UUID
    objective: str
    status: TaskStatus
    verification_state: str
    approval_required: bool
    denied: bool
    uncertain: bool
    retry_count: int
    replan_count: int
    created_at: datetime
    updated_at: datetime
    actions: tuple[ActionStatusResponse, ...]
    schedule_ids: tuple[str, ...]
    schedules: tuple[ScheduleResponse, ...]
    last_error: str


@dataclass(frozen=True)
class SubmitTaskResult:
    task: TaskStatusResponse
    success: bool
    duplicate: bool
    error: ServiceErrorInfo | None = None


@dataclass(frozen=True)
class CancelTaskResult:
    task: TaskStatusResponse
    cancellation_requested: bool


@dataclass(frozen=True)
class SchedulerOccurrenceResponse:
    schedule_id: str
    occurrence_id: str
    status: OccurrenceStatus
    success: bool | None
    uncertain: bool


@dataclass(frozen=True)
class ScheduleRequest:
    objective: str
    action_name: str
    action_kind: ActionKind | str
    run_at: datetime
    parameters: Mapping[str, Any]
    schedule_type: ScheduleType = ScheduleType.RUN_AT
    interval_seconds: int | None = None
    end_at: datetime | None = None
    deadline_at: datetime | None = None
    execution_timeout_seconds: float | None = None


@dataclass(frozen=True)
class ScheduleResponse:
    schedule_id: str
    task_id: UUID
    objective: str
    action_name: str
    action_kind: str
    schedule_type: ScheduleType
    status: ScheduleStatus
    enabled: bool
    next_occurrence: datetime | None
    cancellation_pending: bool
    interval_seconds: int | None
    occurrence_count: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class AuditEventResponse:
    event_type: str
    task_id: UUID
    occurred_at: datetime
    details: Mapping[str, Any]


@dataclass(frozen=True)
class ReconciliationResponse:
    task_id: UUID
    action_id: str
    outcome: ActionReconciliationOutcome
    uncertain: bool


@dataclass(frozen=True)
class SchedulerStatusResponse:
    running: bool
    shutdown: bool
    active_tasks: int
    active_occurrences: int
    uncertain_actions: int
    kill_switch_active: bool
    last_error: str


class TaskExecutor(Protocol):
    def kill_switch_active(self) -> bool: ...

    def run(
        self,
        user_request: str,
        *,
        context: ContextManager | None = None,
        task_id: UUID | None = None,
    ) -> AgentResult: ...


_AUDIT_DETAIL_KEYS = frozenset(
    {
        "from",
        "to",
        "allowed",
        "risk",
        "status",
        "state",
        "action_status",
        "failure_type",
        "execution_id",
        "action_id",
        "schedule_id",
        "occurrence_id",
        "source",
        "count",
        "retry_count",
        "replan_count",
        "requires_verification",
        "approved",
        "completed_after_timeout",
        "returned_count",
        "session_filtered",
        "provenance_filtered",
        "trust_filtered",
        "expired_excluded",
        "limit",
        "max_context_size",
        "request_id",
        "caller_id",
        "scope",
        "code",
        "endpoint",
        "method",
        "status_code",
    }
)


class AgentService:
    """Service facade; it requests work but grants no execution authority."""

    def __init__(
        self,
        store: TaskStateStore,
        task_executor: TaskExecutor,
        runtime: AgentRuntime,
        scheduler: TaskScheduler,
        *,
        scheduler_poll_interval_seconds: float = 1.0,
    ) -> None:
        if scheduler_poll_interval_seconds <= 0:
            raise ValueError("scheduler poll interval must be positive")
        self._store = store
        self._task_executor = task_executor
        self._runtime = runtime
        self._scheduler = scheduler
        self._poll_interval = scheduler_poll_interval_seconds
        self._lock = threading.RLock()
        self._submission_lock = threading.Lock()
        self._scheduler_task: asyncio.Task[None] | None = None
        self._scheduler_stop: asyncio.Event | None = None
        self._shutdown = False
        self._last_error = ""

    def submit_task(self, request: SubmitTaskRequest) -> SubmitTaskResult:
        with self._submission_lock:
            return self._submit_task(request)

    def _submit_task(self, request: SubmitTaskRequest) -> SubmitTaskResult:
        objective = self._validate_objective(request.objective)
        caller_id = self._validate_identity(request.caller_id, "caller_id")
        key = request.idempotency_key
        task_id = uuid4()
        duplicate = False
        if key is not None:
            key = self._validate_identity(key, "idempotency_key")
            request_fingerprint = hashlib.sha256(
                json.dumps({"objective": objective}, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            caller_hash = self._hash_identity(caller_id)
            key_hash = self._hash_identity(key)
            initial = TaskRecord(task_id=task_id, objective=objective)
            try:
                with self._lock:
                    task_id, created = self._store.register_idempotent_task(
                        caller_hash, key_hash, request_fingerprint, initial
                    )
                duplicate = not created
            except IdempotencyConflict as conflict:
                self._audit_service_event(
                    "service.idempotency_conflict",
                    task_id,
                    {"caller_hash": caller_hash, "key_hash": key_hash},
                )
                raise AgentServiceError(ServiceErrorCode.CONFLICT, str(conflict)) from None
        if duplicate:
            with self._lock:
                record = self._store.load_task(task_id)
            if record is None:
                raise AgentServiceError(
                    ServiceErrorCode.INTERNAL_FAILURE,
                    "reserved task state is unavailable; execution was not repeated",
                )
            return SubmitTaskResult(
                task=self._task_status(record),
                success=record.status in {TaskStatus.SUCCEEDED, TaskStatus.COMPLETED},
                duplicate=True,
                error=self._record_error(record),
            )

        try:
            result = self._task_executor.run(objective, task_id=task_id)
            with self._lock:
                record = self._store.load_task(task_id)
        except Exception:  # noqa: BLE001 - public boundary converts internal failures to safe typed errors
            self._audit_service_event("service.task_submission_failed", task_id, {})
            raise AgentServiceError(
                ServiceErrorCode.INTERNAL_FAILURE,
                "task submission failed; inspect persisted task state before retrying",
            ) from None
        if record is None:
            raise AgentServiceError(ServiceErrorCode.INTERNAL_FAILURE, "task state is unavailable")
        submission_error = self._submission_error(result, record)
        return SubmitTaskResult(
            task=self._task_status(record),
            success=bool(result.success),
            duplicate=False,
            error=submission_error,
        )

    def get_task(self, task_id: UUID | str) -> TaskStatusResponse:
        with self._lock:
            record = self._store.load_task(task_id)
        if record is None:
            raise AgentServiceError(ServiceErrorCode.TASK_NOT_FOUND, "task not found")
        return self._task_status(record)

    def get_task_status(self, task_id: UUID | str) -> TaskStatusResponse:
        return self.get_task(task_id)

    def list_tasks(self, *, limit: int = 100) -> tuple[TaskStatusResponse, ...]:
        self._validate_limit(limit)
        with self._lock:
            records = self._store.list_task_records(limit=limit)
        return tuple(self._task_status(record) for record in records)

    def cancel_task(self, request: CancelTaskRequest) -> CancelTaskResult:
        task_id = request.task_id
        record = self._load_task(task_id)
        if record.status in {
            TaskStatus.SUCCEEDED,
            TaskStatus.COMPLETED,
            TaskStatus.DENIED,
            TaskStatus.STOPPED,
            TaskStatus.ABORTED,
        }:
            raise AgentServiceError(ServiceErrorCode.ALREADY_COMPLETED, "task is already terminal")
        actions = self._store.list_actions(record.task_id)
        if any(
            action.status in {ActionExecutionStatus.UNCERTAIN, ActionExecutionStatus.RECONCILING}
            or (
                action.status is ActionExecutionStatus.COMPLETED
                and action.verification_status
                in {
                    VerificationStatus.PENDING,
                    VerificationStatus.FAILED,
                    VerificationStatus.UNCERTAIN,
                }
            )
            for action in actions
        ):
            raise AgentServiceError(ServiceErrorCode.UNCERTAIN, "uncertain work cannot be cancelled as completed")
        schedules = [
            schedule
            for schedule in self._store.list_schedules()
            if schedule.task_id == record.task_id
            and schedule.status not in {ScheduleStatus.CANCELLED, ScheduleStatus.COMPLETED}
        ]
        active = False
        for schedule in schedules:
            self._scheduler.cancel(schedule.schedule_id)
            active = active or any(
                occurrence.status in {OccurrenceStatus.DISPATCHING, OccurrenceStatus.RUNNING}
                for occurrence in self._store.list_occurrences(schedule.schedule_id)
            )
        if active:
            return CancelTaskResult(self.get_task(record.task_id), cancellation_requested=True)
        if record.status not in {TaskStatus.CREATED, TaskStatus.PLANNED, TaskStatus.FAILED}:
            raise AgentServiceError(
                ServiceErrorCode.CANCELLATION_REJECTED,
                "active task cancellation is not safely supported",
            )
        record.status = TaskStatus.STOPPED
        record.current_phase = "cancelled"
        record.termination_reason = "cancelled by service caller"
        with self._lock:
            self._store.save_task(record)
            self._store.record_audit_event(
                AuditEvent(
                    "service.task_cancelled",
                    record.task_id,
                    details={"status": record.status.value},
                )
            )
        return CancelTaskResult(self.get_task(record.task_id), cancellation_requested=False)

    def get_action(self, task_id: UUID | str, action_id: str) -> ActionStatusResponse:
        with self._lock:
            record = self._store.get_action(task_id, action_id)
            task_exists = self._store.load_task(task_id) is not None
        if record is None:
            if not task_exists:
                raise AgentServiceError(ServiceErrorCode.TASK_NOT_FOUND, "task not found")
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "action not found")
        return self._action_status(record)

    def get_action_by_id(self, action_id: str) -> ActionStatusResponse:
        with self._lock:
            record = self._store.find_action(action_id)
        if record is None:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "action not found")
        return self._action_status(record)

    def get_action_history_by_id(
        self, action_id: str, *, limit: int = 100
    ) -> tuple[ActionStatusResponse, ...]:
        action = self.get_action_by_id(action_id)
        return self.get_action_history(action.task_id, limit=limit)

    def get_action_history(
        self, task_id: UUID | str, *, limit: int = 100
    ) -> tuple[ActionStatusResponse, ...]:
        self._validate_limit(limit)
        self._load_task(task_id)
        return tuple(self._action_status(item) for item in self._store.list_actions(task_id)[:limit])

    def get_uncertain_actions(self, *, limit: int = 100) -> tuple[ActionStatusResponse, ...]:
        self._validate_limit(limit)
        records = self._store.list_uncertain_actions(limit=limit)
        return tuple(self._action_status(item) for item in records)

    def request_reconciliation(
        self, task_id: UUID | str, action_id: str
    ) -> ReconciliationResponse:
        record = self._store.get_action(task_id, action_id)
        if record is None:
            if self._store.load_task(task_id) is None:
                raise AgentServiceError(ServiceErrorCode.TASK_NOT_FOUND, "task not found")
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "action not found")
        if record.status is not ActionExecutionStatus.UNCERTAIN:
            raise AgentServiceError(ServiceErrorCode.UNCERTAIN, "action is not in an uncertain state")
        try:
            outcome = self._runtime.reconcile_action(task_id, action_id)
        except ValueError:
            raise AgentServiceError(ServiceErrorCode.UNCERTAIN, "reconciliation is unavailable") from None
        except Exception:  # noqa: BLE001 - internal/provider detail must not cross the service boundary
            raise AgentServiceError(
                ServiceErrorCode.INTERNAL_FAILURE,
                "reconciliation failed; persisted action state remains authoritative",
            ) from None
        with self._lock:
            refreshed = self._store.get_action(task_id, action_id)
        still_uncertain = refreshed is None or refreshed.status in {
            ActionExecutionStatus.UNCERTAIN,
            ActionExecutionStatus.RECONCILING,
        }
        return ReconciliationResponse(UUID(str(task_id)), action_id, outcome, still_uncertain)

    def create_schedule(self, request: ScheduleRequest) -> ScheduleResponse:
        if not isinstance(request.schedule_type, ScheduleType):
            try:
                schedule_type = ScheduleType(request.schedule_type)
            except (TypeError, ValueError):
                raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "invalid schedule type") from None
        else:
            schedule_type = request.schedule_type
        if schedule_type is ScheduleType.CRON:
            raise AgentServiceError(
                ServiceErrorCode.UNSUPPORTED_CAPABILITY,
                "cron schedules are not supported",
            )
        objective = self._validate_objective(request.objective)
        if not isinstance(request.action_name, str) or not request.action_name.strip():
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "action_name is required")
        try:
            kind = ActionKind(request.action_kind)
        except (TypeError, ValueError):
            kind = ActionKind.UNKNOWN
        if kind is ActionKind.UNKNOWN:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "unknown action kind is denied")
        if not isinstance(request.run_at, datetime) or request.run_at.tzinfo is None:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "run_at must be timezone-aware")
        if not isinstance(request.parameters, Mapping):
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "parameters must be a mapping")
        try:
            safe_parameters = sanitize_value(dict(request.parameters))
            if not all(isinstance(key, str) for key in safe_parameters):
                raise ValueError("parameter keys must be strings")
            json.dumps(safe_parameters)
        except (TypeError, ValueError):
            raise AgentServiceError(
                ServiceErrorCode.INVALID_REQUEST,
                "parameters must contain JSON-compatible values",
            ) from None
        task_id = uuid4()
        scheduled = ScheduledTask(
            objective=objective,
            action=ActionRequest(
                task_id=task_id,
                name=sanitize_text(request.action_name),
                kind=kind,
                parameters=safe_parameters,
            ),
            run_at=request.run_at,
            schedule_type=schedule_type,
            interval_seconds=request.interval_seconds,
            end_at=request.end_at,
            deadline_at=request.deadline_at,
            execution_timeout_seconds=request.execution_timeout_seconds,
            task_id=task_id,
        )
        try:
            return self._schedule_response(self._scheduler.create(scheduled))
        except ValueError as error:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, str(error)) from None

    def get_schedule(self, schedule_id: str) -> ScheduleResponse:
        schedule = self._scheduler_store_schedule(schedule_id)
        if schedule is None:
            raise AgentServiceError(ServiceErrorCode.SCHEDULE_NOT_FOUND, "schedule not found")
        return self._schedule_response(schedule)

    def list_schedules(self, *, limit: int = 100) -> tuple[ScheduleResponse, ...]:
        self._validate_limit(limit)
        schedules = self._store.list_schedules()[:limit]
        return tuple(self._schedule_response(item) for item in schedules)

    def cancel_schedule(self, schedule_id: str) -> ScheduleResponse:
        schedule = self._scheduler.cancel(schedule_id)
        if schedule is None:
            raise AgentServiceError(ServiceErrorCode.SCHEDULE_NOT_FOUND, "schedule not found")
        return self._schedule_response(schedule)

    def enable_schedule(self, schedule_id: str) -> ScheduleResponse:
        try:
            return self._schedule_response(self._scheduler.enable(schedule_id, True))
        except KeyError:
            raise AgentServiceError(ServiceErrorCode.SCHEDULE_NOT_FOUND, "schedule not found") from None
        except ValueError as error:
            raise AgentServiceError(ServiceErrorCode.CANCELLATION_REJECTED, str(error)) from None

    def disable_schedule(self, schedule_id: str) -> ScheduleResponse:
        try:
            return self._schedule_response(self._scheduler.enable(schedule_id, False))
        except KeyError:
            raise AgentServiceError(ServiceErrorCode.SCHEDULE_NOT_FOUND, "schedule not found") from None
        except ValueError as error:
            raise AgentServiceError(ServiceErrorCode.CANCELLATION_REJECTED, str(error)) from None

    async def run_scheduler_once(self) -> tuple[SchedulerOccurrenceResponse, ...]:
        try:
            results = await self._scheduler.run_once()
        except Exception:  # noqa: BLE001 - runtime details may contain provider secrets
            raise AgentServiceError(ServiceErrorCode.INTERNAL_FAILURE, "scheduler cycle failed") from None
        return tuple(
            SchedulerOccurrenceResponse(
                schedule_id=occurrence.schedule_id,
                occurrence_id=occurrence.occurrence_id,
                status=occurrence.status,
                success=result.success if result is not None else None,
                uncertain=occurrence.status is OccurrenceStatus.UNCERTAIN,
            )
            for occurrence, result in results
        )

    async def start_scheduler(self) -> SchedulerStatusResponse:
        if self._shutdown:
            raise AgentServiceError(ServiceErrorCode.CANCELLATION_REJECTED, "service is shut down")
        if self._scheduler_task is not None and not self._scheduler_task.done():
            return self.scheduler_status()
        self._scheduler_stop = asyncio.Event()
        self._scheduler_task = asyncio.create_task(self._scheduler_loop(self._scheduler_stop))
        return self.scheduler_status()

    async def stop_scheduler(self) -> SchedulerStatusResponse:
        task = self._scheduler_task
        if task is not None and not task.done():
            assert self._scheduler_stop is not None
            self._scheduler_stop.set()
            await task
        return self.scheduler_status()

    async def shutdown(self) -> None:
        if self._shutdown:
            return
        await self.stop_scheduler()
        self._shutdown = True
        await self._scheduler.close()

    def scheduler_status(self) -> SchedulerStatusResponse:
        actions = self._store.list_all_actions(limit=10000)
        uncertain = sum(
            action.status in {ActionExecutionStatus.UNCERTAIN, ActionExecutionStatus.RECONCILING}
            for action in actions
        )
        active = sum(
            occurrence.status in {OccurrenceStatus.DISPATCHING, OccurrenceStatus.RUNNING}
            for occurrence in self._store.list_occurrences()
        )
        active_tasks = sum(
            record.status
            in {
                TaskStatus.CREATED,
                TaskStatus.PLANNED,
                TaskStatus.PLANNING,
                TaskStatus.RUNNING,
                TaskStatus.AWAITING_APPROVAL,
                TaskStatus.EXECUTING,
                TaskStatus.VERIFYING,
                TaskStatus.RECOVERING,
            }
            for record in self._store.list_task_records(limit=10000)
        )
        task = self._scheduler_task
        return SchedulerStatusResponse(
            running=task is not None and not task.done(),
            shutdown=self._shutdown,
            active_tasks=active_tasks,
            active_occurrences=active,
            uncertain_actions=uncertain,
            kill_switch_active=(
                self._runtime.kill_switch_active()
                or self._task_executor.kill_switch_active()
                or self._scheduler.kill_switch_active()
            ),
            last_error=self._last_error,
        )

    def list_audit_events(
        self,
        *,
        task_id: UUID | str | None = None,
        action_id: str | None = None,
        schedule_id: str | None = None,
        event_type: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> tuple[AuditEventResponse, ...]:
        self._validate_limit(limit)
        if since is not None and since.tzinfo is None:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "since must be timezone-aware")
        if until is not None and until.tzinfo is None:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "until must be timezone-aware")
        if since is not None and until is not None and since > until:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "since must not be after until")
        with self._lock:
            events = self._store.audit_events(task_id)
        selected = []
        for event in events:
            details = event.details if isinstance(event.details, dict) else {}
            if action_id is not None and action_id not in {
                str(details.get("action_id", "")),
                str(details.get("execution_id", "")),
            }:
                continue
            if schedule_id is not None and str(details.get("schedule_id", "")) != schedule_id:
                continue
            if event_type is not None and event.event_type != event_type:
                continue
            if since is not None and event.timestamp < since:
                continue
            if until is not None and event.timestamp >= until:
                continue
            public_details = self._public_audit_details(details)
            selected.append(
                AuditEventResponse(
                    event.event_type,
                    event.task_id,
                    event.timestamp,
                    MappingProxyType(public_details),
                )
            )
        return tuple(selected[-limit:])

    def record_api_audit_event(
        self,
        event_type: str,
        *,
        request_id: str,
        caller_id: str | None = None,
        scope: str | None = None,
        code: str | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        task_id: UUID | None = None,
    ) -> None:
        """Persist an allowlisted transport security event without caller-controlled payloads."""
        if not event_type.startswith("api.") or len(event_type) > 80:
            raise ValueError("invalid API audit event type")
        details: dict[str, Any] = {"request_id": sanitize_text(request_id[:64])}
        for key, value in (
            ("caller_id", caller_id),
            ("scope", scope),
            ("code", code),
            ("endpoint", endpoint),
            ("method", method),
        ):
            if value is not None:
                details[key] = sanitize_text(value[:128])
        if status_code is not None:
            details["status_code"] = status_code
        with self._lock:
            self._store.record_audit_event(
                AuditEvent(
                    event_type,
                    task_id or UUID(int=0),
                    details=sanitize_value(details),
                )
            )

    async def _scheduler_loop(self, stop: asyncio.Event) -> None:
        try:
            while not stop.is_set():
                try:
                    await self._scheduler.run_once()
                except Exception:  # noqa: BLE001 - loop must stop and publish a safe diagnostic
                    self._last_error = "scheduler polling failed"
                    self._audit_service_event("service.scheduler_failed", uuid4(), {})
                    return
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self._poll_interval)
                except TimeoutError:
                    continue
        finally:
            self._scheduler_task = None

    def _task_status(self, record: TaskRecord) -> TaskStatusResponse:
        actions = tuple(self._action_status(item) for item in self._store.list_actions(record.task_id))
        task_schedules = tuple(
            schedule
            for schedule in self._store.list_schedules()
            if schedule.task_id == record.task_id
        )
        return TaskStatusResponse(
            task_id=record.task_id,
            objective=sanitize_text(record.objective)[:2000],
            status=record.status,
            verification_state=sanitize_text(record.verification_state),
            approval_required=record.status is TaskStatus.AWAITING_APPROVAL,
            denied=record.status is TaskStatus.DENIED,
            uncertain=any(action.uncertain for action in actions),
            retry_count=record.retry_count,
            replan_count=record.replan_count,
            created_at=record.created_at,
            updated_at=record.updated_at,
            actions=actions,
            schedule_ids=tuple(schedule.schedule_id for schedule in task_schedules),
            schedules=tuple(self._schedule_response(schedule) for schedule in task_schedules),
            last_error=sanitize_text(record.last_error)[:500],
        )

    @staticmethod
    def _action_status(record: ActionExecutionRecord) -> ActionStatusResponse:
        uncertain = record.status in {
            ActionExecutionStatus.UNCERTAIN,
            ActionExecutionStatus.RECONCILING,
        } or record.verification_status is VerificationStatus.UNCERTAIN
        if uncertain:
            failure = "execution outcome is uncertain; action remains blocked pending reconciliation"
        elif record.status is ActionExecutionStatus.FAILED:
            failure = "action failed; retry requires a fresh runtime safety decision"
        else:
            failure = ""
        return ActionStatusResponse(
            task_id=record.task_id,
            action_id=record.action_id,
            name=sanitize_text(record.name)[:200],
            status=record.status,
            verification_status=record.verification_status,
            attempts=record.attempts,
            uncertain=uncertain,
            created_at=record.created_at,
            updated_at=record.updated_at,
            failure=failure,
        )

    def _schedule_response(self, record: ScheduleRecord) -> ScheduleResponse:
        occurrences = self._store.list_occurrences(record.schedule_id)
        return ScheduleResponse(
            schedule_id=record.schedule_id,
            task_id=record.task_id,
            objective=sanitize_text(record.objective)[:2000],
            action_name=sanitize_text(record.action_name)[:200],
            action_kind=sanitize_text(record.action_kind),
            schedule_type=record.schedule_type,
            status=record.status,
            enabled=record.enabled,
            next_occurrence=record.next_run_at if record.enabled else None,
            cancellation_pending=any(
                occurrence.cancellation_requested
                and occurrence.status in {OccurrenceStatus.DISPATCHING, OccurrenceStatus.RUNNING}
                for occurrence in occurrences
            ),
            interval_seconds=record.interval_seconds,
            occurrence_count=record.occurrence_number,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def _scheduler_store_schedule(self, schedule_id: str) -> ScheduleRecord | None:
        return next(
            (item for item in self._store.list_schedules() if item.schedule_id == schedule_id),
            None,
        )

    def _load_task(self, task_id: UUID | str) -> TaskRecord:
        with self._lock:
            record = self._store.load_task(task_id)
        if record is None:
            raise AgentServiceError(ServiceErrorCode.TASK_NOT_FOUND, "task not found")
        return record

    def _audit_service_event(
        self, event_type: str, task_id: UUID, details: dict[str, Any]
    ) -> None:
        with self._lock:
            self._store.record_audit_event(
                AuditEvent(event_type, task_id, details=sanitize_value(details))
            )

    @staticmethod
    def _public_audit_details(details: dict[str, Any]) -> dict[str, Any]:
        cleaned = sanitize_value(details)
        return {
            key: value
            for key, value in cleaned.items()
            if key in _AUDIT_DETAIL_KEYS
            and isinstance(value, (str, int, float, bool, type(None)))
        }

    def _submission_error(
        self, result: AgentResult, record: TaskRecord
    ) -> ServiceErrorInfo | None:
        if result.success:
            return None
        return self._record_error(record, result.reason)

    def _record_error(
        self, record: TaskRecord, reason: str = ""
    ) -> ServiceErrorInfo | None:
        safe_reason = sanitize_text(reason or record.last_error).lower()
        if record.status in {TaskStatus.SUCCEEDED, TaskStatus.COMPLETED}:
            return None
        if "kill switch" in safe_reason or "kill switch" in record.termination_reason.lower():
            code, message = ServiceErrorCode.KILL_SWITCH_ACTIVE, "execution blocked by the kill switch"
        elif record.status is TaskStatus.DENIED and record.approval_state == "denied":
            code, message = ServiceErrorCode.AUTHORIZATION_REQUIRED, "current approval was not granted"
        elif record.status is TaskStatus.DENIED:
            code, message = ServiceErrorCode.POLICY_DENIED, "execution denied by current policy"
        elif any(
            action.status in {ActionExecutionStatus.UNCERTAIN, ActionExecutionStatus.RECONCILING}
            or action.verification_status is VerificationStatus.UNCERTAIN
            for action in self._store.list_actions(record.task_id)
        ) or "uncertain" in safe_reason or "recovery" in safe_reason:
            code, message = ServiceErrorCode.UNCERTAIN, "execution outcome is uncertain and remains blocked"
        elif record.status is TaskStatus.AWAITING_APPROVAL:
            code, message = ServiceErrorCode.AUTHORIZATION_REQUIRED, "current approval is required"
        elif record.status is TaskStatus.STOPPED:
            code, message = ServiceErrorCode.KILL_SWITCH_ACTIVE, "execution was stopped by a safety control"
        else:
            code, message = ServiceErrorCode.INTERNAL_FAILURE, "task did not complete"
        return ServiceErrorInfo(code, message)

    @staticmethod
    def _validate_objective(objective: str) -> str:
        if not isinstance(objective, str) or not objective.strip() or len(objective) > 8000:
            raise AgentServiceError(
                ServiceErrorCode.INVALID_REQUEST,
                "objective must contain between 1 and 8000 characters",
            )
        return sanitize_text(objective.strip())

    @staticmethod
    def _validate_identity(value: str, name: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise AgentServiceError(
                ServiceErrorCode.INVALID_REQUEST,
                f"{name} must contain between 1 and 256 characters",
            )
        return value.strip()

    @staticmethod
    def _hash_identity(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if not 1 <= limit <= 500:
            raise AgentServiceError(
                ServiceErrorCode.INVALID_REQUEST,
                "limit must be between 1 and 500",
            )


__all__ = [
    "ActionStatusResponse",
    "AgentService",
    "AgentServiceError",
    "AuditEventResponse",
    "CancelTaskRequest",
    "CancelTaskResult",
    "ReconciliationResponse",
    "ScheduleRequest",
    "ScheduleResponse",
    "SchedulerOccurrenceResponse",
    "SchedulerStatusResponse",
    "ServiceErrorCode",
    "ServiceErrorInfo",
    "SubmitTaskRequest",
    "SubmitTaskResult",
    "TaskStatusResponse",
]

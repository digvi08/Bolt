"""Persistent task state, execution idempotency, and bounded memory storage."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Concatenate, ParamSpec, Protocol, TypeVar
from uuid import UUID, uuid4

from .models import AuditEvent, Task, TaskStatus
from .secrets import sanitize_value


def _utc_now() -> datetime:
    return datetime.now(UTC)


P = ParamSpec("P")
R = TypeVar("R")


def _synchronized(
    function: Callable[Concatenate[SQLiteTaskStore, P], R],
) -> Callable[Concatenate[SQLiteTaskStore, P], R]:
    def wrapped(self: SQLiteTaskStore, /, *args: P.args, **kwargs: P.kwargs) -> R:
        with self._connection_lock:
            return function(self, *args, **kwargs)

    return wrapped


class ActionExecutionStatus(StrEnum):
    NEVER_ATTEMPTED = "never_attempted"
    EXECUTING = "executing"
    RECONCILING = "reconciling"
    COMPLETED = "completed"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class VerificationStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    NOT_CONFIGURED = "not_configured"


class MemoryTrust(StrEnum):
    SYSTEM = "system"
    VERIFIED = "verified"
    USER = "user"
    TOOL = "tool"
    EXTERNAL = "external"


class ScheduleType(StrEnum):
    RUN_AT = "run_at"
    INTERVAL = "interval"
    CRON = "cron"


class ScheduleStatus(StrEnum):
    SCHEDULED = "scheduled"
    DISABLED = "disabled"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class OccurrenceStatus(StrEnum):
    SCHEDULED = "scheduled"
    DUE = "due"
    DISPATCHING = "dispatching"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    MISSED = "missed"
    UNCERTAIN = "uncertain"


@dataclass
class ScheduleRecord:
    schedule_id: str
    task_id: UUID
    objective: str
    action_name: str
    action_kind: str
    parameters: dict[str, Any]
    schedule_type: ScheduleType
    next_run_at: datetime
    interval_seconds: int | None = None
    end_at: datetime | None = None
    deadline_at: datetime | None = None
    execution_timeout_seconds: float | None = None
    enabled: bool = True
    status: ScheduleStatus = ScheduleStatus.SCHEDULED
    occurrence_number: int = 0
    timezone_policy: str = "UTC"
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)


@dataclass
class ScheduleOccurrence:
    schedule_id: str
    occurrence_id: str
    task_id: UUID
    execution_id: str
    scheduled_for: datetime
    status: OccurrenceStatus = OccurrenceStatus.DUE
    deadline_at: datetime | None = None
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    failure_reason: str = ""
    cancellation_requested: bool = False


class TaskTransitionError(ValueError):
    """Raised when a persisted state transition violates the task state machine."""


class ActionExecutionConflict(ValueError):
    """Raised when an action execution claim is stale or already in flight."""


class IdempotencyConflict(ValueError):
    """Raised when an idempotency key is reused for a different request."""


@dataclass
class TaskRecord:
    task_id: UUID
    root_task_id: UUID | None = None
    parent_task_id: UUID | None = None
    objective: str = ""
    status: TaskStatus = TaskStatus.CREATED
    current_phase: str = "created"
    current_plan_version: str = "v1"
    current_step: str | None = None
    completed_steps: list[str] = field(default_factory=list)
    failed_steps: list[str] = field(default_factory=list)
    retry_count: int = 0
    replan_count: int = 0
    approval_state: str = "pending"
    verification_state: str = "pending"
    last_error: str = ""
    termination_reason: str = ""
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    execution_metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_task(cls, task: Task, **extra: Any) -> TaskRecord:
        metadata = dict(getattr(task, "execution_metadata", {}))
        metadata.update(extra)
        return cls(
            task_id=task.id,
            root_task_id=getattr(task, "root_task_id", None),
            parent_task_id=getattr(task, "parent_task_id", None),
            objective=getattr(task, "objective", "") or task.instruction.text,
            status=task.status,
            current_phase=getattr(task, "current_phase", "created"),
            current_plan_version=getattr(task, "current_plan_version", "v1"),
            current_step=getattr(task, "current_step", None),
            completed_steps=list(getattr(task, "completed_steps", [])),
            failed_steps=list(getattr(task, "failed_steps", [])),
            retry_count=getattr(task, "retry_count", 0),
            replan_count=getattr(task, "replan_count", 0),
            approval_state=getattr(task, "approval_state", "pending"),
            verification_state=getattr(task, "verification_state", "pending"),
            last_error=getattr(task, "last_error", ""),
            termination_reason=getattr(task, "termination_reason", ""),
            created_at=task.created_at,
            updated_at=getattr(task, "updated_at", task.created_at),
            execution_metadata=sanitize_value(metadata),
        )


@dataclass
class ActionExecutionRecord:
    action_id: str
    task_id: UUID
    name: str
    status: ActionExecutionStatus = ActionExecutionStatus.NEVER_ATTEMPTED
    attempts: int = 0
    outcome: str = ""
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)
    verification_status: VerificationStatus = VerificationStatus.PENDING
    verification_reason: str = ""


@dataclass
class MemoryRecord:
    memory_id: str = field(default_factory=lambda: str(uuid4()))
    task_id: UUID | None = None
    session_id: str | None = None
    content: str = ""
    category: str = "general"
    provenance: str = "system"
    trust: MemoryTrust | str = MemoryTrust.SYSTEM
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def sanitized(self) -> MemoryRecord:
        try:
            trust = MemoryTrust(self.trust)
        except ValueError as error:
            raise ValueError("memory trust must be a recognized trust classification") from error
        cleaned = sanitize_value(
            {
                "content": self.content,
                "category": self.category,
                "provenance": self.provenance,
                "metadata": self.metadata,
            }
        )
        return MemoryRecord(
            memory_id=sanitize_value(self.memory_id),
            task_id=self.task_id,
            session_id=sanitize_value(self.session_id),
            content=str(cleaned["content"]),
            category=str(cleaned["category"]),
            provenance=str(cleaned["provenance"]),
            trust=trust,
            created_at=self.created_at,
            updated_at=self.updated_at,
            expires_at=self.expires_at,
            metadata=dict(cleaned["metadata"]),
        )


class TaskStateStore(Protocol):
    def save_task(self, task: Task | TaskRecord) -> TaskRecord: ...

    def load_task(self, task_id: UUID | str) -> TaskRecord | None: ...

    def save_action(self, action: ActionExecutionRecord) -> ActionExecutionRecord: ...

    def get_action(self, task_id: UUID | str, action_id: str) -> ActionExecutionRecord | None: ...

    def save_memory(self, item: MemoryRecord) -> MemoryRecord: ...

    def retrieve_memory(
        self,
        *,
        task_id: UUID | str | None = None,
        session_id: str | None = None,
        category: str | None = None,
        provenance: str | None = None,
        trust: str | None = None,
        include_expired: bool = False,
        limit: int = 50,
        max_context_size: int | None = None,
    ) -> list[MemoryRecord]: ...

    def delete_expired_memories(self) -> int: ...

    def list_unfinished_tasks(self) -> list[TaskRecord]: ...

    def list_actions(self, task_id: UUID | str) -> list[ActionExecutionRecord]: ...

    def save_task_and_action(
        self, task: Task | TaskRecord, action: ActionExecutionRecord
    ) -> None: ...

    def save_verification(
        self,
        task_id: UUID | str,
        action_id: str,
        status: VerificationStatus,
        reason: str = "",
    ) -> ActionExecutionRecord: ...

    def save_task_and_verification(
        self,
        task: Task | TaskRecord,
        action_id: str,
        status: VerificationStatus,
        reason: str = "",
    ) -> None: ...

    def record_audit_event(self, event: AuditEvent) -> None: ...

    def save_schedule(self, schedule: ScheduleRecord) -> ScheduleRecord: ...

    def load_schedule(self, schedule_id: str) -> ScheduleRecord | None: ...

    def list_schedules(self) -> list[ScheduleRecord]: ...

    def create_due_occurrence(
        self,
        schedule_id: str,
        now: datetime,
        *,
        missed: bool = False,
        skipped_intervals: int = 0,
    ) -> ScheduleOccurrence | None: ...

    def list_occurrences(
        self, schedule_id: str | None = None
    ) -> list[ScheduleOccurrence]: ...

    def update_occurrence(self, occurrence: ScheduleOccurrence) -> None: ...

    def cancel_schedule(self, schedule_id: str) -> ScheduleRecord | None: ...

    def list_task_records(self, *, limit: int = 1000) -> list[TaskRecord]: ...

    def find_action(self, action_id: str) -> ActionExecutionRecord | None: ...

    def register_idempotent_task(
        self,
        caller_hash: str,
        key_hash: str,
        request_fingerprint: str,
        task: TaskRecord,
    ) -> tuple[UUID, bool]: ...

    def lookup_idempotent_task(
        self, caller_hash: str, key_hash: str
    ) -> tuple[UUID, str] | None: ...

    def audit_events(self, task_id: UUID | str | None = None) -> list[AuditEvent]: ...

    def list_all_actions(self, *, limit: int = 1000) -> list[ActionExecutionRecord]: ...

    def list_uncertain_actions(self, *, limit: int = 100) -> list[ActionExecutionRecord]: ...


class TaskStateMachine:
    _initial: ClassVar[set[TaskStatus]] = {
        TaskStatus.CREATED,
        TaskStatus.PLANNED,
        TaskStatus.STOPPED,
    }

    _allowed: ClassVar[dict[TaskStatus, set[TaskStatus]]] = {
        TaskStatus.CREATED: {TaskStatus.PLANNED, TaskStatus.AWAITING_APPROVAL, TaskStatus.EXECUTING, TaskStatus.DENIED, TaskStatus.STOPPED, TaskStatus.ABORTED},
        TaskStatus.PLANNED: {TaskStatus.AWAITING_APPROVAL, TaskStatus.EXECUTING, TaskStatus.FAILED, TaskStatus.DENIED, TaskStatus.STOPPED, TaskStatus.SUCCEEDED, TaskStatus.ABORTED},
        TaskStatus.PLANNING: {TaskStatus.PLANNED, TaskStatus.DENIED, TaskStatus.ABORTED},
        TaskStatus.RUNNING: {TaskStatus.EXECUTING, TaskStatus.FAILED, TaskStatus.DENIED, TaskStatus.SUCCEEDED, TaskStatus.ABORTED},
        TaskStatus.WAITING_APPROVAL: {TaskStatus.AWAITING_APPROVAL, TaskStatus.DENIED, TaskStatus.ABORTED},
        TaskStatus.AWAITING_APPROVAL: {TaskStatus.EXECUTING, TaskStatus.DENIED, TaskStatus.ABORTED},
        TaskStatus.EXECUTING: {TaskStatus.VERIFYING, TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.DENIED, TaskStatus.STOPPED},
        TaskStatus.VERIFYING: {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.DENIED, TaskStatus.STOPPED},
        TaskStatus.RECOVERING: {TaskStatus.AWAITING_APPROVAL, TaskStatus.EXECUTING, TaskStatus.FAILED, TaskStatus.DENIED, TaskStatus.STOPPED, TaskStatus.SUCCEEDED},
        TaskStatus.SUCCEEDED: {
            TaskStatus.COMPLETED,
            TaskStatus.AWAITING_APPROVAL,
            TaskStatus.EXECUTING,
            TaskStatus.DENIED,
            TaskStatus.STOPPED,
        },
        TaskStatus.COMPLETED: set(),
        TaskStatus.FAILED: {TaskStatus.RECOVERING, TaskStatus.STOPPED, TaskStatus.ABORTED},
        TaskStatus.DENIED: {TaskStatus.ABORTED},
        TaskStatus.STOPPED: {TaskStatus.ABORTED},
        TaskStatus.ABORTED: set(),
    }

    @classmethod
    def assert_transition(cls, current: TaskStatus, next_status: TaskStatus) -> bool:
        if current is next_status:
            return True
        allowed = cls._allowed.get(current, set())
        if next_status not in allowed:
            raise TaskTransitionError(f"illegal task transition: {current.value} -> {next_status.value}")
        return True

    @classmethod
    def assert_initial_status(cls, status: TaskStatus) -> bool:
        if status not in cls._initial:
            raise TaskTransitionError(f"illegal initial task status: {status.value}")
        return True


@dataclass
class RestartDecision:
    allowed: bool
    reason: str
    requires_verification: bool = False
    action_status: ActionExecutionStatus | None = None


class RestartSafetyChecker:
    def __init__(self, store: TaskStateStore, *, kill_switch: Any | None = None, audit_sink: Any | None = None) -> None:
        self._store = store
        self._kill_switch = kill_switch
        self._audit = audit_sink

    def evaluate(self, task_id: UUID | str) -> RestartDecision:
        try:
            task = self._store.load_task(task_id)
        except (ValueError, TypeError, json.JSONDecodeError, sqlite3.DatabaseError) as error:
            return self._decision(task_id, False, f"persisted state integrity failure: {sanitize_value(str(error))}")
        if task is None:
            return self._decision(task_id, False, "task state missing")
        if self._kill_switch is not None and self._kill_switch.is_engaged():
            return self._decision(task_id, False, "kill switch engaged on restart")
        if task.status in {TaskStatus.DENIED, TaskStatus.STOPPED, TaskStatus.ABORTED}:
            return self._decision(
                task_id,
                False,
                f"historical terminal state blocks continuation: {task.status.value}",
            )
        try:
            actions = self._store.list_actions(task_id)
        except (ValueError, TypeError, json.JSONDecodeError, sqlite3.DatabaseError) as error:
            return self._decision(
                task_id,
                False,
                f"persisted action integrity failure: {sanitize_value(str(error))}",
            )
        uncertain = next(
            (
                action for action in actions
                if action.status
                in {
                    ActionExecutionStatus.EXECUTING,
                    ActionExecutionStatus.RECONCILING,
                    ActionExecutionStatus.UNCERTAIN,
                }
            ),
            None,
        )
        if uncertain is not None:
            return self._decision(
                task_id,
                False,
                "action outcome is uncertain; reconciliation required",
                requires_verification=True,
                action_status=uncertain.status,
            )
        failed = next(
            (action for action in actions if action.status is ActionExecutionStatus.FAILED),
            None,
        )
        if failed is not None:
            return self._decision(
                task_id,
                False,
                "failed action requires current runtime retry-safety decision",
                requires_verification=True,
                action_status=failed.status,
            )
        unverified = next(
            (
                action for action in actions
                if action.status is ActionExecutionStatus.COMPLETED
                and action.verification_status
                in {VerificationStatus.PENDING, VerificationStatus.FAILED, VerificationStatus.UNCERTAIN}
            ),
            None,
        )
        if unverified is not None:
            return self._decision(
                task_id,
                False,
                "completed action requires independent verification",
                requires_verification=True,
                action_status=unverified.status,
            )
        if task.status in {TaskStatus.COMPLETED, TaskStatus.SUCCEEDED}:
            if task.verification_state.lower() not in {"verified", "passed", "complete"}:
                return self._decision(task_id, False, "completed task lacks verification", requires_verification=True)
            return self._decision(task_id, True, "task is already verified")
        if task.status in {TaskStatus.EXECUTING, TaskStatus.VERIFYING}:
            return self._decision(
                task_id,
                False,
                "execution state is uncertain; fail closed",
                requires_verification=True,
                action_status=ActionExecutionStatus.UNCERTAIN,
            )
        if task.termination_reason:
            return self._decision(task_id, False, f"termination reason: {sanitize_value(task.termination_reason)}")
        return self._decision(task_id, True, "task state is recoverable")

    def _decision(
        self,
        task_id: UUID | str,
        allowed: bool,
        reason: str,
        *,
        requires_verification: bool = False,
        action_status: ActionExecutionStatus | None = None,
    ) -> RestartDecision:
        decision = RestartDecision(allowed, reason, requires_verification, action_status)
        event = AuditEvent(
            "restart.allowed" if allowed else "restart.denied",
            UUID(str(task_id)),
            details=sanitize_value(
                {
                    "reason": reason,
                    "requires_verification": requires_verification,
                    "action_status": action_status.value if action_status else None,
                }
            ),
        )
        self._store.record_audit_event(event)
        if self._audit is not None:
            self._audit.record(event)
        return decision


class SQLiteTaskStore:
    """SQLite persistence; omitted paths use a durable per-user local database."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        resolved_path = Path(db_path) if db_path is not None else self.default_path()
        if str(resolved_path) != ":memory:":
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(resolved_path)
        self._connection_lock = threading.RLock()
        self._connection = sqlite3.connect(self._db_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._ensure_schema()

    @staticmethod
    def default_path() -> Path:
        """Resolve the app database under the user's local data directory."""
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            root = Path(local_app_data)
        else:
            root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        return root / "bolt" / "agent-state.sqlite3"

    def _ensure_schema(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS task_records (
                task_id TEXT PRIMARY KEY,
                root_task_id TEXT,
                parent_task_id TEXT,
                objective TEXT,
                status TEXT NOT NULL,
                current_phase TEXT NOT NULL,
                current_plan_version TEXT NOT NULL,
                current_step TEXT,
                completed_steps TEXT,
                failed_steps TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                replan_count INTEGER NOT NULL DEFAULT 0,
                approval_state TEXT NOT NULL,
                verification_state TEXT NOT NULL,
                last_error TEXT,
                termination_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                execution_metadata TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS action_records (
                action_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                outcome TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_records (
                memory_id TEXT PRIMARY KEY,
                task_id TEXT,
                session_id TEXT,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                provenance TEXT NOT NULL,
                trust TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                metadata TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                task_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schedule_records (
                schedule_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                objective TEXT NOT NULL,
                action_name TEXT NOT NULL,
                action_kind TEXT NOT NULL,
                parameters TEXT NOT NULL,
                schedule_type TEXT NOT NULL,
                next_run_at TEXT NOT NULL,
                interval_seconds INTEGER,
                end_at TEXT,
                deadline_at TEXT,
                execution_timeout_seconds REAL,
                enabled INTEGER NOT NULL,
                status TEXT NOT NULL,
                occurrence_number INTEGER NOT NULL,
                timezone_policy TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schedule_occurrences (
                schedule_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                execution_id TEXT NOT NULL UNIQUE,
                scheduled_for TEXT NOT NULL,
                status TEXT NOT NULL,
                deadline_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                failure_reason TEXT NOT NULL,
                cancellation_requested INTEGER NOT NULL,
                PRIMARY KEY (schedule_id, occurrence_id),
                FOREIGN KEY (schedule_id) REFERENCES schedule_records(schedule_id)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS idempotency_records (
                caller_hash TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                task_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                PRIMARY KEY (caller_hash, key_hash),
                FOREIGN KEY (task_id) REFERENCES task_records(task_id)
            )
            """
        )
        self._add_column("action_records", "verification_status", "TEXT NOT NULL DEFAULT 'pending'")
        self._add_column("action_records", "verification_reason", "TEXT NOT NULL DEFAULT ''")
        self._connection.commit()

    @_synchronized
    def record_audit_event(self, event: AuditEvent) -> None:
        with self.transaction():
            self._queue_audit(event)

    def _queue_audit(self, event: AuditEvent) -> None:
        self._connection.execute(
            """
            INSERT INTO audit_records (event_type, task_id, timestamp, details)
            VALUES (?, ?, ?, ?)
            """,
            (
                sanitize_value(event.event_type),
                str(event.task_id),
                event.timestamp.isoformat(),
                json.dumps(sanitize_value(event.details)),
            ),
        )

    @_synchronized
    def audit_events(self, task_id: UUID | str | None = None) -> list[AuditEvent]:
        if task_id is None:
            rows = self._connection.execute(
                "SELECT * FROM audit_records ORDER BY audit_id"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM audit_records WHERE task_id = ? ORDER BY audit_id",
                (str(task_id),),
            ).fetchall()
        return [
            AuditEvent(
                event_type=row["event_type"],
                task_id=UUID(row["task_id"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
                details=json.loads(row["details"]),
            )
            for row in rows
        ]

    def _add_column(self, table: str, name: str, definition: str) -> None:
        columns = {
            row["name"]
            for row in self._connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if name not in columns:
            self._connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self._connection_lock.acquire()
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()
        finally:
            self._connection_lock.release()

    @contextmanager
    def _task_transition_transaction(self, record: TaskRecord) -> Iterator[None]:
        try:
            with self.transaction():
                yield
        except TaskTransitionError as error:
            self.record_audit_event(
                AuditEvent(
                    "task.transition_rejected",
                    record.task_id,
                    details={
                        "to": record.status.value,
                        "reason": sanitize_value(str(error)),
                    },
                )
            )
            raise

    @_synchronized
    def save_task(self, task: Task | TaskRecord) -> TaskRecord:
        record = task if isinstance(task, TaskRecord) else TaskRecord.from_task(task)
        record.updated_at = _utc_now()
        with self._task_transition_transaction(record):
            previous = self.load_task(record.task_id)
            if previous is not None:
                TaskStateMachine.assert_transition(previous.status, record.status)
            else:
                TaskStateMachine.assert_initial_status(record.status)
            self._assert_task_completion(record)
            self._save_task_record(record)
        return record

    def _save_task_record(self, record: TaskRecord) -> None:
        self._connection.execute(
            """
            INSERT INTO task_records (
                task_id, root_task_id, parent_task_id, objective, status, current_phase,
                current_plan_version, current_step, completed_steps, failed_steps, retry_count,
                replan_count, approval_state, verification_state, last_error, termination_reason,
                created_at, updated_at, execution_metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                root_task_id=excluded.root_task_id,
                parent_task_id=excluded.parent_task_id,
                objective=excluded.objective,
                status=excluded.status,
                current_phase=excluded.current_phase,
                current_plan_version=excluded.current_plan_version,
                current_step=excluded.current_step,
                completed_steps=excluded.completed_steps,
                failed_steps=excluded.failed_steps,
                retry_count=excluded.retry_count,
                replan_count=excluded.replan_count,
                approval_state=excluded.approval_state,
                verification_state=excluded.verification_state,
                last_error=excluded.last_error,
                termination_reason=excluded.termination_reason,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at,
                execution_metadata=excluded.execution_metadata
            """,
            (
                str(record.task_id),
                str(record.root_task_id) if record.root_task_id is not None else None,
                str(record.parent_task_id) if record.parent_task_id is not None else None,
                sanitize_value(record.objective),
                record.status.value,
                sanitize_value(record.current_phase),
                sanitize_value(record.current_plan_version),
                sanitize_value(record.current_step),
                json.dumps(sanitize_value(record.completed_steps)),
                json.dumps(sanitize_value(record.failed_steps)),
                record.retry_count,
                record.replan_count,
                sanitize_value(record.approval_state),
                sanitize_value(record.verification_state),
                sanitize_value(record.last_error),
                sanitize_value(record.termination_reason),
                record.created_at.isoformat(),
                record.updated_at.isoformat(),
                json.dumps(sanitize_value(record.execution_metadata)),
            ),
        )

    @_synchronized
    def save_task_and_action(
        self, task: Task | TaskRecord, action: ActionExecutionRecord
    ) -> None:
        record = task if isinstance(task, TaskRecord) else TaskRecord.from_task(task)
        record.updated_at = _utc_now()
        with self._task_transition_transaction(record):
            previous = self.load_task(record.task_id)
            if previous is not None:
                TaskStateMachine.assert_transition(previous.status, record.status)
            else:
                TaskStateMachine.assert_initial_status(record.status)
            self._assert_task_completion(record)
            if record.status is TaskStatus.COMPLETED and (
                action.status is not ActionExecutionStatus.COMPLETED
                or action.verification_status
                not in {VerificationStatus.VERIFIED, VerificationStatus.NOT_CONFIGURED}
            ):
                raise TaskTransitionError("task cannot complete while its action lacks a final result")
            self._save_task_record(record)
            self._save_action_record(action)

    @staticmethod
    def _assert_task_completion(record: TaskRecord) -> None:
        if record.status is TaskStatus.COMPLETED and record.verification_state not in {
            "verified",
            "passed",
            "complete",
            "not_configured",
        }:
            raise TaskTransitionError(
                "task cannot be completed without successful or explicitly unconfigured verification"
            )

    @_synchronized
    def load_task(self, task_id: UUID | str) -> TaskRecord | None:
        row = self._connection.execute(
            "SELECT * FROM task_records WHERE task_id = ?",
            (str(task_id),),
        ).fetchone()
        if row is None:
            return None
        return TaskRecord(
            task_id=UUID(row["task_id"]),
            root_task_id=UUID(row["root_task_id"]) if row["root_task_id"] else None,
            parent_task_id=UUID(row["parent_task_id"]) if row["parent_task_id"] else None,
            objective=row["objective"] or "",
            status=TaskStatus(row["status"]),
            current_phase=row["current_phase"],
            current_plan_version=row["current_plan_version"],
            current_step=row["current_step"],
            completed_steps=json.loads(row["completed_steps"] or "[]"),
            failed_steps=json.loads(row["failed_steps"] or "[]"),
            retry_count=int(row["retry_count"]),
            replan_count=int(row["replan_count"]),
            approval_state=row["approval_state"],
            verification_state=row["verification_state"],
            last_error=row["last_error"] or "",
            termination_reason=row["termination_reason"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            execution_metadata=json.loads(row["execution_metadata"] or "{}"),
        )

    @_synchronized
    def save_action(self, action: ActionExecutionRecord) -> ActionExecutionRecord:
        action.updated_at = _utc_now()
        with self.transaction():
            self._save_action_record(action)
        return action

    def _save_action_record(self, action: ActionExecutionRecord) -> None:
        action.updated_at = _utc_now()
        action.action_id = sanitize_value(action.action_id)
        action.name = sanitize_value(action.name)
        action.outcome = sanitize_value(action.outcome)
        action.verification_reason = sanitize_value(action.verification_reason)
        action.metadata = sanitize_value(action.metadata)
        previous = self.get_action(action.task_id, action.action_id)
        owner = self._connection.execute(
            "SELECT task_id FROM action_records WHERE action_id = ?",
            (action.action_id,),
        ).fetchone()
        if owner is not None and owner["task_id"] != str(action.task_id):
            raise ValueError("action identity is already owned by another task")
        if self.load_task(action.task_id) is None:
            raise ValueError("action references unknown task")
        if previous is None and action.status is not ActionExecutionStatus.NEVER_ATTEMPTED:
            raise ValueError("new actions must begin as never_attempted")
        if (
            action.status is ActionExecutionStatus.EXECUTING
            and previous is not None
            and action.attempts != previous.attempts + 1
        ):
            raise ActionExecutionConflict("action execution claim is stale or already in flight")
        if previous is not None and previous.status is not action.status:
            allowed = {
                ActionExecutionStatus.NEVER_ATTEMPTED: {ActionExecutionStatus.EXECUTING},
                ActionExecutionStatus.EXECUTING: {
                    ActionExecutionStatus.RECONCILING,
                    ActionExecutionStatus.COMPLETED,
                    ActionExecutionStatus.FAILED,
                    ActionExecutionStatus.UNCERTAIN,
                },
                ActionExecutionStatus.RECONCILING: {
                    ActionExecutionStatus.COMPLETED,
                    ActionExecutionStatus.FAILED,
                    ActionExecutionStatus.UNCERTAIN,
                },
                ActionExecutionStatus.FAILED: {
                    ActionExecutionStatus.EXECUTING,
                    ActionExecutionStatus.RECONCILING,
                    ActionExecutionStatus.COMPLETED,
                },
                ActionExecutionStatus.UNCERTAIN: {
                    ActionExecutionStatus.RECONCILING,
                    ActionExecutionStatus.COMPLETED,
                    ActionExecutionStatus.FAILED,
                },
                ActionExecutionStatus.COMPLETED: {ActionExecutionStatus.RECONCILING},
            }
            if action.status not in allowed[previous.status]:
                raise ValueError(
                    f"illegal action transition: {previous.status.value} -> {action.status.value}"
                )
        if previous is not None and previous.verification_status is not action.verification_status:
            verification_transitions = {
                VerificationStatus.PENDING: {
                    VerificationStatus.VERIFIED,
                    VerificationStatus.FAILED,
                    VerificationStatus.UNCERTAIN,
                    VerificationStatus.NOT_CONFIGURED,
                },
                VerificationStatus.UNCERTAIN: {VerificationStatus.VERIFIED, VerificationStatus.FAILED},
                VerificationStatus.FAILED: {VerificationStatus.VERIFIED},
                VerificationStatus.VERIFIED: set(),
                VerificationStatus.NOT_CONFIGURED: set(),
            }
            if action.verification_status not in verification_transitions[previous.verification_status]:
                raise ValueError(
                    "illegal verification transition: "
                    f"{previous.verification_status.value} -> {action.verification_status.value}"
                )
        self._connection.execute(
            """
            INSERT INTO action_records (
                action_id, task_id, name, status, attempts, outcome, created_at, updated_at,
                metadata, verification_status, verification_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(action_id) DO UPDATE SET
                task_id=excluded.task_id,
                name=excluded.name,
                status=excluded.status,
                attempts=excluded.attempts,
                outcome=excluded.outcome,
                created_at=excluded.created_at,
                updated_at=excluded.updated_at,
                metadata=excluded.metadata,
                verification_status=excluded.verification_status,
                verification_reason=excluded.verification_reason
            """,
            (
                action.action_id,
                str(action.task_id),
                sanitize_value(action.name),
                action.status.value,
                action.attempts,
                sanitize_value(action.outcome),
                action.created_at.isoformat(),
                action.updated_at.isoformat(),
                json.dumps(sanitize_value(action.metadata)),
                action.verification_status.value,
                sanitize_value(action.verification_reason),
            ),
        )

    @_synchronized
    def get_action(self, task_id: UUID | str, action_id: str) -> ActionExecutionRecord | None:
        row = self._connection.execute(
            "SELECT * FROM action_records WHERE task_id = ? AND action_id = ?",
            (str(task_id), action_id),
        ).fetchone()
        if row is None:
            return None
        return ActionExecutionRecord(
            action_id=row["action_id"],
            task_id=UUID(row["task_id"]),
            name=row["name"],
            status=ActionExecutionStatus(row["status"]),
            attempts=int(row["attempts"]),
            outcome=row["outcome"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            metadata=json.loads(row["metadata"] or "{}"),
            verification_status=VerificationStatus(row["verification_status"]),
            verification_reason=row["verification_reason"] or "",
        )

    @_synchronized
    def list_actions(self, task_id: UUID | str) -> list[ActionExecutionRecord]:
        rows = self._connection.execute(
            "SELECT action_id FROM action_records WHERE task_id = ? ORDER BY created_at, action_id",
            (str(task_id),),
        ).fetchall()
        return [
            action
            for row in rows
            if (action := self.get_action(task_id, row["action_id"])) is not None
        ]

    @_synchronized
    def list_unfinished_tasks(self) -> list[TaskRecord]:
        rows = self._connection.execute(
            """
            SELECT task_id FROM task_records
            WHERE status NOT IN (?, ?, ?, ?, ?)
            ORDER BY created_at, task_id
            """,
            (
                TaskStatus.COMPLETED.value,
                TaskStatus.SUCCEEDED.value,
                TaskStatus.DENIED.value,
                TaskStatus.STOPPED.value,
                TaskStatus.ABORTED.value,
            ),
        ).fetchall()
        return [
            task
            for row in rows
            if (task := self.load_task(row["task_id"])) is not None
        ]

    @_synchronized
    def list_task_records(self, *, limit: int = 1000) -> list[TaskRecord]:
        if not 1 <= limit <= 10000:
            raise ValueError("task list limit must be between 1 and 10000")
        rows = self._connection.execute(
            "SELECT task_id FROM task_records ORDER BY created_at, task_id LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            task
            for row in rows
            if (task := self.load_task(row["task_id"])) is not None
        ]

    @_synchronized
    def list_all_actions(self, *, limit: int = 1000) -> list[ActionExecutionRecord]:
        if not 1 <= limit <= 10000:
            raise ValueError("action list limit must be between 1 and 10000")
        rows = self._connection.execute(
            "SELECT task_id, action_id FROM action_records ORDER BY created_at, action_id LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            action
            for row in rows
            if (
                action := self.get_action(row["task_id"], row["action_id"])
            )
            is not None
        ]

    @_synchronized
    def find_action(self, action_id: str) -> ActionExecutionRecord | None:
        row = self._connection.execute(
            "SELECT task_id FROM action_records WHERE action_id=?",
            (action_id,),
        ).fetchone()
        if row is None:
            return None
        return self.get_action(row["task_id"], action_id)

    @_synchronized
    def list_uncertain_actions(self, *, limit: int = 100) -> list[ActionExecutionRecord]:
        if not 1 <= limit <= 10000:
            raise ValueError("uncertain action list limit must be between 1 and 10000")
        rows = self._connection.execute(
            """
            SELECT task_id, action_id FROM action_records
            WHERE status IN (?, ?) OR verification_status = ?
            ORDER BY updated_at DESC, action_id LIMIT ?
            """,
            (
                ActionExecutionStatus.UNCERTAIN.value,
                ActionExecutionStatus.RECONCILING.value,
                VerificationStatus.UNCERTAIN.value,
                limit,
            ),
        ).fetchall()
        return [
            action
            for row in rows
            if (
                action := self.get_action(row["task_id"], row["action_id"])
            )
            is not None
        ]

    @_synchronized
    def register_idempotent_task(
        self,
        caller_hash: str,
        key_hash: str,
        request_fingerprint: str,
        task: TaskRecord,
    ) -> tuple[UUID, bool]:
        with self.transaction():
            row = self._connection.execute(
                """
                SELECT request_fingerprint, task_id
                FROM idempotency_records WHERE caller_hash=? AND key_hash=?
                """,
                (caller_hash, key_hash),
            ).fetchone()
            if row is not None:
                if row["request_fingerprint"] != request_fingerprint:
                    raise IdempotencyConflict(
                        "idempotency key is already associated with a different request"
                    )
                return UUID(row["task_id"]), False
            if self.load_task(task.task_id) is not None:
                raise IdempotencyConflict("task identity is already in use")
            TaskStateMachine.assert_initial_status(task.status)
            self._save_task_record(task)
            self._connection.execute(
                """
                INSERT INTO idempotency_records (
                    caller_hash, key_hash, request_fingerprint, task_id, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    caller_hash,
                    key_hash,
                    request_fingerprint,
                    str(task.task_id),
                    _utc_now().isoformat(),
                ),
            )
            self._queue_audit(
                AuditEvent(
                    "task.idempotency_reserved",
                    task.task_id,
                    details={"request_fingerprint": request_fingerprint},
                )
            )
            return task.task_id, True

    @_synchronized
    def lookup_idempotent_task(
        self, caller_hash: str, key_hash: str
    ) -> tuple[UUID, str] | None:
        row = self._connection.execute(
            """
            SELECT task_id, request_fingerprint
            FROM idempotency_records WHERE caller_hash=? AND key_hash=?
            """,
            (caller_hash, key_hash),
        ).fetchone()
        if row is None:
            return None
        return UUID(row["task_id"]), row["request_fingerprint"]

    @_synchronized
    def save_verification(
        self,
        task_id: UUID | str,
        action_id: str,
        status: VerificationStatus,
        reason: str = "",
    ) -> ActionExecutionRecord:
        with self.transaction():
            if self.load_task(task_id) is None:
                raise ValueError("verification references unknown task")
            action = self.get_action(task_id, action_id)
            if action is None:
                raise ValueError("verification references unknown action")
            if action.status is not ActionExecutionStatus.COMPLETED and status is VerificationStatus.VERIFIED:
                raise ValueError("only a completed action can be verified")
            action.verification_status = status
            action.verification_reason = sanitize_value(reason)
            self._save_action_record(action)
        return action

    @_synchronized
    def save_task_and_verification(
        self,
        task: Task | TaskRecord,
        action_id: str,
        status: VerificationStatus,
        reason: str = "",
    ) -> None:
        record = task if isinstance(task, TaskRecord) else TaskRecord.from_task(task)
        record.updated_at = _utc_now()
        with self._task_transition_transaction(record):
            previous = self.load_task(record.task_id)
            if previous is None:
                raise ValueError("verification references unknown task")
            TaskStateMachine.assert_transition(previous.status, record.status)
            self._assert_task_completion(record)
            action = self.get_action(record.task_id, action_id)
            if action is None:
                raise ValueError("verification references unknown action")
            if action.status is not ActionExecutionStatus.COMPLETED:
                raise ValueError("only a completed action can be verified")
            self._assert_verification_consistency(record, status)
            action.verification_status = status
            action.verification_reason = sanitize_value(reason)
            self._save_action_record(action)
            self._save_task_record(record)

    @staticmethod
    def _assert_verification_consistency(
        record: TaskRecord,
        status: VerificationStatus,
    ) -> None:
        expected_states = {
            VerificationStatus.PENDING: {"pending"},
            VerificationStatus.VERIFIED: {"verified", "passed", "complete"},
            VerificationStatus.FAILED: {"failed"},
            VerificationStatus.UNCERTAIN: {"uncertain"},
            VerificationStatus.NOT_CONFIGURED: {"not_configured"},
        }
        if record.verification_state not in expected_states[status]:
            raise TaskTransitionError(
                "task verification state does not match the persisted action verification result"
            )

    @_synchronized
    def save_schedule(self, schedule: ScheduleRecord) -> ScheduleRecord:
        if schedule.schedule_type is ScheduleType.CRON:
            raise ValueError("cron schedules are not supported")
        if schedule.schedule_type is ScheduleType.INTERVAL and (
            schedule.interval_seconds is None or schedule.interval_seconds < 1
        ):
            raise ValueError("interval schedules require a positive interval")
        if schedule.next_run_at.tzinfo is None:
            raise ValueError("schedule timestamps must be timezone-aware")
        if schedule.end_at is not None and schedule.end_at.tzinfo is None:
            raise ValueError("schedule end time must be timezone-aware")
        if schedule.deadline_at is not None and schedule.deadline_at.tzinfo is None:
            raise ValueError("schedule deadline must be timezone-aware")

        schedule.objective = sanitize_value(schedule.objective)
        schedule.action_name = sanitize_value(schedule.action_name)
        schedule.action_kind = sanitize_value(schedule.action_kind)
        schedule.parameters = sanitize_value(schedule.parameters)
        schedule.updated_at = _utc_now()
        with self.transaction():
            previous = self.load_schedule(schedule.schedule_id)
            if previous is not None:
                allowed = {
                    ScheduleStatus.SCHEDULED: {
                        ScheduleStatus.SCHEDULED,
                        ScheduleStatus.DISABLED,
                        ScheduleStatus.COMPLETED,
                        ScheduleStatus.FAILED,
                        ScheduleStatus.CANCELLED,
                    },
                    ScheduleStatus.DISABLED: {
                        ScheduleStatus.DISABLED,
                        ScheduleStatus.SCHEDULED,
                        ScheduleStatus.CANCELLED,
                    },
                    ScheduleStatus.COMPLETED: {ScheduleStatus.COMPLETED},
                    ScheduleStatus.FAILED: {ScheduleStatus.FAILED},
                    ScheduleStatus.CANCELLED: {ScheduleStatus.CANCELLED},
                }
                if schedule.status not in allowed[previous.status]:
                    raise ValueError(
                        f"illegal schedule transition: {previous.status.value} -> {schedule.status.value}"
                    )
            self._connection.execute(
                """
                INSERT INTO schedule_records (
                    schedule_id, task_id, objective, action_name, action_kind, parameters,
                    schedule_type, next_run_at, interval_seconds, end_at, deadline_at,
                    execution_timeout_seconds, enabled, status, occurrence_number,
                    timezone_policy, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(schedule_id) DO UPDATE SET
                    task_id=excluded.task_id, objective=excluded.objective,
                    action_name=excluded.action_name, action_kind=excluded.action_kind,
                    parameters=excluded.parameters, schedule_type=excluded.schedule_type,
                    next_run_at=excluded.next_run_at, interval_seconds=excluded.interval_seconds,
                    end_at=excluded.end_at, deadline_at=excluded.deadline_at,
                    execution_timeout_seconds=excluded.execution_timeout_seconds,
                    enabled=excluded.enabled, status=excluded.status,
                    occurrence_number=excluded.occurrence_number,
                    timezone_policy=excluded.timezone_policy, updated_at=excluded.updated_at
                """,
                (
                    schedule.schedule_id,
                    str(schedule.task_id),
                    schedule.objective,
                    schedule.action_name,
                    schedule.action_kind,
                    json.dumps(sanitize_value(schedule.parameters)),
                    schedule.schedule_type.value,
                    schedule.next_run_at.isoformat(),
                    schedule.interval_seconds,
                    schedule.end_at.isoformat() if schedule.end_at else None,
                    schedule.deadline_at.isoformat() if schedule.deadline_at else None,
                    schedule.execution_timeout_seconds,
                    int(schedule.enabled),
                    schedule.status.value,
                    schedule.occurrence_number,
                    schedule.timezone_policy,
                    schedule.created_at.isoformat(),
                    schedule.updated_at.isoformat(),
                ),
            )
            event_type = (
                "schedule.created"
                if previous is None
                else "schedule.enabled" if schedule.enabled and not previous.enabled
                else "schedule.disabled" if previous.enabled and not schedule.enabled
                else "schedule.updated"
            )
            self._queue_audit(
                AuditEvent(
                    event_type,
                    schedule.task_id,
                    details={"schedule_id": schedule.schedule_id, "status": schedule.status.value},
                )
            )
        return schedule

    @_synchronized
    def load_schedule(self, schedule_id: str) -> ScheduleRecord | None:
        row = self._connection.execute(
            "SELECT * FROM schedule_records WHERE schedule_id = ?", (schedule_id,)
        ).fetchone()
        if row is None:
            return None
        return ScheduleRecord(
            schedule_id=row["schedule_id"],
            task_id=UUID(row["task_id"]),
            objective=row["objective"],
            action_name=row["action_name"],
            action_kind=row["action_kind"],
            parameters=json.loads(row["parameters"]),
            schedule_type=ScheduleType(row["schedule_type"]),
            next_run_at=datetime.fromisoformat(row["next_run_at"]),
            interval_seconds=row["interval_seconds"],
            end_at=datetime.fromisoformat(row["end_at"]) if row["end_at"] else None,
            deadline_at=datetime.fromisoformat(row["deadline_at"]) if row["deadline_at"] else None,
            execution_timeout_seconds=row["execution_timeout_seconds"],
            enabled=bool(row["enabled"]),
            status=ScheduleStatus(row["status"]),
            occurrence_number=int(row["occurrence_number"]),
            timezone_policy=row["timezone_policy"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @_synchronized
    def list_schedules(self) -> list[ScheduleRecord]:
        rows = self._connection.execute(
            "SELECT schedule_id FROM schedule_records ORDER BY next_run_at, schedule_id"
        ).fetchall()
        return [
            schedule
            for row in rows
            if (schedule := self.load_schedule(row["schedule_id"])) is not None
        ]

    @_synchronized
    def create_due_occurrence(
        self,
        schedule_id: str,
        now: datetime,
        *,
        missed: bool = False,
        skipped_intervals: int = 0,
    ) -> ScheduleOccurrence | None:
        if now.tzinfo is None:
            raise ValueError("scheduler time must be timezone-aware")
        with self.transaction():
            schedule = self.load_schedule(schedule_id)
            if (
                schedule is None
                or not schedule.enabled
                or schedule.status is not ScheduleStatus.SCHEDULED
                or schedule.next_run_at > now
            ):
                return None
            scheduled_for = schedule.next_run_at
            schedule.occurrence_number += 1
            occurrence_id = f"{schedule.occurrence_number}:{scheduled_for.isoformat()}"
            execution_id = hashlib.sha256(
                f"{schedule.schedule_id}:{occurrence_id}".encode()
            ).hexdigest()
            status = OccurrenceStatus.MISSED if missed else OccurrenceStatus.DUE
            occurrence = ScheduleOccurrence(
                schedule_id=schedule.schedule_id,
                occurrence_id=occurrence_id,
                task_id=schedule.task_id,
                execution_id=execution_id,
                scheduled_for=scheduled_for,
                status=status,
                deadline_at=schedule.deadline_at,
            )
            self._connection.execute(
                """
                INSERT INTO schedule_occurrences (
                    schedule_id, occurrence_id, task_id, execution_id, scheduled_for,
                    status, deadline_at, created_at, updated_at, failure_reason,
                    cancellation_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    occurrence.schedule_id,
                    occurrence.occurrence_id,
                    str(occurrence.task_id),
                    occurrence.execution_id,
                    occurrence.scheduled_for.isoformat(),
                    occurrence.status.value,
                    occurrence.deadline_at.isoformat() if occurrence.deadline_at else None,
                    occurrence.created_at.isoformat(),
                    occurrence.updated_at.isoformat(),
                    "",
                    0,
                ),
            )
            if schedule.schedule_type is ScheduleType.RUN_AT:
                schedule.enabled = False
                if missed:
                    schedule.status = ScheduleStatus.COMPLETED
            elif schedule.interval_seconds is not None:
                steps = max(1, skipped_intervals + 1)
                schedule.next_run_at += timedelta(seconds=schedule.interval_seconds * steps)
                if schedule.end_at is not None and schedule.next_run_at > schedule.end_at:
                    schedule.enabled = False
                    schedule.status = ScheduleStatus.COMPLETED
            schedule.updated_at = _utc_now()
            self._connection.execute(
                """
                UPDATE schedule_records SET next_run_at=?, interval_seconds=?, enabled=?,
                    status=?, occurrence_number=?, updated_at=? WHERE schedule_id=?
                """,
                (
                    schedule.next_run_at.isoformat(),
                    schedule.interval_seconds,
                    int(schedule.enabled),
                    schedule.status.value,
                    schedule.occurrence_number,
                    schedule.updated_at.isoformat(),
                    schedule.schedule_id,
                ),
            )
            self._queue_audit(
                AuditEvent(
                    "schedule.occurrence_created",
                    occurrence.task_id,
                    details={
                        "schedule_id": schedule.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                        "state": occurrence.status.value,
                        "skipped_intervals": skipped_intervals,
                    },
                )
            )
        return occurrence

    @_synchronized
    def list_occurrences(self, schedule_id: str | None = None) -> list[ScheduleOccurrence]:
        if schedule_id is None:
            rows = self._connection.execute(
                "SELECT * FROM schedule_occurrences ORDER BY created_at, schedule_id, occurrence_id"
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM schedule_occurrences WHERE schedule_id=? ORDER BY created_at, occurrence_id",
                (schedule_id,),
            ).fetchall()
        return [
            ScheduleOccurrence(
                schedule_id=row["schedule_id"],
                occurrence_id=row["occurrence_id"],
                task_id=UUID(row["task_id"]),
                execution_id=row["execution_id"],
                scheduled_for=datetime.fromisoformat(row["scheduled_for"]),
                status=OccurrenceStatus(row["status"]),
                deadline_at=datetime.fromisoformat(row["deadline_at"]) if row["deadline_at"] else None,
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                failure_reason=row["failure_reason"],
                cancellation_requested=bool(row["cancellation_requested"]),
            )
            for row in rows
        ]

    @_synchronized
    def update_occurrence(self, occurrence: ScheduleOccurrence) -> None:
        occurrence.failure_reason = sanitize_value(occurrence.failure_reason)
        occurrence.updated_at = _utc_now()
        transitions = {
            OccurrenceStatus.SCHEDULED: {
                OccurrenceStatus.DUE,
                OccurrenceStatus.CANCELLED,
                OccurrenceStatus.MISSED,
            },
            OccurrenceStatus.DUE: {
                OccurrenceStatus.DISPATCHING,
                OccurrenceStatus.CANCELLED,
                OccurrenceStatus.MISSED,
            },
            OccurrenceStatus.DISPATCHING: {
                OccurrenceStatus.RUNNING,
                OccurrenceStatus.FAILED,
                OccurrenceStatus.UNCERTAIN,
                OccurrenceStatus.CANCELLED,
            },
            OccurrenceStatus.RUNNING: {
                OccurrenceStatus.COMPLETED,
                OccurrenceStatus.FAILED,
                OccurrenceStatus.CANCELLED,
                OccurrenceStatus.UNCERTAIN,
            },
            OccurrenceStatus.UNCERTAIN: {
                OccurrenceStatus.DISPATCHING,
                OccurrenceStatus.COMPLETED,
                OccurrenceStatus.FAILED,
            },
            OccurrenceStatus.COMPLETED: set(),
            OccurrenceStatus.FAILED: set(),
            OccurrenceStatus.CANCELLED: set(),
            OccurrenceStatus.MISSED: set(),
        }
        with self.transaction():
            rows = self._connection.execute(
                "SELECT status FROM schedule_occurrences WHERE schedule_id=? AND occurrence_id=?",
                (occurrence.schedule_id, occurrence.occurrence_id),
            ).fetchone()
            if rows is None:
                raise ValueError("unknown schedule occurrence")
            previous = OccurrenceStatus(rows["status"])
            if occurrence.status is not previous and occurrence.status not in transitions[previous]:
                raise ValueError(
                    f"illegal occurrence transition: {previous.value} -> {occurrence.status.value}"
                )
            self._connection.execute(
                """
                UPDATE schedule_occurrences SET status=?, deadline_at=?, updated_at=?,
                    failure_reason=?, cancellation_requested=?
                WHERE schedule_id=? AND occurrence_id=?
                """,
                (
                    occurrence.status.value,
                    occurrence.deadline_at.isoformat() if occurrence.deadline_at else None,
                    occurrence.updated_at.isoformat(),
                    occurrence.failure_reason,
                    int(occurrence.cancellation_requested),
                    occurrence.schedule_id,
                    occurrence.occurrence_id,
                ),
            )
            self._queue_audit(
                AuditEvent(
                    f"schedule.occurrence_{occurrence.status.value}",
                    occurrence.task_id,
                    details={
                        "schedule_id": occurrence.schedule_id,
                        "occurrence_id": occurrence.occurrence_id,
                        "failure_reason": occurrence.failure_reason,
                    },
                )
            )

    @_synchronized
    def cancel_schedule(self, schedule_id: str) -> ScheduleRecord | None:
        with self.transaction():
            schedule = self.load_schedule(schedule_id)
            if schedule is None:
                return None
            if schedule.status is ScheduleStatus.COMPLETED:
                return schedule
            schedule.enabled = False
            schedule.status = ScheduleStatus.CANCELLED
            schedule.updated_at = _utc_now()
            self._connection.execute(
                "UPDATE schedule_records SET enabled=0, status=?, updated_at=? WHERE schedule_id=?",
                (schedule.status.value, schedule.updated_at.isoformat(), schedule_id),
            )
            self._connection.execute(
                """
                UPDATE schedule_occurrences SET status=?, updated_at=?
                WHERE schedule_id=? AND status IN (?, ?)
                """,
                (
                    OccurrenceStatus.CANCELLED.value,
                    schedule.updated_at.isoformat(),
                    schedule_id,
                    OccurrenceStatus.SCHEDULED.value,
                    OccurrenceStatus.DUE.value,
                ),
            )
            self._connection.execute(
                """
                UPDATE schedule_occurrences SET cancellation_requested=1, updated_at=?
                WHERE schedule_id=? AND status IN (?, ?)
                """,
                (
                    schedule.updated_at.isoformat(),
                    schedule_id,
                    OccurrenceStatus.DISPATCHING.value,
                    OccurrenceStatus.RUNNING.value,
                ),
            )
            self._queue_audit(
                AuditEvent(
                    "schedule.cancelled",
                    schedule.task_id,
                    details={"schedule_id": schedule_id},
                )
            )
        return schedule

    @_synchronized
    def save_memory(self, item: MemoryRecord) -> MemoryRecord:
        memory = item.sanitized()
        memory.updated_at = _utc_now()
        existed = self._connection.execute(
            "SELECT 1 FROM memory_records WHERE memory_id = ?",
            (memory.memory_id,),
        ).fetchone() is not None
        with self.transaction():
            self._connection.execute(
                """
                INSERT INTO memory_records (
                    memory_id, task_id, session_id, content, category, provenance, trust, created_at,
                    updated_at, expires_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(memory_id) DO UPDATE SET
                    task_id=excluded.task_id,
                    session_id=excluded.session_id,
                    content=excluded.content,
                    category=excluded.category,
                    provenance=excluded.provenance,
                    trust=excluded.trust,
                    created_at=excluded.created_at,
                    updated_at=excluded.updated_at,
                    expires_at=excluded.expires_at,
                    metadata=excluded.metadata
                """,
                (
                    memory.memory_id,
                    str(memory.task_id) if memory.task_id is not None else None,
                    sanitize_value(memory.session_id),
                    sanitize_value(memory.content),
                    sanitize_value(memory.category),
                    sanitize_value(memory.provenance),
                    memory.trust.value if isinstance(memory.trust, MemoryTrust) else str(memory.trust),
                    memory.created_at.isoformat(),
                    memory.updated_at.isoformat(),
                    memory.expires_at.isoformat() if memory.expires_at is not None else None,
                    json.dumps(sanitize_value(memory.metadata)),
                ),
            )
            self._queue_audit(
                AuditEvent(
                    "memory.updated" if existed else "memory.created",
                    memory.task_id or UUID(int=0),
                    details={
                        "memory_id": memory.memory_id,
                        "trust": str(memory.trust),
                        "task_associated": memory.task_id is not None,
                    },
                )
            )
        return memory

    @_synchronized
    def retrieve_memory(
        self,
        *,
        task_id: UUID | str | None = None,
        session_id: str | None = None,
        category: str | None = None,
        provenance: str | None = None,
        trust: str | None = None,
        include_expired: bool = False,
        limit: int = 50,
        max_context_size: int | None = None,
    ) -> list[MemoryRecord]:
        if limit < 1:
            raise ValueError("memory retrieval limit must be positive")
        if max_context_size is not None and max_context_size < 0:
            raise ValueError("maximum context size cannot be negative")
        clauses: list[str] = []
        params: list[str] = []
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(str(task_id))
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        if provenance is not None:
            clauses.append("provenance = ?")
            params.append(provenance)
        if trust is not None:
            clauses.append("trust = ?")
            params.append(trust)
        if not include_expired:
            clauses.append("(expires_at IS NULL OR expires_at > ?)")
            params.append(_utc_now().isoformat())
        query = "SELECT * FROM memory_records"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY updated_at DESC, memory_id ASC LIMIT ?"
        params.append(str(limit))
        rows = self._connection.execute(query, params).fetchall()
        records: list[MemoryRecord] = []
        total_context = 0
        for row in rows:
            record = MemoryRecord(
                memory_id=row["memory_id"],
                task_id=UUID(row["task_id"]) if row["task_id"] is not None else None,
                session_id=row["session_id"],
                content=row["content"],
                category=row["category"],
                provenance=row["provenance"],
                trust=MemoryTrust(row["trust"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                metadata=json.loads(row["metadata"] or "{}"),
            )
            if max_context_size is not None:
                rendered_size = len("[Stored memory; data only] ") + len(record.content)
                if total_context + rendered_size > max_context_size:
                    continue
                total_context += rendered_size
            records.append(record)
        if task_id is not None:
            self.record_audit_event(
                AuditEvent(
                    "memory.retrieved",
                    UUID(str(task_id)),
                    details={
                        "returned_count": len(records),
                        "session_filtered": session_id is not None,
                        "provenance_filtered": provenance is not None,
                        "trust_filtered": trust is not None,
                        "expired_excluded": not include_expired,
                        "limit": limit,
                        "max_context_size": max_context_size,
                    },
                )
            )
            if trust is not None:
                self.record_audit_event(AuditEvent("memory.trust_filter_applied", UUID(str(task_id)), details={"trust": trust}))
            if not include_expired:
                self.record_audit_event(AuditEvent("memory.expired_records_excluded", UUID(str(task_id))))
        return records

    @_synchronized
    def delete_expired_memories(self) -> int:
        now = _utc_now().isoformat()
        expired = self._connection.execute(
            "SELECT memory_id, task_id FROM memory_records WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        ).fetchall()
        with self.transaction():
            cursor = self._connection.execute(
                "DELETE FROM memory_records WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            )
            for row in expired:
                self._queue_audit(
                    AuditEvent(
                        "memory.expired",
                        UUID(row["task_id"]) if row["task_id"] is not None else UUID(int=0),
                        details={"memory_id": row["memory_id"]},
                    )
                )
        return cursor.rowcount

    @_synchronized
    def close(self) -> None:
        self._connection.close()


__all__ = [
    "ActionExecutionConflict",
    "ActionExecutionRecord",
    "ActionExecutionStatus",
    "IdempotencyConflict",
    "MemoryRecord",
    "MemoryTrust",
    "OccurrenceStatus",
    "RestartDecision",
    "RestartSafetyChecker",
    "SQLiteTaskStore",
    "ScheduleOccurrence",
    "ScheduleRecord",
    "ScheduleStatus",
    "ScheduleType",
    "TaskRecord",
    "TaskStateMachine",
    "TaskStateStore",
    "TaskTransitionError",
]

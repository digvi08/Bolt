"""Single-process composition root and lifecycle owner for the Bolt application."""

from __future__ import annotations

import asyncio
import logging
import math
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID

from .api_auth import ApiCredentialStore
from .config import AgentConfig
from .models import ActionKind, ActionRequest, AuditEvent, RiskLevel
from .persistence import (
    OccurrenceStatus,
    SQLiteTaskStore,
)
from .ports import KillSwitch
from .runtime import AgentRuntime
from .scheduler import TaskScheduler
from .secrets import sanitize_exception, sanitize_text, sanitize_value
from .service import AgentService, SchedulerStatusResponse

if TYPE_CHECKING:
    from fastapi import FastAPI

    from agent_brain.executor import AgentExecutionLoop

logger = logging.getLogger(__name__)


class ApplicationState(StrEnum):
    NEW = "new"
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class ApplicationErrorCode(StrEnum):
    INVALID_TRANSITION = "invalid_transition"
    INVALID_CONFIGURATION = "invalid_configuration"
    OWNERSHIP_CONFLICT = "ownership_conflict"
    STARTUP_FAILED = "startup_failed"
    NOT_READY = "not_ready"
    SHUTDOWN_FAILED = "shutdown_failed"


class AgentApplicationError(RuntimeError):
    def __init__(self, code: ApplicationErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = sanitize_text(message)


class ApplicationOwnershipError(AgentApplicationError):
    def __init__(self) -> None:
        super().__init__(
            ApplicationErrorCode.OWNERSHIP_CONFLICT,
            "exclusive application ownership could not be acquired",
        )


@dataclass(frozen=True)
class AgentApplicationStatus:
    state: ApplicationState
    ownership_held: bool
    persistence_available: bool
    recovery_status: str
    recovery_denials: int
    scheduler_running: bool | None
    scheduler_shutdown: bool | None
    unresolved_actions: int
    unresolved_occurrences: int
    kill_switch_active: bool | None
    kill_switch_available: bool
    api_status: str
    timestamp: datetime


class ProcessOwnershipLock:
    """Kernel-released exclusive lock associated with one durable SQLite path."""

    _registry_lock: ClassVar[threading.Lock] = threading.Lock()
    _owned_paths: ClassVar[set[str]] = set()

    def __init__(self, database_path: str | Path) -> None:
        self._ephemeral = str(database_path) == ":memory:"
        if self._ephemeral:
            self._key = f"memory:{id(self)}"
            self._path: Path | None = None
        else:
            database = Path(database_path).expanduser().resolve(strict=False)
            requested = database.with_name(f"{database.name}.lock")
            self._path = requested
            self._key = os.path.normcase(str(requested))
        self._file: Any | None = None
        self._held = False

    @property
    def held(self) -> bool:
        return self._held

    def acquire(self) -> None:
        if self._held:
            return
        with self._registry_lock:
            if self._key in self._owned_paths:
                raise ApplicationOwnershipError()
            self._owned_paths.add(self._key)
        try:
            if not self._ephemeral:
                self._acquire_os_lock()
            self._held = True
        except (OSError, ValueError) as error:
            if self._file is not None:
                self._file.close()
                self._file = None
            with self._registry_lock:
                self._owned_paths.discard(self._key)
            raise ApplicationOwnershipError() from error

    def _acquire_os_lock(self) -> None:
        assert self._path is not None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("a+b")
        if self._file.seek(0, os.SEEK_END) == 0:
            self._file.write(b"\0")
            self._file.flush()
        self._file.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            lock_file = fcntl.flock  # type: ignore[attr-defined]
            lock_file(
                self._file.fileno(),
                fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
            )

    def release(self) -> None:
        if not self._held:
            return
        file = self._file
        self._file = None
        try:
            if file is not None:
                try:
                    if os.name == "nt":
                        import msvcrt

                        file.seek(0)
                        msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(file.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
                finally:
                    file.close()
        finally:
            self._held = False
            with self._registry_lock:
                self._owned_paths.discard(self._key)


class _LocalKillSwitch(KillSwitch):
    def is_engaged(self) -> bool:
        return False


class _UnavailableActionProvider:
    def execute(self, _action: ActionRequest) -> object:
        raise RuntimeError("no action provider is configured")

    async def execute_async(self, _action: ActionRequest) -> object:
        raise RuntimeError("no action provider is configured")


class _AuditSink:
    def record(self, _event: AuditEvent) -> None:
        return None


_APPLICATION_TRANSITIONS = {
    ApplicationState.NEW: {ApplicationState.STARTING, ApplicationState.STOPPED},
    ApplicationState.STARTING: {
        ApplicationState.READY,
        ApplicationState.DEGRADED,
        ApplicationState.FAILED,
    },
    ApplicationState.READY: {ApplicationState.STOPPING},
    ApplicationState.DEGRADED: {ApplicationState.STOPPING},
    ApplicationState.STOPPING: {ApplicationState.STOPPED},
    ApplicationState.STOPPED: set(),
    ApplicationState.FAILED: set(),
}


class AgentApplication:
    """Owns one store, runtime, executor, service, scheduler, and optional API."""

    def __init__(
        self,
        database_path: str | Path | None = None,
        *,
        config: AgentConfig | None = None,
    ) -> None:
        self.database_path = (
            Path(database_path).expanduser()
            if database_path is not None and str(database_path) != ":memory:"
            else database_path
        )
        self.config = config or AgentConfig()
        lock_database_path = self.database_path or SQLiteTaskStore.default_path()
        self._ownership = ProcessOwnershipLock(lock_database_path)
        self._state = ApplicationState.NEW
        self._state_lock = threading.RLock()
        self._shutdown_lock = asyncio.Lock()
        self._store: SQLiteTaskStore | None = None
        self._runtime: AgentRuntime | None = None
        self._executor: AgentExecutionLoop | None = None
        self._scheduler: TaskScheduler | None = None
        self._service: AgentService | None = None
        self._api: FastAPI | None = None
        self._api_configured_scheduler = False
        self._recovery_status = "not_started"
        self._startup_error: AgentApplicationError | None = None

    @property
    def state(self) -> ApplicationState:
        with self._state_lock:
            return self._state

    @property
    def service(self) -> AgentService:
        if self._service is None:
            raise AgentApplicationError(ApplicationErrorCode.NOT_READY, "application is not composed")
        return self._service

    @property
    def scheduler(self) -> TaskScheduler:
        if self._scheduler is None:
            raise AgentApplicationError(ApplicationErrorCode.NOT_READY, "application is not composed")
        return self._scheduler

    @property
    def store(self) -> SQLiteTaskStore:
        if self._store is None:
            raise AgentApplicationError(ApplicationErrorCode.NOT_READY, "application is not composed")
        return self._store

    def start(
        self,
        *,
        api_credentials: ApiCredentialStore | None = None,
        start_scheduler_on_api_start: bool = False,
    ) -> AgentApplicationStatus:
        self._transition(ApplicationState.STARTING)
        try:
            self._validate_config()
            self._ownership.acquire()
            self._store = SQLiteTaskStore(self.database_path)
            self._audit("application.ownership_acquired")

            from abilities.registry import AbilityRegistry
            from agent_brain.executor import AgentExecutionLoop

            kill_switch = _LocalKillSwitch()
            audit_sink = _AuditSink()
            self._runtime = AgentRuntime(
                self.config,
                _UnavailableActionProvider(),
                audit_sink,
                kill_switch,
                state_store=self._store,
            )
            self._executor = AgentExecutionLoop(
                registry=AbilityRegistry(),
                config=self.config,
                audit_sink=audit_sink,
                kill_switch=kill_switch,
                state_store=self._store,
            )
            self._scheduler = TaskScheduler(self._store, self._runtime)
            self._service = AgentService(
                self._store,
                self._executor,
                self._runtime,
                self._scheduler,
            )

            if api_credentials is not None:
                from .api import create_api_app

                self._api_configured_scheduler = start_scheduler_on_api_start
                self._api = create_api_app(
                    self._service,
                    api_credentials,
                    lifecycle_state=lambda: self.state.value,
                    lifecycle_status=self.status,
                    lifecycle_start_scheduler=self.start_scheduler,
                    lifecycle_stop_scheduler=self.stop_scheduler,
                    lifecycle_run_scheduler_once=self.run_scheduler_once,
                )
                self._attach_api_lifecycle()

            unresolved_actions, unresolved_occurrences = self._unresolved_counts()
            recovery_denials = self._recovery_denial_count()
            scheduler_status = self._service.scheduler_status()
            if unresolved_actions or unresolved_occurrences or recovery_denials:
                self._recovery_status = (
                    "blocked_uncertain_work"
                    if unresolved_actions or unresolved_occurrences
                    else "blocked_restart_recovery"
                )
                target_state = ApplicationState.DEGRADED
                self._audit(
                    "application.started_degraded",
                    unresolved_actions=unresolved_actions,
                    unresolved_occurrences=unresolved_occurrences,
                    recovery_denials=recovery_denials,
                )
            else:
                self._recovery_status = "clear"
                target_state = ApplicationState.READY
                self._audit("application.started")
            self._transition(target_state)
            return self._status_snapshot(
                unresolved_actions,
                unresolved_occurrences,
                recovery_denials,
                scheduler_status,
            )
        except AgentApplicationError as error:
            self._fail_startup(error)
            raise
        except Exception as error:
            failure = AgentApplicationError(
                ApplicationErrorCode.STARTUP_FAILED,
                "application startup failed: " + sanitize_exception(error),
            )
            self._fail_startup(failure)
            raise failure from error

    @property
    def api(self) -> FastAPI:
        if self._api is None:
            raise AgentApplicationError(ApplicationErrorCode.NOT_READY, "API is not configured")
        return self._api

    def status(self) -> AgentApplicationStatus:
        unresolved_actions, unresolved_occurrences = self._unresolved_counts()
        recovery_denials = self._recovery_denial_count()
        scheduler_status: SchedulerStatusResponse | None = None
        if self._service is not None and self.state not in {
            ApplicationState.STOPPED,
            ApplicationState.FAILED,
        }:
            scheduler_status = self._service.scheduler_status()
        return self._status_snapshot(
            unresolved_actions,
            unresolved_occurrences,
            recovery_denials,
            scheduler_status,
        )

    def _status_snapshot(
        self,
        unresolved_actions: int,
        unresolved_occurrences: int,
        recovery_denials: int,
        scheduler_status: SchedulerStatusResponse | None,
    ) -> AgentApplicationStatus:
        return AgentApplicationStatus(
            state=self.state,
            ownership_held=self._ownership.held,
            persistence_available=self._store is not None
            and self.state not in {ApplicationState.STOPPED, ApplicationState.FAILED},
            recovery_status=self._recovery_status,
            recovery_denials=recovery_denials,
            scheduler_running=scheduler_status.running if scheduler_status else None,
            scheduler_shutdown=scheduler_status.shutdown if scheduler_status else None,
            unresolved_actions=unresolved_actions,
            unresolved_occurrences=unresolved_occurrences,
            kill_switch_active=scheduler_status.kill_switch_active if scheduler_status else None,
            kill_switch_available=False,
            api_status=(
                "available"
                if self._api is not None and self.state in {ApplicationState.READY, ApplicationState.DEGRADED}
                else "unavailable"
            ),
            timestamp=datetime.now(UTC),
        )

    async def start_scheduler(self) -> SchedulerStatusResponse:
        if self.state is not ApplicationState.READY or not self._ownership.held:
            raise AgentApplicationError(
                ApplicationErrorCode.NOT_READY,
                "scheduler requires a ready application with process ownership",
            )
        assert self._service is not None
        try:
            status = await self._service.start_scheduler()
        except Exception as error:
            raise AgentApplicationError(
                ApplicationErrorCode.STARTUP_FAILED,
                "application scheduler could not start: " + sanitize_exception(error),
            ) from error
        try:
            self._audit("application.scheduler_started")
        except Exception as error:
            try:
                await self._service.stop_scheduler()
            except Exception as cleanup_error:  # noqa: BLE001 - preserve cleanup failure safely
                logger.error("scheduler rollback failed: %s", sanitize_exception(cleanup_error))
            raise AgentApplicationError(
                ApplicationErrorCode.STARTUP_FAILED,
                "application scheduler start could not be audited",
            ) from error
        return status

    async def stop_scheduler(self) -> SchedulerStatusResponse:
        if not self._ownership.held or self.state not in {
            ApplicationState.READY,
            ApplicationState.DEGRADED,
        }:
            raise AgentApplicationError(
                ApplicationErrorCode.NOT_READY,
                "scheduler control requires an active application owner",
            )
        assert self._service is not None
        status = await self._service.stop_scheduler()
        self._audit("application.scheduler_stopped")
        return status

    async def run_scheduler_once(self) -> object:
        if self.state is not ApplicationState.READY or not self._ownership.held:
            raise AgentApplicationError(
                ApplicationErrorCode.NOT_READY,
                "scheduled dispatch requires a ready application with process ownership",
            )
        assert self._service is not None
        result = await self._service.run_scheduler_once()
        self._audit("application.scheduler_run_once")
        return result

    async def shutdown(self) -> None:
        async with self._shutdown_lock:
            if self.state in {ApplicationState.STOPPED, ApplicationState.FAILED}:
                return
            if self.state is ApplicationState.NEW:
                self._transition(ApplicationState.STOPPED)
                return
            if self.state is ApplicationState.STOPPING:
                return
            self._transition(ApplicationState.STOPPING)
            cleanup = asyncio.create_task(self._shutdown_owned_resources())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
                raise

    async def _shutdown_owned_resources(self) -> None:
        failures: list[str] = []
        try:
            if self._service is not None:
                try:
                    await self._service.shutdown()
                except asyncio.CancelledError as error:
                    failures.append(sanitize_exception(error))
                    if self._scheduler is not None:
                        try:
                            await self._scheduler.close()
                        except asyncio.CancelledError as cleanup_error:
                            failures.append(sanitize_exception(cleanup_error))
                        except Exception as cleanup_error:  # noqa: BLE001 - continue cleanup
                            failures.append(sanitize_exception(cleanup_error))
                except Exception as error:  # noqa: BLE001 - continue ordered cleanup
                    failures.append(sanitize_exception(error))
                    if self._scheduler is not None:
                        try:
                            await self._scheduler.close()
                        except Exception as cleanup_error:  # noqa: BLE001 - continue cleanup
                            failures.append(sanitize_exception(cleanup_error))
                else:
                    try:
                        self._audit("application.scheduler_stopped")
                    except Exception as error:  # noqa: BLE001 - continue ordered cleanup
                        failures.append(sanitize_exception(error))
            elif self._scheduler is not None:
                try:
                    await self._scheduler.close()
                except Exception as error:  # noqa: BLE001 - continue ordered cleanup
                    failures.append(sanitize_exception(error))
            if self._store is not None:
                try:
                    self._audit("application.shutdown")
                    self._audit("application.ownership_releasing")
                except Exception as error:  # noqa: BLE001 - close store despite audit errors
                    failures.append(sanitize_exception(error))
                try:
                    self._store.close()
                except Exception as error:  # noqa: BLE001 - ownership still releases last
                    failures.append(sanitize_exception(error))
        finally:
            try:
                self._ownership.release()
            except Exception as error:  # noqa: BLE001 - finish state transition after release attempt
                failures.append(sanitize_exception(error))
            self._store = None
            self._transition(ApplicationState.STOPPED)
        logger.info("application ownership released")
        if failures:
            logger.error("application shutdown cleanup reported errors: %s", "; ".join(failures))

    async def _start_configured_scheduler(self) -> None:
        if not self._api_configured_scheduler:
            return
        try:
            await self.start_scheduler()
        except Exception:
            await self.shutdown()
            raise

    def _attach_api_lifecycle(self) -> None:
        assert self._api is not None
        self._api.add_event_handler("startup", self._start_configured_scheduler)
        self._api.add_event_handler("shutdown", self.shutdown)

    def _unresolved_counts(self) -> tuple[int, int]:
        if self._store is None:
            return 0, 0
        actions = self._store.list_uncertain_actions(limit=10000)
        occurrences = self._store.list_occurrences()
        unresolved_actions = len(actions)
        unresolved_occurrences = sum(
            occurrence.status is OccurrenceStatus.UNCERTAIN for occurrence in occurrences
        )
        return unresolved_actions, unresolved_occurrences

    def _recovery_denial_count(self) -> int:
        if self._runtime is None:
            return 0
        return sum(not decision.allowed for _task, decision in self._runtime.restart_decisions)

    def _audit(self, event_type: str, **details: object) -> None:
        store = self._store
        if store is None:
            return
        safe_details = sanitize_value(details)
        store.record_audit_event(
            AuditEvent(
                event_type,
                UUID(int=0),
                details=safe_details,
            )
        )

    def _validate_config(self) -> None:
        config = self.config
        valid = (
            config.max_plan_steps >= 1
            and config.max_replans >= 0
            and config.max_model_calls >= 1
            and config.max_total_tokens >= 1
            and config.max_task_duration_ms >= 1
            and isinstance(config.approval_required_at, RiskLevel)
            and isinstance(config.max_automatic_risk, RiskLevel)
            and all(isinstance(action, ActionKind) for action in config.allowed_actions)
        )
        numeric_limits = (
            config.max_total_cost,
            config.model_input_price_per_1k,
            config.model_output_price_per_1k,
        )
        valid = valid and all(
            value is None or math.isfinite(value) and value >= 0
            for value in numeric_limits
        )
        if not valid:
            raise AgentApplicationError(
                ApplicationErrorCode.INVALID_CONFIGURATION,
                "application configuration contains invalid limits or policy values",
            )

    def _fail_startup(self, error: AgentApplicationError) -> None:
        self._startup_error = error
        if error.code is ApplicationErrorCode.OWNERSHIP_CONFLICT:
            logger.warning("application ownership acquisition failed")
        else:
            logger.error("application startup failed (%s)", error.code.value)
        if self._store is not None:
            try:
                self._audit("application.startup_failed", code=error.code.value)
            except Exception:  # noqa: BLE001 - startup rollback must continue through all resources
                logger.error("application startup failure audit could not be persisted")
        if self._scheduler is not None:
            try:
                self._scheduler.shutdown()
            except Exception:  # noqa: BLE001 - continue startup rollback
                logger.error("application scheduler cleanup failed during startup rollback")
        if self._store is not None:
            try:
                self._store.close()
            except Exception:  # noqa: BLE001 - continue startup rollback
                logger.error("application store cleanup failed during startup rollback")
            self._store = None
        try:
            self._ownership.release()
        except Exception:  # noqa: BLE001 - ownership release is part of startup rollback
            logger.error("application ownership cleanup failed during startup rollback")
        if self.state is ApplicationState.STARTING:
            self._transition(ApplicationState.FAILED)

    def _transition(self, state: ApplicationState) -> None:
        with self._state_lock:
            if state not in _APPLICATION_TRANSITIONS[self._state]:
                raise AgentApplicationError(
                    ApplicationErrorCode.INVALID_TRANSITION,
                    f"invalid application lifecycle transition: {self._state.value} to {state.value}",
                )
            self._state = state


__all__ = [
    "AgentApplication",
    "AgentApplicationError",
    "AgentApplicationStatus",
    "ApplicationErrorCode",
    "ApplicationOwnershipError",
    "ApplicationState",
    "ProcessOwnershipLock",
]

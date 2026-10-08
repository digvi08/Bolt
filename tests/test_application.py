from __future__ import annotations

import asyncio
import multiprocessing
import threading
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import agent_core.application as application_module
from agent_core.api_auth import ApiCredentialStore, ApiScope
from agent_core.api_server import create_default_app
from agent_core.application import (
    AgentApplication,
    AgentApplicationError,
    ApplicationErrorCode,
    ApplicationOwnershipError,
    ApplicationState,
)
from agent_core.config import AgentConfig
from agent_core.models import TaskStatus
from agent_core.persistence import (
    ActionExecutionRecord,
    ActionExecutionStatus,
    SQLiteTaskStore,
    TaskRecord,
)
from agent_core.secrets import Secret


def _own_database_until_released(
    database_path: str,
    ready: multiprocessing.synchronize.Event,
    release: multiprocessing.synchronize.Event,
    result: multiprocessing.queues.Queue[tuple[str, bool]],
) -> None:
    application = AgentApplication(database_path)
    try:
        status = application.start()
        result.put((status.state.value, application.service.scheduler_status().running))
        ready.set()
        if not release.wait(20):
            raise TimeoutError("test parent did not release application ownership")
    finally:
        asyncio.run(application.shutdown())


def _auth(token: str | Secret[str]) -> dict[str, str]:
    value = token.reveal(purpose="test HTTP authentication") if isinstance(token, Secret) else token
    return {"Authorization": f"Bearer {value}"}


def test_application_state_machine_and_idempotent_shutdown(tmp_path):
    application = AgentApplication(tmp_path / "state.sqlite3")
    with pytest.raises(AgentApplicationError) as before_start:
        application._transition(ApplicationState.READY)
    assert before_start.value.code is ApplicationErrorCode.INVALID_TRANSITION

    status = application.start()
    assert status.state is ApplicationState.READY
    asyncio.run(application.shutdown())
    asyncio.run(application.shutdown())
    assert application.state is ApplicationState.STOPPED
    with pytest.raises(AgentApplicationError) as after_stop:
        application._transition(ApplicationState.READY)
    assert after_stop.value.code is ApplicationErrorCode.INVALID_TRANSITION


def test_single_application_owns_one_scheduler_and_api_uses_same_service(tmp_path):
    credential_store = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credential_store.create(
        {ApiScope.APPLICATION_READ, ApiScope.SCHEDULER_READ, ApiScope.SAFETY_READ}
    )
    application = AgentApplication(tmp_path / "state.sqlite3")
    status = application.start(api_credentials=credential_store)

    assert status.state is ApplicationState.READY
    assert application.api.state.agent_service is application.service
    assert application.service._scheduler is application.scheduler
    assert application.status().api_status == "available"

    with TestClient(application.api) as client:
        response = client.get("/application/status", headers=_auth(credential.token))
        assert response.status_code == 200
        payload = response.json()
        assert payload["state"] == "ready"
        assert payload["ownership_held"] is True
        assert payload["persistence_available"] is True
        assert payload["kill_switch_available"] is True
        assert isinstance(payload["provider_store_available"], bool)
        assert "secret_ref:" not in response.text

    assert application.state is ApplicationState.STOPPED


def test_operator_kill_switch_persists_and_environment_override_cannot_be_cleared(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    database = tmp_path / "safety.sqlite3"
    application = AgentApplication(database)
    application.start()

    assert application.set_kill_switch_active(True) is True
    assert application._runtime is not None
    assert application._runtime.kill_switch_active() is True
    events = application.store.audit_events()
    assert any(event.event_type == "safety.kill_switch_activated" for event in events)
    asyncio.run(application.shutdown())

    restarted = AgentApplication(database)
    restarted.start()
    assert restarted._runtime is not None
    assert restarted._runtime.kill_switch_active() is True
    assert restarted.set_kill_switch_active(False) is False

    monkeypatch.setenv("BOLT_KILL_SWITCH_ACTIVE", "true")
    assert restarted.set_kill_switch_active(False) is True
    assert restarted._runtime.kill_switch_active() is True
    asyncio.run(restarted.shutdown())


def test_scheduler_start_requires_ready_owner_and_shutdown_stops_it(tmp_path):
    application = AgentApplication(tmp_path / "state.sqlite3")
    with pytest.raises(AgentApplicationError) as not_ready:
        asyncio.run(application.start_scheduler())
    assert not_ready.value.code is ApplicationErrorCode.NOT_READY

    application.start()

    async def start_then_shutdown() -> tuple[bool, bool]:
        status = await application.start_scheduler()
        was_running = status.running
        await application.shutdown()
        return was_running, application.state is ApplicationState.STOPPED

    was_running, stopped = asyncio.run(start_then_shutdown())
    assert was_running
    assert stopped
    assert application._scheduler is not None


def test_startup_recovery_precedes_ready_and_uncertainty_blocks_scheduler(tmp_path):
    database = tmp_path / "recovery.sqlite3"
    store = SQLiteTaskStore(database)
    task_id = UUID("d1c418c2-7103-4e92-9b91-aab642e4b58a")
    task = TaskRecord(task_id=task_id, objective="recover safely")
    store.save_task(task)
    task.status = TaskStatus.EXECUTING
    store.save_task(task)
    action = ActionExecutionRecord(
        action_id="execution-in-flight",
        task_id=task_id,
        name="browser.submit",
        metadata={"execution_owner": "previous-process"},
    )
    store.save_action(action)
    action.status = ActionExecutionStatus.EXECUTING
    action.attempts = 1
    store.save_action(action)
    store.close()

    credential_store = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credential_store.create({ApiScope.APPLICATION_READ, ApiScope.TASK_READ})
    application = AgentApplication(database)
    status = application.start(api_credentials=credential_store)

    assert status.state is ApplicationState.DEGRADED
    assert status.recovery_status == "blocked_uncertain_work"
    assert status.unresolved_actions == 1
    assert application.store.get_action(task_id, "execution-in-flight").status is ActionExecutionStatus.UNCERTAIN
    with pytest.raises(AgentApplicationError) as not_ready:
        asyncio.run(application.start_scheduler())
    assert not_ready.value.code is ApplicationErrorCode.NOT_READY

    with TestClient(application.api) as client:
        status_response = client.get("/application/status", headers=_auth(credential.token))
        assert status_response.status_code == 200
        assert status_response.json()["state"] == "degraded"
        blocked = client.get("/tasks", headers=_auth(credential.token))
        assert blocked.status_code == 503
        assert blocked.json()["error"]["code"] == "APPLICATION_UNAVAILABLE"


def test_pending_verification_restart_is_degraded_even_without_uncertain_action_status(tmp_path):
    database = tmp_path / "verification.sqlite3"
    store = SQLiteTaskStore(database)
    task_id = UUID("b992f6a5-cdf1-4b45-b90e-28a75b0858f0")
    task = TaskRecord(task_id=task_id, objective="verify after restart")
    store.save_task(task)
    task.status = TaskStatus.EXECUTING
    store.save_task(task)
    task.status = TaskStatus.VERIFYING
    store.save_task(task)

    action = ActionExecutionRecord(
        action_id="completed-awaiting-verification",
        task_id=task_id,
        name="browser.submit",
    )
    store.save_action(action)
    action.status = ActionExecutionStatus.EXECUTING
    action.attempts = 1
    store.save_action(action)
    action.status = ActionExecutionStatus.COMPLETED
    store.save_action(action)
    store.close()

    application = AgentApplication(database)
    status = application.start()
    assert status.state is ApplicationState.DEGRADED
    assert status.recovery_status == "blocked_restart_recovery"
    assert status.recovery_denials == 1
    assert status.unresolved_actions == 0
    with pytest.raises(AgentApplicationError) as blocked:
        asyncio.run(application.start_scheduler())
    assert blocked.value.code is ApplicationErrorCode.NOT_READY
    asyncio.run(application.shutdown())


def test_api_rejects_requests_after_shutdown_begins(tmp_path):
    credential_store = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credential_store.create({ApiScope.APPLICATION_READ, ApiScope.TASK_READ})
    application = AgentApplication(tmp_path / "state.sqlite3")
    application.start(api_credentials=credential_store)
    client = TestClient(application.api)

    asyncio.run(application.shutdown())
    response = client.get("/tasks", headers=_auth(credential.token))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "APPLICATION_UNAVAILABLE"
    client.close()


def test_cancelled_shutdown_keeps_ownership_until_cleanup_finishes(tmp_path):
    application = AgentApplication(tmp_path / "state.sqlite3")
    application.start()

    async def exercise() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        original_shutdown = application.service.shutdown

        async def delayed_shutdown() -> None:
            entered.set()
            await release.wait()
            await original_shutdown()

        application.service.shutdown = delayed_shutdown
        shutdown_task = asyncio.create_task(application.shutdown())
        await entered.wait()
        shutdown_task.cancel()
        assert application._ownership.held
        assert application.state is ApplicationState.STOPPING
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await shutdown_task

    asyncio.run(exercise())
    assert application.state is ApplicationState.STOPPED
    assert not application._ownership.held


def test_api_server_uses_one_application_and_scheduler_start_is_explicit(tmp_path):
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    app = create_default_app(
        tmp_path / "state.sqlite3",
        tmp_path / "credentials.json",
        start_scheduler=True,
    )
    application = app.state.agent_application
    try:
        assert app.state.agent_service is application.service
        assert application.service._scheduler is application.scheduler
        assert application.service.scheduler_status().running is False
        with TestClient(app):
            assert application.service.scheduler_status().running is True
    finally:
        asyncio.run(application.shutdown())
    assert application.state is ApplicationState.STOPPED
    assert credentials.list_status() == ()


def test_api_scheduler_controls_use_application_owned_lifecycle(tmp_path):
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create({ApiScope.SCHEDULER_CONTROL})
    application = AgentApplication(tmp_path / "state.sqlite3")
    application.start(api_credentials=credentials)

    with TestClient(application.api) as client:
        started = client.post("/scheduler/start", headers=_auth(credential.token))
        assert started.status_code == 200
        assert started.json()["running"] is True
        stopped = client.post("/scheduler/stop", headers=_auth(credential.token))
        assert stopped.status_code == 200
        assert stopped.json()["running"] is False
        audit_names = {event.event_type for event in application.store.audit_events()}

    assert "application.scheduler_started" in audit_names
    assert "application.scheduler_stopped" in audit_names
    assert application.state is ApplicationState.STOPPED


def test_invalid_config_fails_before_acquiring_database_ownership(tmp_path):
    invalid = AgentConfig(max_total_tokens=0)
    application = AgentApplication(tmp_path / "invalid.sqlite3", config=invalid)
    with pytest.raises(AgentApplicationError) as error:
        application.start()
    assert error.value.code is ApplicationErrorCode.INVALID_CONFIGURATION
    assert application.state is ApplicationState.FAILED
    assert not application._ownership.held

    valid = AgentApplication(tmp_path / "invalid.sqlite3")
    assert valid.start().state is ApplicationState.READY
    asyncio.run(valid.shutdown())


def test_two_threads_competing_for_same_database_have_one_owner(tmp_path):
    database = tmp_path / "shared.sqlite3"
    barrier = threading.Barrier(3)
    applications = [AgentApplication(database), AgentApplication(database)]

    def start(application: AgentApplication) -> tuple[AgentApplication, Exception | None]:
        barrier.wait()
        try:
            application.start()
            return application, None
        except AgentApplicationError as error:
            return application, error

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(start, app) for app in applications]
        barrier.wait()
        results = [future.result(timeout=10) for future in futures]

    succeeded = [(app, error) for app, error in results if error is None]
    failed = [(app, error) for app, error in results if error is not None]
    assert len(succeeded) == len(failed) == 1
    losing_app, ownership_error = failed[0]
    assert isinstance(ownership_error, ApplicationOwnershipError)
    assert losing_app.state is ApplicationState.FAILED
    assert losing_app._store is None
    assert losing_app._scheduler is None
    assert succeeded[0][0].service.scheduler_status().running is False
    asyncio.run(succeeded[0][0].shutdown())


def test_second_process_fails_before_opening_store_or_constructing_scheduler(tmp_path):
    database = str(tmp_path / "shared.sqlite3")
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    result = context.Queue()
    process = context.Process(
        target=_own_database_until_released,
        args=(database, ready, release, result),
    )
    process.start()
    try:
        assert ready.wait(20), "first process did not become ready"
        assert result.get(timeout=5) == ("ready", False)

        second = AgentApplication(database)
        with pytest.raises(ApplicationOwnershipError):
            second.start()
        assert second.state is ApplicationState.FAILED
        assert second._store is None
        assert second._scheduler is None
        assert second._executor is None
    finally:
        release.set()
        process.join(20)
        if process.is_alive():
            process.terminate()
            process.join(10)
    assert process.exitcode == 0


def test_os_lock_is_released_after_abnormal_process_termination(tmp_path):
    database = str(tmp_path / "crash.sqlite3")
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    result = context.Queue()
    process = context.Process(
        target=_own_database_until_released,
        args=(database, ready, release, result),
    )
    process.start()
    assert ready.wait(20), "owner process did not become ready"
    assert result.get(timeout=5) == ("ready", False)
    process.terminate()
    process.join(20)
    assert process.exitcode is not None

    restarted = AgentApplication(database)
    status = restarted.start()
    assert status.state is ApplicationState.READY
    asyncio.run(restarted.shutdown())


@pytest.mark.parametrize(
    "failure_point",
    ["store", "runtime", "recovery", "scheduler", "service", "api"],
)
def test_startup_failure_releases_resources_and_ownership(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
):
    database = tmp_path / f"{failure_point}.sqlite3"

    def fail(*_args, **_kwargs):
        raise RuntimeError(f"{failure_point} failure")

    credentials = ApiCredentialStore(tmp_path / f"{failure_point}-credentials.json")
    with monkeypatch.context() as patch:
        if failure_point == "store":
            patch.setattr(application_module, "SQLiteTaskStore", fail)
        elif failure_point == "runtime":
            patch.setattr(application_module, "AgentRuntime", fail)
        elif failure_point == "recovery":
            patch.setattr(application_module.AgentRuntime, "recover_pending_tasks", fail)
        elif failure_point == "scheduler":
            patch.setattr(application_module, "TaskScheduler", fail)
        elif failure_point == "service":
            patch.setattr(application_module, "AgentService", fail)
        else:
            import agent_core.api

            patch.setattr(agent_core.api, "create_api_app", fail)

        application = AgentApplication(database)
        with pytest.raises(AgentApplicationError) as error:
            application.start(api_credentials=credentials if failure_point == "api" else None)
        assert error.value.code is ApplicationErrorCode.STARTUP_FAILED
        assert error.value.__context__ is None
        assert error.value.__cause__ is None

    assert application.state is ApplicationState.FAILED
    assert not application._ownership.held
    assert application._store is None

    retry = AgentApplication(database)
    assert retry.start().state is ApplicationState.READY
    asyncio.run(retry.shutdown())


def test_shutdown_cleanup_releases_owner_even_when_audit_fails(tmp_path, monkeypatch):
    database = tmp_path / "audit-failure.sqlite3"
    application = AgentApplication(database)
    application.start()

    def fail_audit(_event):
        raise OSError("token=should-not-leak")

    monkeypatch.setattr(application.store, "record_audit_event", fail_audit)
    asyncio.run(application.shutdown())
    assert application.state is ApplicationState.STOPPED
    assert not application._ownership.held
    retry = AgentApplication(database)
    assert retry.start().state is ApplicationState.READY
    asyncio.run(retry.shutdown())

from __future__ import annotations

import socket
import threading
import time
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from uuid import uuid4

import pytest
import uvicorn
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

from agent_core.api import create_api_app
from agent_core.api_auth import ApiCredentialStore, ApiScope
from agent_core.api_server import create_default_app
from agent_core.api_server import main as api_server_main
from agent_core.application import AgentApplication
from agent_core.approval import ApprovalView
from agent_core.cli import run_cli
from agent_core.models import CredentialCallerId, TaskStatus
from agent_core.persistence import (
    ApprovalStatus,
    OccurrenceStatus,
    ScheduleStatus,
    ScheduleType,
    TaskRecord,
)
from agent_core.service import (
    ScheduleResponse,
    SchedulerOccurrenceResponse,
    SubmitTaskResult,
    TaskStatusResponse,
)


def _scopes() -> set[ApiScope]:
    return {
        ApiScope.APPLICATION_READ,
        ApiScope.TASK_READ,
        ApiScope.TASK_SUBMIT,
        ApiScope.APPROVAL_READ,
        ApiScope.APPROVAL_APPROVE,
        ApiScope.APPROVAL_DENY,
        ApiScope.SCHEDULE_READ,
        ApiScope.SCHEDULE_CREATE,
        ApiScope.SCHEDULE_MODIFY,
        ApiScope.SCHEDULE_CANCEL,
        ApiScope.SCHEDULER_READ,
        ApiScope.AUDIT_READ,
        ApiScope.SAFETY_READ,
        ApiScope.SAFETY_CONTROL,
    }


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class UiTaskService:
    def __init__(self) -> None:
        self.tasks: dict[str, TaskStatusResponse] = {}
        self.audit_events: list[tuple[str, dict[str, object]]] = []

    def record_api_audit_event(self, event_type: str, **details: object) -> None:
        self.audit_events.append((event_type, details))

    def submit_task(self, request) -> SubmitTaskResult:
        now = datetime.now(UTC)
        task = TaskStatusResponse(
            task_id=uuid4(),
            objective=request.objective,
            status=TaskStatus.CREATED,
            verification_state="pending",
            approval_required=False,
            denied=False,
            uncertain=False,
            retry_count=0,
            replan_count=0,
            created_at=now,
            updated_at=now,
            actions=(),
            schedule_ids=(),
            schedules=(),
            last_error="",
        )
        self.tasks[str(task.task_id)] = task
        return SubmitTaskResult(task, True, False)

    def list_tasks(self, *, limit: int = 100):
        return tuple(self.tasks.values())[:limit]

    def get_task(self, task_id):
        return self.tasks[str(task_id)]


class UiApprovalService:
    def __init__(self) -> None:
        self.approve_calls = 0
        self.deny_calls = 0
        self.approval = ApprovalView(
            approval_id="approval-ui-test",
            task_id=str(uuid4()),
            action_id="action-ui-test",
            ability="browser",
            action_kind="browser",
            provider="restricted-browser",
            caller_id="local",
            summary="Submit the reviewed form",
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
            status=ApprovalStatus.PENDING,
            decision_at=None,
            decision_actor=None,
        )

    def record_api_audit_event(self, *_args, **_kwargs) -> None:
        return None

    def get_approval(self, _approval_id: str) -> ApprovalView:
        return self.approval

    def list_approvals(self, *, limit: int = 100):
        return (self.approval,)[:limit]

    def approve_approval(self, _approval_id: str, *, actor: str):
        self.approve_calls += 1
        self.approval = ApprovalView(
            **{**self.approval.__dict__, "status": ApprovalStatus.APPROVED, "decision_actor": actor}
        )
        return {"approval": self.approval, "resumed": True}

    def deny_approval(self, _approval_id: str, *, actor: str):
        self.deny_calls += 1
        self.approval = ApprovalView(
            **{**self.approval.__dict__, "status": ApprovalStatus.DENIED, "decision_actor": actor}
        )
        return {"approval": self.approval, "resumed": False}


class UiScheduleService:
    def __init__(self) -> None:
        now = datetime.now(UTC)
        self.schedule = ScheduleResponse(
            schedule_id="schedule-ui-test",
            task_id=uuid4(),
            objective="Research and save a report",
            action_name="",
            action_kind="",
            schedule_type=ScheduleType.INTERVAL,
            status=ScheduleStatus.SCHEDULED,
            enabled=True,
            next_occurrence=now,
            cancellation_pending=False,
            interval_seconds=3600,
            occurrence_count=1,
            created_at=now,
            updated_at=now,
            execution_mode="objective",
        )
        self.occurrences = (
            SchedulerOccurrenceResponse(
                schedule_id=self.schedule.schedule_id,
                occurrence_id="occurrence-ui-test",
                status=OccurrenceStatus.AWAITING_APPROVAL,
                success=None,
                uncertain=False,
                scheduled_for=now,
                updated_at=now,
            ),
        )

    def record_api_audit_event(self, *_args, **_kwargs) -> None:
        return None

    def get_schedule(self, _schedule_id: str) -> ScheduleResponse:
        return self.schedule

    def list_schedule_occurrences(self, _schedule_id: str, *, limit: int = 100):
        return self.occurrences[:limit]


def test_ui_assets_load_and_dynamic_content_is_text_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("BOLT_MODEL_API_KEY", "never-send-this-secret")
    monkeypatch.setenv("BOLT_WORKSPACE_ROOT", str(tmp_path / "missing-workspace"))
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create(_scopes())
    app = create_default_app(tmp_path / "state.sqlite3", tmp_path / "credentials.json")

    with TestClient(app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "Local Agent Console" in page.text
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]

        script = client.get("/assets/app.js")
        stylesheet = client.get("/assets/style.css")
        assert script.status_code == stylesheet.status_code == 200
        assert "textContent" in script.text
        assert "innerHTML" not in script.text

        response = client.get("/application/status", headers=_headers(credential.token.reveal(
            purpose="UI test authentication"
        )))
        assert response.status_code == 200
        assert response.json()["model_provider_configured"] is False
        assert response.json()["workspace"]["valid"] is False
        assert "does not exist" in response.json()["workspace"]["diagnostic"]
        assert "never-send-this-secret" not in response.text


def test_ui_task_submission_uses_authenticated_application_service(tmp_path) -> None:
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create(_scopes())
    token = credential.token.reveal(purpose="UI task test authentication")
    service = UiTaskService()
    app = create_api_app(service, credentials)

    with TestClient(app) as client:
        submitted = client.post(
            "/tasks",
            headers={**_headers(token), "Idempotency-Key": "ui-task-test-1"},
            json={"objective": "Create a task from the local dashboard test."},
        )
        assert submitted.status_code == 200
        task_id = submitted.json()["task"]["task_id"]
        assert task_id
        task = client.get(f"/tasks/{task_id}", headers=_headers(token))
        assert task.status_code == 200
        assert task.json()["task_id"] == task_id
        assert task.json()["objective"] == "Create a task from the local dashboard test."
        assert any(event == "api.task_submitted" for event, _ in service.audit_events)


def test_ui_approval_decisions_use_scopes_and_existing_service(tmp_path) -> None:
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    reader = credentials.create({ApiScope.APPROVAL_READ, ApiScope.APPROVAL_READ_ANY})
    operator = credentials.create(
        {
            ApiScope.APPROVAL_READ,
            ApiScope.APPROVAL_READ_ANY,
            ApiScope.APPROVAL_APPROVE,
            ApiScope.APPROVAL_APPROVE_ANY,
            ApiScope.APPROVAL_DENY,
            ApiScope.APPROVAL_DENY_ANY,
        }
    )
    service = UiApprovalService()
    app = create_api_app(service, credentials)

    with TestClient(app) as client:
        approval_url = "/approvals/approval-ui-test/approve"
        denied = client.post(
            approval_url,
            headers=_headers(reader.token.reveal(purpose="UI approval scope test")),
        )
        assert denied.status_code == 403
        assert service.approve_calls == 0

        operator_token = operator.token.reveal(purpose="UI approval decision test")
        approved = client.post(approval_url, headers=_headers(operator_token))
        assert approved.status_code == 200
        assert approved.json()["approval"]["status"] == "approved"
        assert service.approve_calls == 1


def test_schedule_occurrence_route_returns_persisted_approval_wait_state(tmp_path) -> None:
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create({ApiScope.SCHEDULE_READ, ApiScope.SCHEDULE_READ_ANY})
    service = UiScheduleService()
    app = create_api_app(service, credentials)

    with TestClient(app) as client:
        response = client.get(
            "/schedules/schedule-ui-test/occurrences",
            headers=_headers(credential.token.reveal(purpose="UI schedule occurrence test")),
        )
        assert response.status_code == 200
        occurrence = response.json()[0]
        assert occurrence["occurrence_id"] == "occurrence-ui-test"
        assert occurrence["status"] == "awaiting_approval"
        assert occurrence["scheduled_for"]


def test_ui_authorization_and_kill_switch_use_backend_scopes(tmp_path) -> None:
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    reader = credentials.create({ApiScope.APPLICATION_READ, ApiScope.SAFETY_READ})
    operator = credentials.create({ApiScope.SAFETY_CONTROL, ApiScope.APPLICATION_READ})
    app = create_default_app(tmp_path / "state.sqlite3", tmp_path / "credentials.json")

    with TestClient(app) as client:
        assert client.get("/application/status").status_code == 401
        assert client.get("/tasks", headers=_headers(reader.token.reveal(
            purpose="UI scope test"
        ))).status_code == 403
        reader_token = reader.token.reveal(purpose="UI safety read scope test")
        assert client.post(
            "/safety/kill-switch",
            headers=_headers(reader_token),
            json={"active": True},
        ).status_code == 403

        operator_token = operator.token.reveal(purpose="UI safety control test")
        response = client.post(
            "/safety/kill-switch",
            headers=_headers(operator_token),
            json={"active": True},
        )
        assert response.status_code == 200
        assert response.json() == {"active": True}
        status = client.get("/application/status", headers=_headers(operator_token))
        assert status.json()["kill_switch_active"] is True
        application = app.state.agent_application
        assert isinstance(application, AgentApplication)


def test_ui_application_startup_and_shutdown_releases_process_owner(tmp_path) -> None:
    database = tmp_path / "state.sqlite3"
    credentials_path = tmp_path / "credentials.json"
    app = create_default_app(database, credentials_path)
    application = app.state.agent_application
    assert isinstance(application, AgentApplication)
    assert application.diagnostics()["single_process_owner_held"] is True

    with TestClient(app) as client:
        assert client.get("/").status_code == 200
    assert application.state.value == "stopped"

    restarted = create_default_app(database, credentials_path)
    with TestClient(restarted) as client:
        assert client.get("/").status_code == 200


def test_bolt_ui_command_uses_loopback_api_lifecycle(monkeypatch) -> None:
    import agent_core.api_server

    observed: list[list[str]] = []
    monkeypatch.setattr(
        agent_core.api_server,
        "main",
        lambda arguments: observed.append(arguments) or 0,
    )
    result = run_cli(
        ["--database", "ui-state.sqlite3", "ui", "--port", "8877"],
        stdout=StringIO(),
        stderr=StringIO(),
    )
    assert result == 0
    assert observed == [[
        "--host",
        "127.0.0.1",
        "--port",
        "8877",
        "--start-scheduler",
        "--database",
        "ui-state.sqlite3",
    ]]


def test_invalid_ui_configuration_has_actionable_startup_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("BOLT_ALLOWED_ACTIONS", "not_a_real_action")
    with pytest.raises(SystemExit) as exit_error:
        api_server_main(
            ["--credential-store", str(tmp_path / "credentials.json"), "--port", "8878"]
        )
    assert exit_error.value.code == 2


def test_ui_port_conflict_reports_action_and_releases_application(tmp_path, monkeypatch, capsys) -> None:
    import agent_core.api_server

    app = create_default_app(tmp_path / "state.sqlite3", tmp_path / "credentials.json")
    monkeypatch.setattr(agent_core.api_server, "create_default_app", lambda *_args, **_kwargs: app)

    def fail_to_bind(_config) -> None:
        raise OSError("address already in use")

    monkeypatch.setattr(uvicorn.Config, "bind_socket", fail_to_bind)
    with pytest.raises(SystemExit) as exit_error:
        api_server_main(["--port", "8879"])
    assert exit_error.value.code == 1
    assert "port is already in use" in capsys.readouterr().err
    assert app.state.agent_application.state.value == "stopped"


def test_dashboard_renders_untrusted_task_text_without_html_execution(tmp_path) -> None:
    with sync_playwright() as playwright:
        if not Path(playwright.chromium.executable_path).is_file():
            pytest.skip("Chromium is not installed in this test environment")
        credentials_path = tmp_path / "credentials.json"
        credentials = ApiCredentialStore(credentials_path)
        credential = credentials.create({ApiScope.APPLICATION_READ, ApiScope.TASK_READ})
        task_id = uuid4()
        hostile_text = '<img src=x onerror="globalThis.boltXss=true">'
        credentials.claim_resource("task", str(task_id), credential.credential_id)
        app = create_default_app(tmp_path / "state.sqlite3", credentials_path)
        app.state.agent_application.store.save_task(
            TaskRecord(
                task_id=task_id,
                caller_id=CredentialCallerId(credential.credential_id),
                objective=hostile_text,
            )
        )
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, log_level="error")
        )
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()
        browser = None
        try:
            import urllib.request

            for _ in range(100):
                if not server_thread.is_alive():
                    raise AssertionError("dashboard server exited before becoming ready")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1):
                        break
                except OSError:
                    time.sleep(0.05)
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
            page.locator("#credential-button").click()
            page.locator("#api-token").fill(
                credential.token.reveal(purpose="dashboard XSS test")
            )
            page.locator("#connect-button").click()
            page.get_by_text("Application state", exact=True).wait_for(timeout=10000)
            page.locator('a[data-page="tasks"]').click()
            page.get_by_text("Task history", exact=True).wait_for()
            assert hostile_text in page.locator("main").inner_text()
            assert page.locator("main img").count() == 0
            assert page.evaluate("typeof globalThis.boltXss") == "undefined"
        finally:
            if browser is not None:
                browser.close()
            server.should_exit = True
            server_thread.join(timeout=20)
            assert not server_thread.is_alive(), "dashboard did not shut down gracefully"
            assert app.state.agent_application.state.value == "stopped"

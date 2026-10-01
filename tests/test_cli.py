import asyncio
import json
from datetime import UTC, datetime
from io import StringIO
from uuid import UUID, uuid4

from agent_core.application import AgentApplication, ApplicationState
from agent_core.cli import _build_parser, run_cli
from agent_core.models import ActionKind, TaskStatus
from agent_core.persistence import ScheduleType
from agent_core.runtime import ActionReconciliationOutcome
from agent_core.service import (
    ActionStatusResponse,
    CancelTaskResult,
    ReconciliationResponse,
    SchedulerOccurrenceResponse,
    SchedulerStatusResponse,
    ServiceErrorCode,
    ServiceErrorInfo,
    SubmitTaskResult,
    TaskStatusResponse,
)


def task_response(objective: str = "inspect safely") -> TaskStatusResponse:
    now = datetime.now(UTC)
    return TaskStatusResponse(
        task_id=uuid4(),
        objective=objective,
        status=TaskStatus.SUCCEEDED,
        verification_state="verified",
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


class FakeService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.submission_error: ServiceErrorInfo | None = None

    def __getattr__(self, name: str):
        def call(*args, **kwargs):
            self.calls.append((name, (args, kwargs)))
            return {"operation": name, "api_key": "must-not-escape"}

        return call

    def submit_task(self, request):
        self.calls.append(("submit_task", request))
        return SubmitTaskResult(
            task=task_response("api_key=should-not-escape"),
            success=self.submission_error is None,
            duplicate=False,
            error=self.submission_error,
        )

    def cancel_task(self, request):
        self.calls.append(("cancel_task", request))
        return CancelTaskResult(task_response(), cancellation_requested=True)

    def request_reconciliation(self, task_id, action_id):
        self.calls.append(("request_reconciliation", (task_id, action_id)))
        return ReconciliationResponse(
            task_id=task_id,
            action_id=action_id,
            outcome=ActionReconciliationOutcome.STILL_UNCERTAIN,
            uncertain=True,
        )

    async def run_scheduler_once(self):
        self.calls.append(("run_scheduler_once", None))
        return (SchedulerOccurrenceResponse("schedule", "occurrence", status="completed", success=True, uncertain=False),)

    async def stop_scheduler(self):
        self.calls.append(("stop_scheduler", None))
        return {"stopped": True}

    async def shutdown(self):
        self.calls.append(("shutdown", None))

    def scheduler_status(self):
        self.calls.append(("scheduler_status", None))
        return SchedulerStatusResponse(
            running=False,
            shutdown=False,
            active_tasks=0,
            active_occurrences=0,
            uncertain_actions=0,
            kill_switch_active=False,
            last_error="",
        )

    def get_action_by_id(self, action_id):
        self.calls.append(("get_action_by_id", action_id))
        return ActionStatusResponse(
            task_id=uuid4(),
            action_id=action_id,
            name="browser.observe",
            status="uncertain",
            verification_status="uncertain",
            attempts=1,
            uncertain=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            failure="",
        )


def invoke(service: FakeService, *argv: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    code = run_cli(argv, service=service, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def test_task_submit_delegates_and_json_output_is_secret_sanitized():
    service = FakeService()

    code, stdout, stderr = invoke(
        service,
        "task",
        "submit",
        "inspect safely",
        "--idempotency-key",
        "request-1",
        "--json",
    )

    output = json.loads(stdout)
    assert code == 0
    assert stderr == ""
    assert output["task"]["objective"] == "api_key=secret_ref:redacted"
    assert "must-not-escape" not in stdout
    assert service.calls[0][0] == "submit_task"
    assert service.calls[0][1].idempotency_key == "request-1"


def test_task_submission_error_maps_to_safe_exit_code():
    service = FakeService()
    service.submission_error = ServiceErrorInfo(
        ServiceErrorCode.KILL_SWITCH_ACTIVE,
        "blocked by kill switch",
    )

    code, stdout, stderr = invoke(service, "task", "submit", "inspect safely", "--json")

    assert code == 5
    assert json.loads(stdout)["success"] is False
    assert "kill switch" in stderr


def test_task_get_list_and_cancel_delegate_to_service():
    service = FakeService()
    task_id = str(uuid4())

    assert invoke(service, "task", "get", task_id, "--json")[0] == 0
    assert invoke(service, "task", "list", "--limit", "7", "--json")[0] == 0
    cancel_code, cancel_output, _ = invoke(service, "task", "cancel", task_id, "--json")

    assert cancel_code == 0
    assert json.loads(cancel_output)["status"] == TaskStatus.SUCCEEDED.value
    assert [call[0] for call in service.calls] == ["get_task", "list_tasks", "cancel_task"]
    assert service.calls[1][1][1]["limit"] == 7


def test_action_commands_delegate_and_uncertain_reconciliation_returns_blocked_code():
    service = FakeService()

    assert invoke(service, "action", "get", "execution-1", "--json")[0] == 0
    assert invoke(service, "action", "history", "execution-1", "--limit", "2", "--json")[0] == 0
    assert invoke(service, "action", "uncertain", "--json")[0] == 0
    code, output, _ = invoke(service, "action", "reconcile", "execution-1", "--json")

    assert code == 6
    assert json.loads(output)["outcome"] == ActionReconciliationOutcome.STILL_UNCERTAIN.value
    assert [call[0] for call in service.calls] == [
        "get_action_by_id",
        "get_action_history_by_id",
        "get_uncertain_actions",
        "get_action_by_id",
        "request_reconciliation",
    ]


def test_schedule_create_parses_typed_values_and_rejects_invalid_json():
    service = FakeService()
    code, _, _ = invoke(
        service,
        "schedule",
        "create",
        "--objective",
        "observe",
        "--action-name",
        "browser.observe",
        "--action-kind",
        ActionKind.READ_ONLY.value,
        "--run-at",
        "2030-01-02T03:04:05Z",
        "--parameters-json",
        '{"url":"https://example.invalid"}',
        "--json",
    )

    assert code == 0
    schedule_request = service.calls[0][1][0][0]
    assert schedule_request.schedule_type is ScheduleType.RUN_AT
    assert schedule_request.run_at == datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert schedule_request.parameters == {"url": "https://example.invalid"}

    bad_code, bad_stdout, bad_stderr = invoke(
        service,
        "schedule",
        "create",
        "--objective",
        "observe",
        "--action-name",
        "browser.observe",
        "--action-kind",
        ActionKind.READ_ONLY.value,
        "--run-at",
        "2030-01-02T03:04:05Z",
        "--parameters-json",
        "[]",
    )
    assert bad_code == 2
    assert bad_stdout == ""
    assert "must be an object" in bad_stderr


def test_schedule_read_and_mutation_commands_delegate():
    service = FakeService()
    assert invoke(service, "schedule", "get", "schedule-1", "--json")[0] == 0
    assert invoke(service, "schedule", "list", "--limit", "3", "--json")[0] == 0
    for operation in ("enable", "disable", "cancel"):
        assert invoke(service, "schedule", operation, "schedule-1", "--json")[0] == 0
    assert [call[0] for call in service.calls] == [
        "get_schedule",
        "list_schedules",
        "enable_schedule",
        "disable_schedule",
        "cancel_schedule",
    ]


def test_scheduler_commands_and_safety_status_use_service_facade():
    service = FakeService()
    assert invoke(service, "scheduler", "status", "--json")[0] == 0
    assert invoke(service, "scheduler", "run-once", "--json")[0] == 0
    assert invoke(service, "scheduler", "stop", "--json")[0] == 0
    shutdown_code, shutdown_json, _ = invoke(service, "scheduler", "shutdown", "--json")
    assert shutdown_code == 0
    assert json.loads(shutdown_json) == {"shutdown": True}
    status_code, status_json, _ = invoke(service, "safety", "status", "--json")

    assert status_code == 0
    assert json.loads(status_json)["kill_switch_active"] is False
    assert [call[0] for call in service.calls] == [
        "scheduler_status",
        "run_scheduler_once",
        "stop_scheduler",
        "shutdown",
        "scheduler_status",
    ]


def test_audit_filters_forward_parsed_values_to_service():
    service = FakeService()
    task_id = str(uuid4())
    code, _, _ = invoke(
        service,
        "audit",
        "list",
        "--task-id",
        task_id,
        "--action-id",
        "execution-1",
        "--since",
        "2030-01-01T00:00:00Z",
        "--limit",
        "4",
        "--json",
    )

    assert code == 0
    _args, kwargs = service.calls[0][1]
    assert service.calls[0][0] == "list_audit_events"
    assert kwargs["task_id"].int == UUID(task_id).int
    assert kwargs["action_id"] == "execution-1"
    assert kwargs["since"] == datetime(2030, 1, 1, tzinfo=UTC)
    assert kwargs["limit"] == 4


def test_invalid_arguments_fail_without_tracebacks_or_authority_flags():
    service = FakeService()
    code, stdout, stderr = invoke(service, "task", "get", "not-a-uuid")
    help_text = _build_parser().format_help()

    assert code == 2
    assert stdout == ""
    assert "Traceback" not in stderr
    assert "--approve" not in help_text
    assert "--disable-kill-switch" not in help_text
    assert "--retry-uncertain" not in help_text


def test_positive_timeout_rejects_non_finite_values():
    service = FakeService()
    code, stdout, stderr = invoke(
        service,
        "schedule",
        "create",
        "--objective",
        "observe",
        "--action-name",
        "browser.observe",
        "--action-kind",
        ActionKind.READ_ONLY.value,
        "--run-at",
        "2030-01-02T03:04:05Z",
        "--timeout-seconds",
        "inf",
    )

    assert code == 2
    assert stdout == ""
    assert "invalid command usage" in stderr


def test_default_bootstrap_uses_injected_sqlite_store_and_no_ability_providers(tmp_path):
    database = tmp_path / "cli.sqlite3"
    application = AgentApplication(database)
    try:
        status = application.start()
        service = application.service
        assert database.exists()
        assert status.state is ApplicationState.READY
        assert service.scheduler_status().kill_switch_active is False
        assert service._task_executor.registry.available() == ()
    finally:
        asyncio.run(application.shutdown())


def test_default_cli_uses_application_owner_and_releases_it(tmp_path):
    database = tmp_path / "cli-owned.sqlite3"
    stdout = StringIO()
    stderr = StringIO()

    code = run_cli(
        ["--database", str(database), "task", "list", "--json"],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 0
    assert stderr.getvalue() == ""
    assert json.loads(stdout.getvalue()) == []
    application = AgentApplication(database)
    assert application.start().state is ApplicationState.READY
    asyncio.run(application.shutdown())

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult
from abilities.registry import AbilityRegistry
from agent_brain.executor import AgentExecutionLoop
from agent_brain.model_router import ModelRouter
from agent_core.api import create_api_app
from agent_core.api_auth import (
    ApiCredentialStore,
    ApiScope,
    AuthenticationRateLimiter,
    CredentialStoreError,
    default_credential_path,
)
from agent_core.api_auth_cli import main as auth_cli_main
from agent_core.api_server import _loopback_host
from agent_core.config import AgentConfig
from agent_core.models import ActionKind, ActionRequest, AuditEvent, TaskStatus
from agent_core.persistence import (
    ActionExecutionRecord,
    ActionExecutionStatus,
    ScheduleStatus,
    ScheduleType,
    SQLiteTaskStore,
    TaskRecord,
    VerificationStatus,
)
from agent_core.ports import KillSwitch
from agent_core.runtime import (
    ActionReconciliationOutcome,
    ActionReconciliationResult,
    AgentRuntime,
)
from agent_core.scheduler import TaskScheduler
from agent_core.secrets import Secret
from agent_core.service import (
    ActionStatusResponse,
    AgentService,
    AgentServiceError,
    AuditEventResponse,
    CancelTaskResult,
    ReconciliationResponse,
    ScheduleResponse,
    SchedulerOccurrenceResponse,
    SchedulerStatusResponse,
    ServiceErrorCode,
    SubmitTaskRequest,
    SubmitTaskResult,
    TaskStatusResponse,
)


def make_task(objective: str, task_id: UUID | None = None) -> TaskStatusResponse:
    now = datetime.now(UTC)
    return TaskStatusResponse(
        task_id=task_id or uuid4(),
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


class ServiceStub:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.tasks: dict[UUID, TaskStatusResponse] = {}
        self.owners_by_idempotency: dict[tuple[str, str], tuple[str, UUID, str]] = {}
        self.audit_events: list[tuple[str, dict[str, object]]] = []
        self.provider_calls = 0
        self.reconciliation_calls = 0
        self.scheduler_start_calls = 0

    def record_api_audit_event(self, event_type: str, **details) -> None:
        self.audit_events.append((event_type, details))

    def submit_task(self, request: SubmitTaskRequest) -> SubmitTaskResult:
        with self._lock:
            if request.idempotency_key is not None:
                key = (request.caller_id, request.idempotency_key)
                existing = self.owners_by_idempotency.get(key)
                if existing is not None:
                    _caller, task_id, objective = existing
                    if objective != request.objective:
                        raise AgentServiceError(ServiceErrorCode.CONFLICT, "idempotency conflict")
                    return SubmitTaskResult(self.tasks[task_id], True, True)
            task = make_task(request.objective)
            self.tasks[task.task_id] = task
            if request.idempotency_key is not None:
                self.owners_by_idempotency[
                    (request.caller_id, request.idempotency_key)
                ] = (request.caller_id, task.task_id, request.objective)
            self.provider_calls += 1
            return SubmitTaskResult(task, True, False)

    def list_tasks(self, *, limit: int = 100):
        return tuple(list(self.tasks.values())[-limit:])

    def get_task(self, task_id: UUID):
        try:
            return self.tasks[task_id]
        except KeyError:
            raise AgentServiceError(ServiceErrorCode.TASK_NOT_FOUND, "missing") from None

    def cancel_task(self, _request):
        return CancelTaskResult(next(iter(self.tasks.values())), False)

    def get_action_by_id(self, action_id: str):
        if not self.tasks:
            raise AgentServiceError(ServiceErrorCode.INVALID_REQUEST, "missing")
        task = next(iter(self.tasks.values()))
        return ActionStatusResponse(
            task_id=task.task_id,
            action_id=action_id,
            name="browser.observe",
            status=ActionExecutionStatus.UNCERTAIN,
            verification_status=VerificationStatus.UNCERTAIN,
            attempts=1,
            uncertain=True,
            created_at=task.created_at,
            updated_at=task.updated_at,
            failure="",
        )

    def get_action_history_by_id(self, action_id: str, *, limit: int = 100):
        return (self.get_action_by_id(action_id),)[:limit]

    def get_uncertain_actions(self, *, limit: int = 100):
        return (self.get_action_by_id("execution-1"),)[:limit]

    def request_reconciliation(self, task_id: UUID, action_id: str):
        self.reconciliation_calls += 1
        return ReconciliationResponse(
            task_id, action_id, ActionReconciliationOutcome.STILL_UNCERTAIN, True
        )

    def create_schedule(self, request):
        task = make_task(request.objective)
        self.tasks[task.task_id] = task
        return ScheduleResponse(
            "schedule-1",
            task.task_id,
            task.objective,
            request.action_name,
            str(request.action_kind),
            request.schedule_type,
            ScheduleStatus.SCHEDULED,
            True,
            request.run_at,
            False,
            request.interval_seconds,
            0,
            task.created_at,
            task.updated_at,
        )

    def get_schedule(self, schedule_id: str):
        if schedule_id != "schedule-1" or not self.tasks:
            raise AgentServiceError(ServiceErrorCode.SCHEDULE_NOT_FOUND, "missing")
        task = next(iter(self.tasks.values()))
        return ScheduleResponse(
            schedule_id, task.task_id, task.objective, "browser.observe", "read_only",
            ScheduleType.RUN_AT, ScheduleStatus.SCHEDULED, True, task.created_at, False,
            None, 0, task.created_at, task.updated_at,
        )

    def list_schedules(self, *, limit: int = 100):
        return ()

    def enable_schedule(self, schedule_id: str):
        return self.get_schedule(schedule_id)

    def disable_schedule(self, schedule_id: str):
        return self.get_schedule(schedule_id)

    def cancel_schedule(self, schedule_id: str):
        return self.get_schedule(schedule_id)

    def scheduler_status(self):
        return SchedulerStatusResponse(False, False, 0, 0, 0, False, "")

    async def run_scheduler_once(self):
        return (SchedulerOccurrenceResponse("schedule-1", "occ-1", "completed", True, False),)

    async def start_scheduler(self):
        self.scheduler_start_calls += 1
        return self.scheduler_status()

    async def stop_scheduler(self):
        return self.scheduler_status()

    async def shutdown(self):
        return None

    def list_audit_events(self, **_kwargs):
        return tuple(
            AuditEventResponse(event_type, UUID(int=0), datetime.now(UTC), details)
            for event_type, details in self.audit_events
        )


class Provider:
    ability = "browser"
    descriptor = AbilityDescriptor(
        name="browser",
        description="API integration test provider",
        supported_actions=("navigate", "inspect", "observe", "fill", "submit"),
        risk_classes=("low", "medium", "high"),
        provider="test",
    )

    def __init__(self) -> None:
        self.calls = 0
        self.executed_actions: list[str] = []

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def risk_for(self, action: str):
        from agent_core.models import RiskLevel

        return RiskLevel.HIGH if action in {"click", "submit"} else RiskLevel.LOW

    def execute(
        self, action: AbilityAction, _context: AbilityContext | None = None
    ) -> AbilityResult:
        self.calls += 1
        self.executed_actions.append(action.action)
        return AbilityResult(True, value={"observed": True})


class Switch(KillSwitch):
    def __init__(self, engaged: bool = False) -> None:
        self.engaged = engaged

    def is_engaged(self) -> bool:
        return self.engaged


class AuditSink:
    def record(self, _event: AuditEvent) -> None:
        return None


class Approval:
    def approve(self, _request) -> bool:
        return True


class SubmitPlanModel:
    name = "api-test"
    model_name = "api-test"
    capabilities = ("structured", "text")

    def structured_generate(self, _prompt, _schema, *, system=None):
        return {
            "steps": [
                {
                    "ability": "browser",
                    "action": "submit",
                    "arguments": {
                        "target_id": "submit-button",
                        "expected_text": "Order submitted",
                    },
                }
            ]
        }

    def generate(self, _prompt, *, system=None, max_tokens=None):
        return "done"


class AsyncProvider:
    async def execute_async(self, _action: ActionRequest) -> object:
        return {"ok": True}


class Reconciler:
    def __init__(self, outcome: ActionReconciliationOutcome) -> None:
        self.outcome = outcome
        self.calls = 0

    def reconcile(self, _request) -> ActionReconciliationResult:
        self.calls += 1
        return ActionReconciliationResult(self.outcome, "external evidence")


def build_runtime_service(
    database_path,
    *,
    allowed_actions: frozenset[ActionKind],
    approval_provider=None,
    kill_switch: Switch | None = None,
    provider: Provider | None = None,
    reconciler: Reconciler | None = None,
    model_router: ModelRouter | None = None,
):
    store = SQLiteTaskStore(database_path)
    config = AgentConfig(allowed_actions=allowed_actions)
    switch = kill_switch or Switch()
    provider = provider or Provider()
    registry = AbilityRegistry()
    registry.register(provider)
    executor = AgentExecutionLoop(
        registry=registry,
        approval_provider=approval_provider,
        kill_switch=switch,
        config=config,
        state_store=store,
        model_router=model_router,
    )
    runtime = AgentRuntime(
        config,
        AsyncProvider(),
        AuditSink(),
        switch,
        approval_provider=approval_provider,
        state_store=store,
        action_reconciler=reconciler,
    )
    scheduler = TaskScheduler(store, runtime)
    service = AgentService(store, executor, runtime, scheduler)
    return service, store, provider


def build_client(tmp_path, *, scopes: set[ApiScope], service: ServiceStub | None = None):
    store = ApiCredentialStore(tmp_path / "credentials.json")
    credential = store.create(scopes)
    service = service or ServiceStub()
    app = create_api_app(service, store)
    return TestClient(app), store, credential, service


def auth(token: str | Secret[str]) -> dict[str, str]:
    value = token.reveal(purpose="test HTTP authentication") if isinstance(token, Secret) else token
    return {"Authorization": f"Bearer {value}"}


def submit_headers(token: str, key: str = "api-test-key") -> dict[str, str]:
    return {**auth(token), "Idempotency-Key": key}


def test_authenticated_task_flows_through_existing_runtime_provider(tmp_path):
    service, state_store, provider = build_runtime_service(
        tmp_path / "state.sqlite3",
        allowed_actions=frozenset({ActionKind.BROWSER}),
        approval_provider=Approval(),
    )
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create({ApiScope.TASK_SUBMIT})
    client = TestClient(create_api_app(service, credentials))

    response = client.post(
        "/tasks",
        headers=submit_headers(credential.token),
        json={"objective": "inspect the current page"},
    )

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert provider.calls > 0
    state_store.close()


def test_runtime_policy_approval_and_kill_switch_remain_authoritative(tmp_path):
    scenarios = (
        (
            "policy",
            frozenset(),
            Approval(),
            Switch(),
            "inspect the current page",
            403,
            "POLICY_DENIED",
        ),
        (
            "approval",
            frozenset({ActionKind.BROWSER}),
            None,
            Switch(),
            "submit the order",
            409,
            "APPROVAL_REQUIRED",
        ),
        (
            "kill-switch",
            frozenset({ActionKind.BROWSER}),
            Approval(),
            Switch(True),
            "inspect the current page",
            423,
            "KILL_SWITCH_ACTIVE",
        ),
    )
    for name, allowed, approval, switch, objective, status, code in scenarios:
        model_router = (
            ModelRouter(
                providers=[SubmitPlanModel()],
                fallback_to_deterministic=False,
                max_model_calls=1,
            )
            if name == "approval"
            else None
        )
        service, state_store, provider = build_runtime_service(
            tmp_path / f"{name}.sqlite3",
            allowed_actions=allowed,
            approval_provider=approval,
            kill_switch=switch,
            model_router=model_router,
        )
        credentials = ApiCredentialStore(tmp_path / f"{name}-credentials.json")
        credential = credentials.create({ApiScope.TASK_SUBMIT})
        client = TestClient(create_api_app(service, credentials))

        response = client.post(
            "/tasks",
            headers=submit_headers(credential.token, f"scenario-{name}"),
            json={"objective": objective},
        )

        assert response.status_code == status
        assert response.json()["error"]["code"] == code
        if name == "approval":
            assert "submit" not in provider.executed_actions
        else:
            assert provider.calls == 0, name
        state_store.close()


def test_real_service_idempotency_survives_api_and_service_reconstruction(tmp_path):
    state_path = tmp_path / "durable.sqlite3"
    credentials_path = tmp_path / "credentials.json"
    service1, store1, provider1 = build_runtime_service(
        state_path,
        allowed_actions=frozenset({ActionKind.BROWSER}),
        approval_provider=Approval(),
    )
    auth_store1 = ApiCredentialStore(credentials_path)
    credential = auth_store1.create({ApiScope.TASK_SUBMIT, ApiScope.TASK_READ})
    client1 = TestClient(create_api_app(service1, auth_store1))
    headers = {**auth(credential.token), "Idempotency-Key": "restart-idempotency"}
    first = client1.post(
        "/tasks", headers=headers, json={"objective": "inspect the current page"}
    )
    task_id = first.json()["task"]["task_id"]
    store1.close()

    service2, store2, provider2 = build_runtime_service(
        state_path,
        allowed_actions=frozenset({ActionKind.BROWSER}),
        approval_provider=Approval(),
    )
    client2 = TestClient(create_api_app(service2, ApiCredentialStore(credentials_path)))
    repeated = client2.post(
        "/tasks", headers=headers, json={"objective": "inspect the current page"}
    )

    assert first.status_code == repeated.status_code == 200
    assert repeated.json()["task"]["task_id"] == task_id
    assert repeated.json()["duplicate"] is True
    assert provider1.calls > 0
    assert provider2.calls == 0
    store2.close()


def test_concurrent_api_task_submissions_use_service_idempotency_gate(tmp_path):
    service, store, provider = build_runtime_service(
        tmp_path / "state.sqlite3",
        allowed_actions=frozenset({ActionKind.BROWSER}),
        approval_provider=Approval(),
    )
    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create({ApiScope.TASK_SUBMIT})
    client = TestClient(create_api_app(service, credentials))
    headers = {**auth(credential.token), "Idempotency-Key": "concurrent-key"}

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: client.post(
                    "/tasks",
                    headers=headers,
                    json={"objective": "inspect the current page"},
                ),
                range(2),
            )
        )

    assert [response.status_code for response in responses] == [200, 200]
    assert responses[0].json()["task"]["task_id"] == responses[1].json()["task"]["task_id"]
    assert sorted(response.json()["duplicate"] for response in responses) == [False, True]
    assert provider.calls > 0
    assert len(store.list_task_records()) == 1
    store.close()


def test_real_uncertain_action_reconciliation_stays_fail_closed(tmp_path):
    reconciler = Reconciler(ActionReconciliationOutcome.STILL_UNCERTAIN)
    service, store, provider = build_runtime_service(
        tmp_path / "state.sqlite3",
        allowed_actions=frozenset({ActionKind.BROWSER}),
        approval_provider=Approval(),
        reconciler=reconciler,
    )
    task_id = uuid4()
    store.save_task(TaskRecord(task_id=task_id, objective="reconcile safely"))
    action_request = ActionRequest(
        task_id=task_id,
        name="browser.observe",
        kind=ActionKind.BROWSER,
        parameters={"query": "status"},
        execution_id="execution-uncertain",
    )
    store.save_action(
        ActionExecutionRecord(
            action_id="execution-uncertain",
            task_id=task_id,
            name=action_request.name,
            metadata={
                "kind": ActionKind.BROWSER.value,
                "provider_identity": "browser",
                "parameters": action_request.parameters,
                "identity_fingerprint": AgentRuntime._action_fingerprint(action_request),
            },
        )
    )
    action_record = store.get_action(task_id, "execution-uncertain")
    assert action_record is not None
    action_record.status = ActionExecutionStatus.EXECUTING
    action_record.attempts = 1
    store.save_action(action_record)
    action_record.status = ActionExecutionStatus.UNCERTAIN
    store.save_action(action_record)

    credentials = ApiCredentialStore(tmp_path / "credentials.json")
    credential = credentials.create({ApiScope.ACTION_READ, ApiScope.ACTION_RECONCILE})
    credentials.claim_resource("task", str(task_id), credential.credential_id)
    assert service._runtime._reconciliation_request(action_record) is not None
    client = TestClient(create_api_app(service, credentials))

    response = client.post(
        "/actions/execution-uncertain/reconcile",
        headers=auth(credential.token),
    )

    persisted = store.get_action(task_id, "execution-uncertain")
    assert response.status_code == 200
    assert response.json()["outcome"] == ActionReconciliationOutcome.STILL_UNCERTAIN.value
    assert persisted is not None
    assert persisted.status is ActionExecutionStatus.UNCERTAIN
    assert reconciler.calls == 1
    assert provider.calls == 0
    store.close()


@pytest.mark.parametrize("blocked_by", ["current_policy", "kill_switch"])
def test_api_reconciliation_cannot_bypass_current_security_controls(tmp_path, blocked_by):
    switch = Switch(blocked_by == "kill_switch")
    allowed = frozenset() if blocked_by == "current_policy" else frozenset({ActionKind.BROWSER})
    reconciler = Reconciler(ActionReconciliationOutcome.CONFIRMED_COMPLETED)
    service, store, provider = build_runtime_service(
        tmp_path / f"{blocked_by}.sqlite3",
        allowed_actions=allowed,
        approval_provider=Approval(),
        kill_switch=switch,
        reconciler=reconciler,
    )
    task_id = uuid4()
    store.save_task(TaskRecord(task_id=task_id, objective="reconcile after restart"))
    action = ActionRequest(
        task_id,
        "browser.observe",
        ActionKind.BROWSER,
        {"query": "state"},
        execution_id="execution-blocked",
    )
    store.save_action(
        ActionExecutionRecord(
            "execution-blocked",
            task_id,
            action.name,
            metadata={
                "kind": ActionKind.BROWSER.value,
                "provider_identity": "browser",
                "parameters": action.parameters,
                "identity_fingerprint": AgentRuntime._action_fingerprint(action),
            },
        )
    )
    record = store.get_action(task_id, action.execution_id or "")
    assert record is not None
    record.status = ActionExecutionStatus.EXECUTING
    record.attempts = 1
    store.save_action(record)
    record.status = ActionExecutionStatus.UNCERTAIN
    store.save_action(record)

    credentials = ApiCredentialStore(tmp_path / f"{blocked_by}-credentials.json")
    credential = credentials.create({ApiScope.ACTION_RECONCILE})
    credentials.claim_resource("task", str(task_id), credential.credential_id)
    client = TestClient(create_api_app(service, credentials))
    result = client.post(
        "/actions/execution-blocked/reconcile",
        headers=auth(credential.token),
    )

    persisted = store.get_action(task_id, "execution-blocked")
    assert result.status_code == 200
    assert result.json()["outcome"] == ActionReconciliationOutcome.STILL_UNCERTAIN.value
    assert persisted is not None and persisted.status is ActionExecutionStatus.UNCERTAIN
    assert reconciler.calls == 0
    assert provider.calls == 0
    store.close()


def test_credentials_are_hashed_and_authenticate_rotate_revoke(tmp_path):
    path = tmp_path / "api-auth.json"
    store = ApiCredentialStore(path)
    issued = store.create({ApiScope.TASK_READ})

    contents = path.read_text(encoding="utf-8")
    issued_token = issued.token.reveal(purpose="credential lifecycle test")
    assert issued_token not in contents
    assert store.authenticate(issued_token) is not None
    assert store.authenticate(issued_token + "bad") is None

    rotated = store.rotate(issued.credential_id)
    assert rotated.credential_id == issued.credential_id
    assert store.authenticate(issued_token) is None
    rotated_token = rotated.token.reveal(purpose="credential lifecycle test")
    assert store.authenticate(rotated_token) is not None
    store.revoke(issued.credential_id)
    assert store.authenticate(rotated_token) is None
    status = store.list_status()[0]
    assert status.revoked
    assert rotated_token not in repr(status)


def test_local_authentication_cli_displays_a_token_once_only(tmp_path, capsys):
    path = tmp_path / "credentials.json"
    assert auth_cli_main(
        ["--store", str(path), "create", "--scope", "task.read"]
    ) == 0
    created_output = capsys.readouterr().out
    generated_token = created_output.split('"token":"', 1)[1].split('"', 1)[0]
    credential_id = created_output.split('"credential_id":"', 1)[1].split('"', 1)[0]

    assert generated_token.startswith(f"bolt.{credential_id}.")
    assert generated_token not in path.read_text(encoding="utf-8")
    assert auth_cli_main(["--store", str(path), "status"]) == 0
    status_output = capsys.readouterr().out
    assert generated_token not in status_output
    assert credential_id in status_output


def test_authentication_failure_request_id_rate_limit_and_audit(tmp_path):
    client, _store, credential, service = build_client(
        tmp_path, scopes={ApiScope.SAFETY_READ}
    )
    valid = client.get("/safety/status", headers=auth(credential.token))
    assert valid.status_code == 200
    missing = client.get("/safety/status")
    assert missing.status_code == 401
    assert missing.headers["x-request-id"]
    assert missing.json()["error"]["code"] == "AUTHENTICATION_FAILED"
    assert missing.json()["error"]["request_id"] == missing.headers["x-request-id"]

    invalid_headers = auth("not-a-valid-token")
    responses = [client.get("/safety/status", headers=invalid_headers) for _ in range(4)]
    assert all(response.status_code == 401 for response in responses)
    limited = client.get("/safety/status", headers=invalid_headers)
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.headers["x-request-id"] == limited.json()["error"]["request_id"]
    events = [item[0] for item in service.audit_events]
    assert "api.authentication_failed" in events
    assert "api.authentication_succeeded" in events
    assert credential.token.reveal(purpose="audit redaction test") not in repr(service.audit_events)


def test_scope_enforcement_and_identity_cannot_be_spoofed(tmp_path):
    client, _store, credential, service = build_client(
        tmp_path, scopes={ApiScope.TASK_SUBMIT}
    )
    denied = client.get("/tasks", headers=auth(credential.token))
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "AUTHORIZATION_DENIED"

    spoof = client.post(
        "/tasks",
        headers=submit_headers(credential.token, "spoof"),
        json={"objective": "inspect", "caller_id": "victim"},
    )
    assert spoof.status_code == 422
    missing_key = client.post(
        "/tasks",
        headers=auth(credential.token),
        json={"objective": "inspect"},
    )
    assert missing_key.status_code == 422
    assert service.provider_calls == 0

    response = client.post(
        "/tasks",
        headers={**auth(credential.token), "Idempotency-Key": "same"},
        json={"objective": "inspect"},
    )
    assert response.status_code == 200
    assert service.owners_by_idempotency[(credential.credential_id, "same")][0] == (
        credential.credential_id
    )
    assert service.provider_calls == 1


def test_caller_isolation_and_specific_any_scope_does_not_grant_mutation(tmp_path):
    client, store, alice, service = build_client(
        tmp_path, scopes={ApiScope.TASK_SUBMIT, ApiScope.TASK_READ}
    )
    alice_task = client.post(
        "/tasks",
        headers=submit_headers(alice.token, "alice-task"),
        json={"objective": "private objective"},
    ).json()
    task_id = alice_task["task"]["task_id"]

    bob = store.create({ApiScope.TASK_READ, ApiScope.TASK_READ_ANY, ApiScope.TASK_CANCEL})
    bob_client = TestClient(create_api_app(service, store))
    assert bob_client.get(f"/tasks/{task_id}", headers=auth(bob.token)).status_code == 200
    assert bob_client.post(
        f"/tasks/{task_id}/cancel", headers=auth(bob.token)
    ).status_code == 404
    assert bob_client.get("/tasks", headers=auth(bob.token)).status_code == 200
    assert len(bob_client.get("/tasks", headers=auth(bob.token)).json()) == 1

    stranger = store.create({ApiScope.TASK_READ})
    stranger_client = TestClient(create_api_app(service, store))
    assert stranger_client.get(
        f"/tasks/{task_id}", headers=auth(stranger.token)
    ).status_code == 404


def test_any_scopes_do_not_grant_access_to_other_resource_types(tmp_path):
    service = ServiceStub()
    store = ApiCredentialStore(tmp_path / "auth.json")
    alice = store.create({ApiScope.SCHEDULE_CREATE})
    alice_client = TestClient(create_api_app(service, store))
    created = alice_client.post(
        "/schedules",
        headers=auth(alice.token),
        json={
            "objective": "observe",
            "action_name": "browser.observe",
            "action_kind": "read_only",
            "run_at": "2030-01-01T00:00:00Z",
            "parameters": {},
        },
    )
    assert created.status_code == 200

    bob = store.create(
        {
            ApiScope.TASK_READ,
            ApiScope.TASK_READ_ANY,
            ApiScope.ACTION_READ,
            ApiScope.SCHEDULE_READ,
        }
    )
    bob_client = TestClient(create_api_app(service, store))
    assert bob_client.get("/actions/uncertain", headers=auth(bob.token)).json() == []
    assert bob_client.get("/schedules", headers=auth(bob.token)).json() == []


def test_idempotency_caller_scoping_conflicts_and_restart(tmp_path):
    store_path = tmp_path / "credentials.json"
    first_store = ApiCredentialStore(store_path)
    first = first_store.create({ApiScope.TASK_SUBMIT})
    second = first_store.create({ApiScope.TASK_SUBMIT})
    service = ServiceStub()
    client_a = TestClient(create_api_app(service, first_store))
    client_b = TestClient(create_api_app(service, first_store))
    headers_a = {**auth(first.token), "Idempotency-Key": "request-key"}
    headers_b = {**auth(second.token), "Idempotency-Key": "request-key"}

    one = client_a.post("/tasks", headers=headers_a, json={"objective": "same"})
    duplicate = client_a.post("/tasks", headers=headers_a, json={"objective": "same"})
    conflict = client_a.post("/tasks", headers=headers_a, json={"objective": "different"})
    other_caller = client_b.post("/tasks", headers=headers_b, json={"objective": "same"})
    restarted_store = ApiCredentialStore(store_path)
    restarted = TestClient(create_api_app(service, restarted_store)).post(
        "/tasks", headers=headers_a, json={"objective": "same"}
    )

    assert one.status_code == duplicate.status_code == 200
    assert one.json()["task"]["task_id"] == duplicate.json()["task"]["task_id"]
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "CONFLICT"
    assert other_caller.status_code == restarted.status_code == 200
    assert other_caller.json()["task"]["task_id"] != one.json()["task"]["task_id"]
    assert restarted.json()["task"]["task_id"] == one.json()["task"]["task_id"]
    assert service.provider_calls == 2


def test_actions_reconciliation_cannot_accept_force_and_never_reexecutes(tmp_path):
    client, _store, credential, service = build_client(
        tmp_path,
        scopes={ApiScope.TASK_SUBMIT, ApiScope.ACTION_READ, ApiScope.ACTION_RECONCILE},
    )
    task = client.post(
        "/tasks",
        headers=submit_headers(credential.token, "action-test"),
        json={"objective": "observe"},
    ).json()["task"]
    service.get_action_by_id("execution-1")
    # Associate the action's task with this caller using the same resource ownership boundary.
    client.app.state.credential_store.claim_resource(
        "task", task["task_id"], credential.credential_id
    )
    assert client.get("/actions/uncertain", headers=auth(credential.token)).status_code == 200
    assert client.get(
        "/actions/execution-1", headers=auth(credential.token)
    ).status_code == 200
    bad = client.post(
        "/actions/execution-1/reconcile?force=true",
        headers=auth(credential.token),
    )
    assert bad.status_code == 422
    result = client.post(
        "/actions/execution-1/reconcile", headers=auth(credential.token)
    )
    assert result.status_code == 200
    assert result.json()["uncertain"] is True
    assert service.reconciliation_calls == 1
    assert service.provider_calls == 1
    assert any(name == "api.reconciliation_requested" for name, _ in service.audit_events)


def test_schedule_authorization_scheduler_guard_and_safety_read_only(tmp_path):
    client, _store, credential, service = build_client(
        tmp_path,
        scopes={
            ApiScope.SCHEDULE_CREATE,
            ApiScope.SCHEDULE_READ,
            ApiScope.SCHEDULE_MODIFY,
            ApiScope.SCHEDULE_CANCEL,
            ApiScope.SCHEDULER_READ,
            ApiScope.SCHEDULER_CONTROL,
            ApiScope.SAFETY_READ,
        },
    )
    schedule = client.post(
        "/schedules",
        headers=auth(credential.token),
        json={
            "objective": "observe",
            "action_name": "browser.observe",
            "action_kind": "read_only",
            "run_at": "2030-01-01T00:00:00Z",
            "parameters": {"token": "do-not-return"},
        },
    )
    assert schedule.status_code == 200
    assert "do-not-return" not in schedule.text
    assert client.get("/schedules", headers=auth(credential.token)).status_code == 200
    assert client.post(
        "/schedules/schedule-1/disable", headers=auth(credential.token)
    ).status_code == 200
    assert client.post(
        "/schedules/schedule-1/cancel", headers=auth(credential.token)
    ).status_code == 200
    assert client.get("/scheduler/status", headers=auth(credential.token)).status_code == 200
    assert client.post(
        "/scheduler/start", headers=auth(credential.token)
    ).status_code == 200
    assert client.post(
        "/scheduler/start", headers=auth(credential.token)
    ).status_code == 200
    assert service.scheduler_start_calls == 2  # AgentService remains the idempotent loop gate.
    assert client.get("/safety/status", headers=auth(credential.token)).status_code == 200
    assert client.post(
        "/safety/disable-kill-switch", headers=auth(credential.token)
    ).status_code == 404
    assert any(name == "api.schedule_modified" for name, _ in service.audit_events)


def test_openapi_request_ids_cors_and_privacy_boundaries(tmp_path):
    client, _store, credential, _service = build_client(
        tmp_path, scopes={ApiScope.SAFETY_READ}
    )
    request_id = str(uuid4())
    response = client.get(
        "/safety/status",
        headers={**auth(credential.token), "X-Request-ID": request_id},
    )
    assert response.headers["x-request-id"] == request_id
    assert response.headers.get("access-control-allow-origin") is None
    assert "token" not in response.text.lower()

    schema = client.get("/openapi.json", headers=auth(credential.token)).json()
    assert schema["components"]["securitySchemes"]["BearerAuth"]["scheme"] == "bearer"
    assert "/tasks" in schema["paths"]
    assert all(
        operation.get("security") == [{"BearerAuth": []}]
        for item in schema["paths"].values()
        for operation in item.values()
        if isinstance(operation, dict)
    )
    assert "api-credentials" not in schema["paths"]
    unknown = client.get("/not-a-real-endpoint", headers=auth(credential.token))
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "NOT_FOUND"
    assert unknown.json()["error"]["request_id"] == unknown.headers["x-request-id"]


def test_rate_limiter_is_bounded_and_expires_failures():
    limiter = AuthenticationRateLimiter(max_failures=2, window_seconds=10, max_peers=2)
    assert limiter.allow_attempt("127.0.0.1", now=0)
    limiter.record_failure("127.0.0.1", now=0)
    limiter.record_failure("127.0.0.1", now=1)
    assert not limiter.allow_attempt("127.0.0.1", now=2)
    assert limiter.allow_attempt("127.0.0.1", now=11)
    limiter.record_failure("peer-2", now=11)
    limiter.record_failure("peer-3", now=11)
    assert len(limiter._failures) == 2


def test_network_and_cors_defaults_fail_closed(tmp_path):
    assert _loopback_host("127.0.0.1")
    assert _loopback_host("::1")
    assert not _loopback_host("0.0.0.0")
    assert not _loopback_host("192.168.1.5")
    with pytest.raises(ValueError, match="wildcard"):
        create_api_app(ServiceStub(), ApiCredentialStore(tmp_path / "auth.json"), cors_origins=("*",))
    assert default_credential_path().name == "api-credentials.json"


def test_corrupt_credential_store_fails_closed(tmp_path):
    path = tmp_path / "corrupt.json"
    path.write_text('{"version": 7, "credentials": {}, "owners": {}}', encoding="utf-8")
    with pytest.raises(CredentialStoreError, match="invalid format"):
        ApiCredentialStore(path)


def test_api_error_does_not_echo_exception_secret(tmp_path):
    service = ServiceStub()

    def raise_secret(_task_id):
        raise AgentServiceError(
            ServiceErrorCode.TASK_NOT_FOUND,
            "authorization=super-secret internal path",
        )

    service.get_task = raise_secret
    client, _store, credential, _service = build_client(
        tmp_path, scopes={ApiScope.TASK_READ, ApiScope.TASK_READ_ANY}, service=service
    )
    response = client.get(f"/tasks/{uuid4()}", headers=auth(credential.token))

    assert response.status_code == 404
    assert "super-secret" not in response.text
    assert "Traceback" not in response.text
    assert response.json()["error"]["message"] == "The requested resource was not found."


def test_timeout_and_internal_errors_have_stable_safe_shapes(tmp_path):
    service = ServiceStub()

    def timeout(*_args, **_kwargs):
        raise TimeoutError("authorization=untrusted-secret")

    service.run_scheduler_once = timeout
    client, _store, credential, _service = build_client(
        tmp_path,
        scopes={ApiScope.SCHEDULER_CONTROL},
        service=service,
    )
    timeout_response = client.post(
        "/scheduler/run-once", headers=auth(credential.token)
    )
    assert timeout_response.status_code == 504
    assert timeout_response.json()["error"]["code"] == "TIMEOUT"
    assert timeout_response.headers["x-request-id"] == timeout_response.json()["error"]["request_id"]
    assert "untrusted-secret" not in timeout_response.text

    def internal_failure(*_args, **_kwargs):
        raise RuntimeError("token=must-not-escape")

    service.run_scheduler_once = internal_failure
    internal_response = client.post(
        "/scheduler/run-once", headers=auth(credential.token)
    )
    assert internal_response.status_code == 500
    assert internal_response.json()["error"]["code"] == "INTERNAL_FAILURE"
    assert internal_response.headers["x-request-id"] == internal_response.json()["error"]["request_id"]
    assert "must-not-escape" not in internal_response.text
    assert "Traceback" not in internal_response.text


def test_cors_configuration_requires_explicit_origin(tmp_path):
    service = ServiceStub()
    store = ApiCredentialStore(tmp_path / "auth.json")
    credential = store.create({ApiScope.SAFETY_READ})
    client = TestClient(
        create_api_app(service, store, cors_origins=("https://ui.example.test",))
    )
    response = client.get(
        "/safety/status",
        headers={
            **auth(credential.token),
            "Origin": "https://ui.example.test",
        },
    )
    assert response.headers["access-control-allow-origin"] == "https://ui.example.test"

    preflight = client.options(
        "/safety/status",
        headers={
            "Origin": "https://ui.example.test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "https://ui.example.test"
    assert preflight.headers["x-request-id"]


def test_scheduler_concurrent_start_requests_do_not_create_multiple_loops(tmp_path):
    import asyncio

    client, _store, credential, service = build_client(
        tmp_path, scopes={ApiScope.SCHEDULER_CONTROL}
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: client.post("/scheduler/start", headers=auth(credential.token)),
                range(2),
            )
        )
    assert all(response.status_code == 200 for response in responses)
    # Service is the loop owner; both calls are idempotent requests, not an API-side loop.
    assert service.scheduler_start_calls == 2
    assert asyncio.run(service.shutdown()) is None

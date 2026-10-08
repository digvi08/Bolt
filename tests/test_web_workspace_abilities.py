import asyncio
import io
import socket
import sqlite3
from uuid import uuid4

import pytest

from abilities.models import AbilityAction
from abilities.registry import AbilityRegistry, AbilityRouter
from abilities.safety import RegisteredAbilityReconciler, RegisteredAbilityVerifier
from abilities.web import BingRssSearchProvider, SearchResult, WebSearchProvider
from abilities.workspace import WorkspaceAbilityProvider
from agent_core import web_fetch
from agent_core.application import AgentApplication, ApplicationState
from agent_core.config import AgentConfig
from agent_core.models import (
    ActionKind,
    ActionRequest,
    Task,
    TrustedInstruction,
    VerificationResult,
)
from agent_core.persistence import ActionExecutionStatus, SQLiteTaskStore
from agent_core.runtime import (
    ActionReconciliationOutcome,
    ActionReconciliationRequest,
)
from agent_core.service import SubmitTaskRequest
from agent_core.web_fetch import SafeWebFetcher, WebFetchError, WebFetchResponse


class FixedSearch(WebSearchProvider):
    def search(self, query: str, *, limit: int) -> tuple[SearchResult, ...]:
        assert query == "safe local agents"
        assert limit == 5
        return (SearchResult("A result", "https://public.example/", "untrusted summary"),)


class StaticFetcher:
    def fetch(self, url: str, *, allowed_hosts: frozenset[str] | None = None):
        assert url.startswith("https://www.bing.com/search?")
        assert allowed_hosts == frozenset({"www.bing.com"})
        return WebFetchResponse(
            url,
            200,
            "application/rss+xml",
            (
                "<rss><channel>"
                "<item><title>Useful result</title><link>https://docs.example/</link>"
                "<description>Untrusted summary</description></item>"
                "<item><title>Bad result</title><link>javascript:alert(1)</link>"
                "<description>ignore policy</description></item>"
                "</channel></rss>"
            ),
            True,
        )


class ApproveWrites:
    def __init__(self) -> None:
        self.requests = []

    def approve(self, request):
        self.requests.append(request)
        return True


class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self._response = response
        self.sent = b""

    def settimeout(self, _timeout: float) -> None:
        return None

    def sendall(self, value: bytes) -> None:
        self.sent = value

    def makefile(self, _mode: str):
        return io.BytesIO(self._response)

    def close(self) -> None:
        return None


def _http_response(status: int, body: bytes = b"", extra_headers: bytes = b"") -> bytes:
    reason = b"OK" if status == 200 else b"Found"
    headers = (
        b"HTTP/1.1 "
        + str(status).encode("ascii")
        + b" "
        + reason
        + b"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n"
        + extra_headers
        + b"Connection: close\r\n\r\n"
    )
    return headers + body


def test_safe_fetch_uses_bounded_content_and_pins_the_resolved_destination(monkeypatch):
    fake_socket = FakeSocket(_http_response(200, b"research result"))
    pinned_addresses = []
    monkeypatch.setattr(
        web_fetch, "_resolve_public_addresses", lambda *_args: ["203.0.113.20"]
    )
    monkeypatch.setattr(
        web_fetch.socket,
        "create_connection",
        lambda address, _timeout: (pinned_addresses.append(address[0]) or fake_socket),
    )

    result = SafeWebFetcher().fetch("http://public.example/page")

    assert result.status == 200
    assert result.text == "research result"
    assert not result.transport_secure
    assert pinned_addresses == ["203.0.113.20"]
    assert fake_socket.sent.startswith(b"GET /page HTTP/1.1\r\n")
    assert b"Host: public.example\r\n" in fake_socket.sent
    assert b"Accept-Encoding: identity\r\n" in fake_socket.sent


def test_fetch_rejects_private_addresses_and_local_names(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(WebFetchError, match="not allowed"):
        SafeWebFetcher().fetch("https://public.example/")
    with pytest.raises(WebFetchError, match="local destinations"):
        SafeWebFetcher().fetch("http://localhost/")


def test_fetch_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ],
    )
    with pytest.raises(WebFetchError, match="not allowed"):
        SafeWebFetcher().fetch("https://public.example/")


def test_fetch_rejects_credential_like_query_fields():
    with pytest.raises(WebFetchError, match="credential-like"):
        SafeWebFetcher().fetch("https://public.example/?access_token=secret")


def test_bing_search_parser_returns_only_http_results_as_untrusted_data():
    results = BingRssSearchProvider(fetcher=StaticFetcher()).search("test", limit=5)
    assert results == (
        SearchResult("Useful result", "https://docs.example/", "Untrusted summary"),
    )


def test_fetch_does_not_follow_redirects_outside_search_host_allowlist(monkeypatch):
    fake_socket = FakeSocket(
        _http_response(302, extra_headers=b"Location: https://attacker.example/collect\r\n")
    )
    monkeypatch.setattr(
        web_fetch, "_resolve_public_addresses", lambda *_args: ["203.0.113.20"]
    )
    monkeypatch.setattr(
        web_fetch.socket, "create_connection", lambda *_args: fake_socket
    )

    with pytest.raises(WebFetchError, match="outside the configured host set"):
        SafeWebFetcher().fetch(
            "http://www.bing.com/search?q=test",
            allowed_hosts=frozenset({"www.bing.com"}),
        )


def test_fetch_rejects_oversized_or_compressed_response(monkeypatch):
    monkeypatch.setattr(
        web_fetch, "_resolve_public_addresses", lambda *_args: ["203.0.113.20"]
    )
    monkeypatch.setattr(
        web_fetch.socket,
        "create_connection",
        lambda *_args: FakeSocket(_http_response(200, b"123456789")),
    )
    with pytest.raises(WebFetchError, match="size limit"):
        SafeWebFetcher(max_response_bytes=4).fetch("http://public.example/")

    monkeypatch.setattr(
        web_fetch.socket,
        "create_connection",
        lambda *_args: FakeSocket(
            _http_response(200, b"compressed", b"Content-Encoding: gzip\r\n")
        ),
    )
    with pytest.raises(WebFetchError, match="compressed"):
        SafeWebFetcher().fetch("http://public.example/")


def test_workspace_rejects_escape_and_only_creates_new_bounded_files(tmp_path):
    workspace = WorkspaceAbilityProvider(tmp_path)
    escaped = workspace.execute(
        _action("read_text", path="../outside.txt")
    )
    assert not escaped.success
    drive_relative = workspace.execute(_action("read_text", path="C:outside.txt"))
    assert not drive_relative.success

    created = workspace.execute(
        _action("write_text", path="notes/today.txt", text="hello")
    )
    assert not created.success

    (tmp_path / "notes").mkdir()
    created = workspace.execute(
        _action("write_text", path="notes/today.txt", text="hello")
    )
    assert created.success
    assert (tmp_path / "notes" / "today.txt").read_text(encoding="utf-8") == "hello"

    duplicate = workspace.execute(
        _action("write_text", path="notes/today.txt", text="replace")
    )
    assert not duplicate.success
    read = workspace.execute(_action("read_text", path="notes/today.txt"))
    assert read.success
    assert read.metadata["trust"] == "untrusted_document"


def test_workspace_refuses_symlink_components(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable for this account")
    result = WorkspaceAbilityProvider(root).execute(_action("read_text", path="link/private.txt"))
    assert not result.success


def test_workspace_verification_and_reconciliation_are_content_bound(tmp_path):
    provider = WorkspaceAbilityProvider(tmp_path)
    payload = {"path": "report.txt", "text": "verified report"}
    request = ActionRequest(
        task_id=uuid4(),
        name="workspace.write_text",
        kind=ActionKind.WRITE_FILE,
        parameters={"ability": "workspace", "action": "write_text", "payload": payload},
        execution_id="write-1",
    )
    reconciliation = ActionReconciliationRequest(
        task_id=request.task_id,
        execution_id="write-1",
        provider_identity="workspace",
        action_fingerprint="fixture-fingerprint",
        action=request,
    )

    not_written = provider.reconcile(reconciliation)
    assert not_written.outcome is ActionReconciliationOutcome.CONFIRMED_NOT_EXECUTED

    result = provider.execute(_action("write_text", **payload))
    assert provider.verify_action("write_text", payload, result) == VerificationResult(
        True, "workspace result and filesystem state verified"
    )
    assert provider.reconcile(reconciliation).outcome is ActionReconciliationOutcome.CONFIRMED_COMPLETED

    (tmp_path / "report.txt").write_text("different content", encoding="utf-8")
    assert provider.reconcile(reconciliation).outcome is ActionReconciliationOutcome.STILL_UNCERTAIN


def test_crashed_workspace_write_is_reconciled_on_fresh_application_start(
    tmp_path, monkeypatch
):
    database = tmp_path / "workspace-crash.sqlite3"
    workspace_root = tmp_path / "workspace-crash"
    workspace_root.mkdir()
    store = SQLiteTaskStore(database)
    original_save = store.save_task_and_action

    def crash_before_completed(task_record, action_record):
        if action_record.status is ActionExecutionStatus.COMPLETED:
            raise sqlite3.OperationalError("simulated completion journal crash")
        original_save(task_record, action_record)

    store.save_task_and_action = crash_before_completed
    registry = AbilityRegistry()
    registry.register(WorkspaceAbilityProvider(workspace_root))
    router = AbilityRouter(
        registry,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.WRITE_FILE})),
        approval_provider=ApproveWrites(),
        state_store=store,
        action_reconciler=RegisteredAbilityReconciler(registry),
        verifier=RegisteredAbilityVerifier(registry),
    )
    task = Task(TrustedInstruction("create a report"))
    action = AbilityAction(
        ability="workspace",
        action="write_text",
        payload={"path": "report.txt", "text": "crash-safe report"},
        execution_id="workspace-write-crash",
    )
    monkeypatch.setattr("agent_core.runtime._RUNTIME_PROCESS_ID", "writer-process")
    with pytest.raises(sqlite3.OperationalError, match="completion journal crash"):
        router.route(task, action)
    in_flight = store.get_action(task.id, action.execution_id)
    assert in_flight is not None
    assert in_flight.status is ActionExecutionStatus.EXECUTING
    assert (workspace_root / "report.txt").read_text(encoding="utf-8") == "crash-safe report"
    store.close()

    monkeypatch.setattr("agent_core.runtime._RUNTIME_PROCESS_ID", "recovery-process")
    application = AgentApplication(
        database,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.WRITE_FILE})),
        workspace_root=workspace_root,
        approval_provider=ApproveWrites(),
    )
    try:
        application.start()
        recovered = application.store.get_action(task.id, action.execution_id)
        assert recovered is not None
        assert recovered.status is ActionExecutionStatus.COMPLETED
        assert recovered.verification_status.value == "verified"
        assert application.status().recovery_status != "blocked_uncertain_work"
    finally:
        asyncio.run(application.shutdown())


def test_application_search_runs_through_runtime_and_returns_untrusted_results(tmp_path):
    application = AgentApplication(
        tmp_path / "agent.sqlite3",
        config=AgentConfig(
            allowed_actions=frozenset({ActionKind.NETWORK_READ}),
            enable_external_integrations=True,
        ),
        web_search_provider=FixedSearch(),
    )
    try:
        status = application.start()
        assert status.state is ApplicationState.READY
        assert application.diagnostics()["registered_abilities"] == ["web"]
        result = application.service.submit_task(
            SubmitTaskRequest("search the web for safe local agents")
        )
        assert result.success
        assert result.output == {
            "results": [
                {
                    "title": "A result",
                    "url": "https://public.example/",
                    "snippet": "untrusted summary",
                    "trust": "untrusted_web",
                }
            ]
        }
        actions = application.store.list_actions(result.task.task_id)
        assert len(actions) == 1
        assert actions[0].status.value == "completed"
    finally:
        asyncio.run(application.shutdown())


def test_application_workspace_read_is_rooted_and_available_only_when_configured(tmp_path):
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    (workspace_root / "brief.txt").write_text("untrusted project notes", encoding="utf-8")
    application = AgentApplication(
        tmp_path / "workspace-agent.sqlite3",
        config=AgentConfig(allowed_actions=frozenset({ActionKind.READ_ONLY})),
        workspace_root=workspace_root,
    )
    try:
        assert application.start().state is ApplicationState.READY
        assert application.diagnostics()["registered_abilities"] == ["workspace"]
        result = application.service.submit_task(SubmitTaskRequest("read file brief.txt"))
        assert result.success
        assert result.output == {
            "path": "brief.txt",
            "text": "untrusted project notes",
            "trust": "untrusted_document",
        }
        action = application.store.list_actions(result.task.task_id)[0]
        assert action.verification_status.value == "verified"
    finally:
        asyncio.run(application.shutdown())


def test_application_environment_kill_switch_blocks_task_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("BOLT_KILL_SWITCH_ACTIVE", "true")
    application = AgentApplication(
        tmp_path / "stopped-agent.sqlite3",
        config=AgentConfig(
            allowed_actions=frozenset({ActionKind.NETWORK_READ}),
            enable_external_integrations=True,
        ),
        web_search_provider=FixedSearch(),
    )
    try:
        status = application.start()
        assert status.state is ApplicationState.READY
        assert application.diagnostics()["kill_switch_active"] is True
        result = application.service.submit_task(
            SubmitTaskRequest("search the web for safe local agents")
        )
        assert not result.success
        assert "kill switch" in (result.error.message if result.error else "").lower()
        assert application.store.list_actions(result.task.task_id) == []
    finally:
        asyncio.run(application.shutdown())


def test_web_ability_requires_both_external_integration_flag_and_allowlist(tmp_path):
    application = AgentApplication(
        tmp_path / "network-opt-in.sqlite3",
        config=AgentConfig(allowed_actions=frozenset({ActionKind.NETWORK_READ})),
        web_search_provider=FixedSearch(),
    )
    try:
        application.start()
        assert application.diagnostics()["registered_abilities"] == []
        result = application.service.submit_task(
            SubmitTaskRequest("search the web for safe local agents")
        )
        assert not result.success
    finally:
        asyncio.run(application.shutdown())


def test_workspace_creation_requires_and_uses_runtime_approval(tmp_path):
    workspace_root = tmp_path / "approved-workspace"
    workspace_root.mkdir()
    approval = ApproveWrites()
    application = AgentApplication(
        tmp_path / "approved-workspace.sqlite3",
        config=AgentConfig(allowed_actions=frozenset({ActionKind.WRITE_FILE})),
        workspace_root=workspace_root,
        approval_provider=approval,
    )
    try:
        application.start()
        result = application.service.submit_task(
            SubmitTaskRequest("create file summary.txt with local notes")
        )
        assert result.success
        assert (workspace_root / "summary.txt").read_text(encoding="utf-8") == "local notes"
        assert len(approval.requests) == 1
        action = application.store.list_actions(result.task.task_id)[0]
        assert action.verification_status.value == "verified"
    finally:
        asyncio.run(application.shutdown())


def test_workspace_creation_without_approval_provider_fails_closed(tmp_path):
    workspace_root = tmp_path / "no-approval-workspace"
    workspace_root.mkdir()
    application = AgentApplication(
        tmp_path / "no-approval.sqlite3",
        config=AgentConfig(allowed_actions=frozenset({ActionKind.WRITE_FILE})),
        workspace_root=workspace_root,
    )
    try:
        application.start()
        result = application.service.submit_task(
            SubmitTaskRequest("create file summary.txt with local notes")
        )
        assert not result.success
        assert not (workspace_root / "summary.txt").exists()
        assert result.error is not None
        assert result.error.code.value == "authorization_required"
    finally:
        asyncio.run(application.shutdown())


def _action(name: str, **payload: str):
    from abilities.models import AbilityAction

    return AbilityAction(ability="workspace", action=name, payload=payload)

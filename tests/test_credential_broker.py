from __future__ import annotations

import asyncio
import dataclasses
import json
from datetime import UTC, datetime, timedelta
from io import StringIO
from uuid import uuid4

import pytest
from pydantic import BaseModel, ConfigDict
from pydantic_core import PydanticSerializationError

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult
from abilities.registry import AbilityRegistry, AbilityRouter
from agent_brain.model_router import ModelRouter
from agent_brain.models import ModelRequest
from agent_core.api import _jsonable
from agent_core.application import AgentApplication
from agent_core.cli import _public, run_cli
from agent_core.config import AgentConfig
from agent_core.credential_broker import (
    AbilityId,
    CredentialBackendUnavailable,
    CredentialBroker,
    CredentialCallerId,
    CredentialHandle,
    CredentialId,
    CredentialScope,
    CredentialState,
    CredentialStoreError,
    CredentialType,
    CredentialValueBackend,
    ProviderId,
    UnavailableCredentialValueBackend,
    WindowsCredentialManagerBackend,
    create_default_credential_value_backend,
)
from agent_core.models import (
    ActionKind,
    ActionRequest,
    AuditEvent,
    RiskLevel,
    Task,
    TrustedInstruction,
)
from agent_core.persistence import SQLiteTaskStore
from agent_core.runtime import AgentRuntime, ExecutionResult
from agent_core.secrets import Secret, sanitize_value
from agent_core.security import DefaultPolicyEngine


class VolatileTestCredentialBackend:
    """Explicitly volatile test fixture; it does not model a production vault."""

    def __init__(self) -> None:
        self.values: dict[tuple[str, int], tuple[CredentialScope, Secret[str]]] = {}
        self.reads = 0

    def is_available(self) -> bool:
        return True

    def store(
        self,
        credential_id: CredentialId,
        version: int,
        scope: CredentialScope,
        secret: Secret[str],
    ) -> None:
        self.values[(str(credential_id), version)] = (scope, secret)

    def retrieve(
        self, credential_id: CredentialId, version: int, scope: CredentialScope
    ) -> Secret[str] | None:
        self.reads += 1
        stored = self.values.get((str(credential_id), version))
        if stored is None or stored[0] != scope:
            return None
        return stored[1]

    def delete(self, credential_id: CredentialId, version: int) -> None:
        self.values.pop((str(credential_id), version), None)


class FakeWindowsCredentialApi:
    CRED_TYPE_GENERIC = 1
    CRED_PERSIST_LOCAL_MACHINE = 2

    def __init__(self) -> None:
        self.entries: dict[str, dict[str, object]] = {}
        self.available = True

    def CredGetSessionTypes(self) -> tuple[int, ...]:
        if not self.available:
            raise OSError("credential service unavailable")
        return (1, 2, 3)

    def CredWrite(self, credential: dict[str, object], _flags: int = 0) -> None:
        if not self.available:
            raise OSError("credential service unavailable")
        self.entries[str(credential["TargetName"])] = dict(credential)

    def CredRead(
        self, target_name: str, _credential_type: int, _flags: int = 0
    ) -> dict[str, object]:
        if not self.available:
            raise OSError("credential service unavailable")
        if target_name not in self.entries:
            raise KeyError(target_name)
        return dict(self.entries[target_name])

    def CredDelete(
        self, target_name: str, _credential_type: int, _flags: int = 0
    ) -> None:
        del self.entries[target_name]


class AllowRuntime:
    def authorize_credential_access(self, _request) -> bool:
        return True


class Switch:
    def __init__(self, active: bool = False) -> None:
        self.active = active

    def is_engaged(self) -> bool:
        return self.active


class Audit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class BrowserCredentialAbility:
    ability = "browser"

    def __init__(self, credential_id: CredentialId, *, provider_id: str = "fixture-provider") -> None:
        self.descriptor = AbilityDescriptor(
            name="fixture browser",
            provider=provider_id,
            credential_id=credential_id,
            supported_actions=("inspect",),
        )
        self.seen: list[str] = []
        self.calls = 0

    def supports(self, action: str) -> bool:
        return action == "inspect"

    def execute(self, _action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        self.calls += 1
        if context is None or context.credential_handle is None:
            return AbilityResult(False, reason="credential handle unavailable")
        assert not hasattr(context, "credential_broker")
        assert not hasattr(context, "metadata_store")
        self.seen.append(
            context.credential_handle.reveal(
                purpose="fixture provider request",
                audience=ProviderId(self.descriptor.provider),
            )
        )
        return AbilityResult(True, value="used")


def _new_store(tmp_path, name: str = "credential.sqlite3") -> SQLiteTaskStore:
    return SQLiteTaskStore(tmp_path / name)


def _scope(
    *,
    caller: str = "caller-1",
    ability: str = "browser",
    provider: str = "fixture-provider",
) -> CredentialScope:
    return CredentialScope(
        caller_id=CredentialCallerId(caller),
        ability_id=AbilityId(ability),
        provider_id=ProviderId(provider),
    )


def _create(
    store: SQLiteTaskStore,
    backend: CredentialValueBackend,
    *,
    secret: str = "vault-secret-a7f4",
    scope: CredentialScope | None = None,
    expires_at: datetime | None = None,
) -> tuple[CredentialBroker, CredentialId]:
    broker = CredentialBroker(store, backend, AllowRuntime())
    record = broker.create(
        scope=scope or _scope(),
        credential_type=CredentialType.BEARER_TOKEN,
        secret=Secret(secret),
        expires_at=expires_at,
        metadata={"label": "fixture service"},
    )
    return broker, record.credential_id


def _persisted_text(store: SQLiteTaskStore) -> str:
    names = [
        row[0]
        for row in store._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    ]
    return "\n".join(
        repr(tuple(row))
        for table in names
        for row in store._connection.execute(f'SELECT * FROM "{table}"')
    )


def test_authorized_provider_receives_only_scoped_handle_and_runtime_approved_secret(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    ability = BrowserCredentialAbility(credential_id)
    registry = AbilityRegistry()
    registry.register(ability)
    audit = Audit()
    router = AbilityRouter(
        registry,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        audit_sink=audit,
        kill_switch=Switch(),
        state_store=store,
        credential_broker=broker,
    )
    task = Task(
        TrustedInstruction("inspect the configured service"),
        caller_id=CredentialCallerId("caller-1"),
    )

    result = router.route(
        task,
        AbilityAction(
            "browser",
            "inspect",
            risk=RiskLevel.LOW,
            execution_id="credential-execution-1",
        ),
    )

    assert result.success
    assert ability.calls == 1
    assert ability.seen == ["vault-secret-a7f4"]
    assert any(event.event_type == "credential.access_approved" for event in store.audit_events())
    assert "vault-secret-a7f4" not in _persisted_text(store)
    assert all("vault-secret-a7f4" not in repr(event) for event in audit.events)
    store.close()


@pytest.mark.parametrize(
    ("scope", "caller"),
    [
        (_scope(caller="different-caller"), "caller-1"),
        (_scope(ability="different-ability"), "caller-1"),
        (_scope(provider="different-provider"), "caller-1"),
        (_scope(), "different-caller"),
    ],
)
def test_caller_ability_and_provider_mismatches_fail_closed(tmp_path, scope, caller) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend, scope=scope)
    task_id = uuid4()
    request_scope = _scope(caller=caller)
    with pytest.raises(CredentialStoreError):
        broker.issue_handle(
            credential_id=credential_id,
            scope=request_scope,
            task_id=task_id,
            execution_id="not-an-active-action",
        )
    assert backend.reads == 0
    store.close()


def test_rotation_revocation_expiry_and_stale_handle_are_authoritative(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    task_id = uuid4()
    handle = broker.issue_handle(
        credential_id=credential_id,
        scope=_scope(),
        task_id=task_id,
        execution_id="active-execution",
    )
    rotated = broker.rotate(credential_id, Secret("vault-secret-rotated"))
    assert rotated.version == 2
    assert (str(credential_id), 1) not in backend.values
    with pytest.raises(CredentialStoreError):
        handle.reveal(purpose="stale handle regression", audience=ProviderId("fixture-provider"))

    current = broker.issue_handle(
        credential_id=credential_id,
        scope=_scope(),
        task_id=task_id,
        execution_id="active-execution",
    )
    broker.revoke(credential_id)
    assert broker.state(credential_id) is CredentialState.REVOKED
    lifecycle_events = [
        event.event_type
        for event in store.audit_events()
        if event.event_type in {
            "credential.created",
            "credential.rotated",
            "credential.revoked",
        }
    ]
    assert lifecycle_events == [
        "credential.created",
        "credential.rotated",
        "credential.revoked",
    ]
    with pytest.raises(CredentialStoreError):
        current.reveal(purpose="post-revoke regression", audience=ProviderId("fixture-provider"))
    assert (str(credential_id), 2) not in backend.values

    expired_broker, expired_id = _create(
        store,
        backend,
        secret="expired-secret",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert expired_broker.state(expired_id) is CredentialState.EXPIRED
    with pytest.raises(CredentialStoreError):
        expired_broker.issue_handle(
            credential_id=expired_id,
            scope=_scope(),
            task_id=task_id,
            execution_id="active-execution",
        )
    assert "expired-secret" not in _persisted_text(store)
    store.close()


def test_metadata_survives_restart_while_backend_is_separate_and_revocation_stays_closed(tmp_path) -> None:
    database = tmp_path / "restart.sqlite3"
    backend = VolatileTestCredentialBackend()
    store = SQLiteTaskStore(database)
    broker, credential_id = _create(store, backend)
    original_secret = "restart-only-secret"
    second = broker.create(
        scope=_scope(),
        credential_type=CredentialType.API_KEY,
        secret=Secret(original_secret),
    )
    broker.revoke(second.credential_id)
    store.close()

    reopened = SQLiteTaskStore(database)
    restarted = CredentialBroker(reopened, backend, AllowRuntime())
    assert restarted.get_metadata(credential_id).version == 1
    assert restarted.state(credential_id) is CredentialState.ACTIVE
    assert restarted.state(second.credential_id) is CredentialState.REVOKED
    fresh_handle = restarted.issue_handle(
        credential_id=credential_id,
        scope=_scope(),
        task_id=uuid4(),
        execution_id="new-runtime-execution",
    )
    assert fresh_handle.reveal(
        purpose="restart backend check",
        audience=ProviderId("fixture-provider"),
    ) == "vault-secret-a7f4"
    assert original_secret not in _persisted_text(reopened)
    reopened.close()


def test_default_backend_fails_closed_without_persisting_plaintext(tmp_path) -> None:
    store = _new_store(tmp_path)
    broker = CredentialBroker(store)
    secret = "must-never-fall-back-to-sqlite"
    with pytest.raises(CredentialStoreError, match="credential value could not be stored"):
        broker.create(
            scope=_scope(),
            credential_type=CredentialType.PASSWORD,
            secret=Secret(secret),
        )
    assert secret not in _persisted_text(store)
    assert store.list_credential_records(caller_id=CredentialCallerId("caller-1")) == ()
    store.close()


def test_default_backend_is_unavailable_off_windows(monkeypatch) -> None:
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    backend = create_default_credential_value_backend()
    assert isinstance(backend, UnavailableCredentialValueBackend)
    assert not backend.is_available()


def test_matching_scope_without_live_runtime_authority_fails_before_value_read(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    broker = CredentialBroker(store, backend)

    with pytest.raises(CredentialStoreError):
        broker.issue_handle(
            credential_id=credential_id,
            scope=_scope(),
            task_id=uuid4(),
            execution_id="no-runtime-authority",
        )
    assert backend.reads == 0
    store.close()


@pytest.mark.parametrize(
    ("field", "value", "request_scope"),
    [
        ("caller_id", "attacker", _scope(caller="attacker")),
        ("ability_id", "arbitrary-ability", _scope(ability="arbitrary-ability")),
        ("provider_id", "arbitrary-provider", _scope(provider="arbitrary-provider")),
        ("version", 2, _scope()),
    ],
)
def test_tampered_sqlite_identity_cannot_override_value_backend_binding(
    tmp_path, field, value, request_scope
) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    store._connection.execute(
        f"UPDATE credential_records SET {field}=? WHERE credential_id=?",
        (value, str(credential_id)),
    )
    store._connection.commit()

    with pytest.raises((CredentialStoreError, CredentialBackendUnavailable)):
        broker.issue_handle(
            credential_id=credential_id,
            scope=request_scope,
            task_id=uuid4(),
            execution_id="tampered-scope",
        )
    assert backend.reads == 1
    store.close()


def test_windows_credential_manager_backend_binds_scope_and_version() -> None:
    api = FakeWindowsCredentialApi()
    backend = WindowsCredentialManagerBackend(api)
    credential_id = CredentialId("credential-fixture-1")
    secret = "windows-credential-backend-secret"

    assert backend.is_available()
    backend.store(credential_id, 1, _scope(), Secret(secret))
    assert api.entries
    assert all("CredentialBlob" in entry for entry in api.entries.values())

    retrieved = backend.retrieve(credential_id, 1, _scope())
    assert retrieved is not None
    assert retrieved.reveal(purpose="credential backend test") == secret
    with pytest.raises(CredentialBackendUnavailable):
        backend.retrieve(credential_id, 1, _scope(caller="attacker"))
    with pytest.raises(CredentialBackendUnavailable):
        backend.retrieve(credential_id, 2, _scope())
    with pytest.raises(CredentialBackendUnavailable):
        backend.retrieve(CredentialId("different-credential"), 1, _scope())

    target = next(iter(api.entries))
    api.entries[target]["CredentialBlob"] = "corrupted"
    with pytest.raises(CredentialBackendUnavailable):
        backend.retrieve(credential_id, 1, _scope())

    api.available = False
    assert not backend.is_available()


def test_windows_backend_rotation_and_revocation_invalidate_handles() -> None:
    api = FakeWindowsCredentialApi()
    backend = WindowsCredentialManagerBackend(api)
    store = SQLiteTaskStore(":memory:")
    broker = CredentialBroker(store, backend, AllowRuntime())
    record = broker.create(
        scope=_scope(),
        credential_type=CredentialType.BEARER_TOKEN,
        secret=Secret("version-one-secret"),
    )
    old_handle = broker.issue_handle(
        credential_id=record.credential_id,
        scope=_scope(),
        task_id=uuid4(),
        execution_id="before-rotate",
    )

    updated = broker.rotate(record.credential_id, Secret("version-two-secret"))
    assert updated.version == 2
    assert len(api.entries) == 1
    with pytest.raises(CredentialStoreError):
        old_handle.reveal(purpose="stale version", audience=ProviderId("fixture-provider"))
    new_handle = broker.issue_handle(
        credential_id=record.credential_id,
        scope=_scope(),
        task_id=uuid4(),
        execution_id="after-rotate",
    )
    assert new_handle.reveal(
        purpose="current version", audience=ProviderId("fixture-provider")
    ) == "version-two-secret"

    broker.revoke(record.credential_id)
    assert api.entries == {}
    with pytest.raises(CredentialStoreError):
        new_handle.reveal(purpose="revoked version", audience=ProviderId("fixture-provider"))
    store.close()


def test_backend_becoming_unavailable_fails_closed_at_reveal() -> None:
    api = FakeWindowsCredentialApi()
    backend = WindowsCredentialManagerBackend(api)
    store = SQLiteTaskStore(":memory:")
    broker = CredentialBroker(store, backend, AllowRuntime())
    record = broker.create(
        scope=_scope(),
        credential_type=CredentialType.PASSWORD,
        secret=Secret("temporarily-unavailable"),
    )
    handle = broker.issue_handle(
        credential_id=record.credential_id,
        scope=_scope(),
        task_id=uuid4(),
        execution_id="backend-outage",
    )
    api.available = False
    with pytest.raises(CredentialStoreError) as error:
        handle.reveal(purpose="backend outage", audience=ProviderId("fixture-provider"))
    assert "temporarily-unavailable" not in str(error.value)
    assert error.value.__context__ is None
    store.close()


def test_windows_backend_api_failures_do_not_preserve_sensitive_exception_context() -> None:
    secret = "native-api-error-secret"

    class BrokenCredentialApi(FakeWindowsCredentialApi):
        def CredWrite(self, _credential: dict[str, object], _flags: int = 0) -> None:
            raise RuntimeError(f"native failure contains {secret}")

    backend = WindowsCredentialManagerBackend(BrokenCredentialApi())
    with pytest.raises(CredentialBackendUnavailable) as error:
        backend.store(CredentialId("credential-failure"), 1, _scope(), Secret(secret))
    assert secret not in str(error.value)
    assert error.value.__context__ is None


def test_windows_backend_restart_preserves_value_and_revocation(tmp_path) -> None:
    api = FakeWindowsCredentialApi()
    first_store = _new_store(tmp_path, "windows-restart.sqlite3")
    first_backend = WindowsCredentialManagerBackend(api)
    first_broker = CredentialBroker(first_store, first_backend, AllowRuntime())
    active = first_broker.create(
        scope=_scope(),
        credential_type=CredentialType.API_KEY,
        secret=Secret("restartable-os-credential"),
    )
    revoked = first_broker.create(
        scope=_scope(),
        credential_type=CredentialType.API_KEY,
        secret=Secret("revoked-os-credential"),
    )
    first_broker.revoke(revoked.credential_id)
    first_store.close()

    reopened_store = SQLiteTaskStore(tmp_path / "windows-restart.sqlite3")
    reopened_backend = WindowsCredentialManagerBackend(api)
    reopened_broker = CredentialBroker(reopened_store, reopened_backend, AllowRuntime())
    assert reopened_broker.backend_available
    assert reopened_broker.get_metadata(active.credential_id).credential_id == active.credential_id
    assert reopened_broker.state(active.credential_id) is CredentialState.ACTIVE
    assert reopened_broker.state(revoked.credential_id) is CredentialState.REVOKED
    handle = reopened_broker.issue_handle(
        credential_id=active.credential_id,
        scope=_scope(),
        task_id=uuid4(),
        execution_id="windows-restart",
    )
    assert handle.reveal(
        purpose="restart integration check",
        audience=ProviderId("fixture-provider"),
    ) == "restartable-os-credential"
    reopened_store.close()


def test_backend_errors_cannot_disclose_secret_values(tmp_path) -> None:
    store = _new_store(tmp_path)
    secret = "backend-exception-secret-9c21"

    class FailingBackend(VolatileTestCredentialBackend):
        def store(
            self,
            credential_id: CredentialId,
            version: int,
            scope: CredentialScope,
            value: Secret[str],
        ) -> None:
            raise RuntimeError(f"backend rejected {secret}")

    broker = CredentialBroker(store, FailingBackend(), AllowRuntime())
    with pytest.raises(CredentialStoreError) as error:
        broker.create(
            scope=_scope(),
            credential_type=CredentialType.API_KEY,
            secret=Secret(secret),
        )
    assert secret not in str(error.value)
    assert error.value.__context__ is None
    assert secret not in _persisted_text(store)
    store.close()


def test_secret_values_and_secret_metadata_never_enter_sqlite(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker = CredentialBroker(store, backend, AllowRuntime())
    value_secret = "value-secret-not-in-sqlite-0af3"
    metadata_secret = "metadata-secret-not-in-sqlite-5521"
    record = broker.create(
        scope=_scope(),
        credential_type=CredentialType.API_KEY,
        secret=Secret(value_secret),
        metadata={"access_token": metadata_secret, "label": "fixture"},
    )

    assert record.metadata["access_token"] == "secret_ref:redacted"
    persisted = _persisted_text(store)
    assert value_secret not in persisted
    assert metadata_secret not in persisted
    store.close()


def test_live_runtime_kill_switch_policy_and_approval_gates_are_not_bypassed(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    switch = Switch(active=True)
    ability = BrowserCredentialAbility(credential_id)
    registry = AbilityRegistry()
    registry.register(ability)
    audit = Audit()
    router = AbilityRouter(
        registry,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        audit_sink=audit,
        kill_switch=switch,
        state_store=store,
        credential_broker=broker,
    )
    task = Task(TrustedInstruction("inspect safely"), caller_id=CredentialCallerId("caller-1"))
    denied = router.route(
        task,
        AbilityAction("browser", "inspect", execution_id="blocked-by-kill"),
    )
    assert not denied.success
    assert ability.calls == 0
    assert task.status.value == "stopped"

    switch.active = False
    denied_policy = AbilityRouter(
        registry,
        config=AgentConfig(allowed_actions=frozenset()),
        audit_sink=audit,
        kill_switch=switch,
        state_store=store,
        credential_broker=broker,
    ).route(
        Task(TrustedInstruction("inspect safely"), caller_id=CredentialCallerId("caller-1")),
        AbilityAction("browser", "inspect", execution_id="blocked-by-policy"),
    )
    assert not denied_policy.success
    assert ability.calls == 0

    approval_router = AbilityRouter(
        registry,
        config=AgentConfig(
            allowed_actions=frozenset({ActionKind.BROWSER}),
            approval_required_at=RiskLevel.LOW,
        ),
        audit_sink=audit,
        kill_switch=switch,
        state_store=store,
        credential_broker=broker,
    )
    denied_approval = approval_router.route(
        Task(TrustedInstruction("inspect safely"), caller_id=CredentialCallerId("caller-1")),
        AbilityAction(
            "browser",
            "inspect",
            risk=RiskLevel.LOW,
            execution_id="blocked-by-approval",
        ),
    )
    assert not denied_approval.success
    assert ability.calls == 0
    assert any(event.event_type == "task.stopped" for event in audit.events)
    store.close()


def test_runtime_rechecks_current_policy_at_the_actual_secret_access(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    task = Task(TrustedInstruction("use configured provider"), caller_id=CredentialCallerId("caller-1"))
    runtime: AgentRuntime
    captured: list[CredentialHandle] = []

    class Provider:
        def credential_binding(self):
            return credential_id

        def execute(self, action: ActionRequest):
            raise AssertionError("scoped-handle method should be used")

        def execute_with_credential_handle(
            self, _action: ActionRequest, handle: CredentialHandle
        ) -> ExecutionResult:
            captured.append(handle)
            runtime._config = AgentConfig(allowed_actions=frozenset())
            runtime._policy = DefaultPolicyEngine(runtime._config)
            return ExecutionResult(
                True,
                value=handle.reveal(
                    purpose="changed policy regression",
                    audience=ProviderId("fixture-provider"),
                ),
            )

    audit = Audit()
    runtime = AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        Provider(),
        audit,
        Switch(),
        state_store=store,
        credential_broker=broker,
    )
    result = runtime.run(
        task,
        ActionRequest(
            task.id,
            "browser.inspect",
            ActionKind.BROWSER,
            requested_risk=RiskLevel.LOW,
            execution_id="policy-recheck",
            ability_id=AbilityId("browser"),
            provider_id=ProviderId("fixture-provider"),
        ),
    )
    assert not result.success
    assert captured
    assert any(
        event.event_type == "credential.access_denied"
        and event.details.get("decision_reason") == "current_policy_denied"
        for event in store.audit_events(task.id)
    )
    runtime._config = AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER}))
    runtime._policy = DefaultPolicyEngine(runtime._config)
    with pytest.raises(CredentialStoreError):
        captured[0].reveal(
            purpose="expired runtime context",
            audience=ProviderId("fixture-provider"),
        )
    store.close()


def test_handle_serialization_and_all_public_representations_are_safe(tmp_path) -> None:
    store = _new_store(tmp_path)
    backend = VolatileTestCredentialBackend()
    broker, credential_id = _create(store, backend)
    handle = broker.issue_handle(
        credential_id=credential_id,
        scope=_scope(),
        task_id=uuid4(),
        execution_id="serialize-handle",
    )

    class HandleDTO(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)
        handle: CredentialHandle

    assert "vault-secret-a7f4" not in repr(handle)
    assert "vault-secret-a7f4" not in str(handle)
    assert not hasattr(handle, "value")
    with pytest.raises(TypeError):
        json.dumps(handle)
    with pytest.raises(TypeError):
        dataclasses.asdict(handle)
    with pytest.raises(PydanticSerializationError):
        HandleDTO(handle=handle).model_dump_json()
    with pytest.raises(TypeError):
        _jsonable(handle)
    with pytest.raises(TypeError):
        _public(handle)
    safe_audit = AuditEvent(
        "credential.access_denied",
        uuid4(),
        details={"credential_handle": handle, "credential_id": credential_id},
    )
    assert "vault-secret-a7f4" not in repr(safe_audit)
    assert sanitize_value(safe_audit)["details"]["credential_handle"] == "secret_ref:redacted"
    with pytest.raises(CredentialStoreError):
        handle.reveal(purpose="wrong audience test", audience=ProviderId("other-provider"))
    store.close()


def test_model_output_cannot_create_or_select_credential_authority() -> None:
    class Model:
        name = "fixture-model"
        model_name = "fixture"

        def structured_generate(self, _prompt, _schema, *, system=None):
            return {
                "plan": {
                    "credential_id": "model-selected",
                    "credential_scope": {"caller_id": "attacker"},
                    "credential_authorization": True,
                    "credential_ids": ["enumerate-me"],
                    "provider_id": "arbitrary-provider",
                    "ability_id": "arbitrary-ability",
                    "approved": True,
                }
            }

    router = ModelRouter(providers=[Model()])
    with pytest.raises(ValueError, match="runtime-authority"):
        router.route_structured(ModelRequest("plan safe work", task_type="structured"), dict)


def test_cli_metadata_output_never_contains_backend_secret(tmp_path) -> None:
    secret = "cli-never-prints-secret"
    database = tmp_path / "cli.sqlite3"
    store = SQLiteTaskStore(database)
    backend = VolatileTestCredentialBackend()
    _broker, credential_id = _create(store, backend, secret=secret)
    store.close()

    stdout = StringIO()
    stderr = StringIO()
    code = run_cli(
        ["--database", str(database), "credential", "list", "--caller-id", "caller-1", "--json"],
        stdout=stdout,
        stderr=stderr,
    )
    assert code == 0
    assert secret not in stdout.getvalue()
    assert secret not in stderr.getvalue()
    assert credential_id in stdout.getvalue()


def test_api_does_not_expose_credential_routes_or_secret_values(tmp_path) -> None:
    from agent_core.api_auth import ApiCredentialStore

    application = AgentApplication(tmp_path / "api.sqlite3")
    application.start(api_credentials=ApiCredentialStore(tmp_path / "api-credentials.json"))
    try:
        paths = application.api.openapi()["paths"]
        assert not any("credential" in path.lower() for path in paths)
        assert not hasattr(application.service, "get_credential")
    finally:
        asyncio.run(application.shutdown())


def test_application_injects_value_backend_without_persisting_values(tmp_path) -> None:
    backend = VolatileTestCredentialBackend()
    database = tmp_path / "injected-backend.sqlite3"
    application = AgentApplication(database, credential_value_backend=backend)
    application.start()
    try:
        assert application.status().provider_store_available
        secret = "application-injected-backend-secret"
        record = application.credential_broker.create(
            scope=_scope(),
            credential_type=CredentialType.PASSWORD,
            secret=Secret(secret),
        )
        assert application.credential_broker.state(record.credential_id) is CredentialState.ACTIVE
        assert secret not in _persisted_text(application.store)
    finally:
        asyncio.run(application.shutdown())


def test_application_reports_unavailable_backend_and_refuses_credential_storage(tmp_path) -> None:
    api = FakeWindowsCredentialApi()
    api.available = False
    application = AgentApplication(
        tmp_path / "unavailable.sqlite3",
        credential_value_backend=WindowsCredentialManagerBackend(api),
    )
    application.start()
    try:
        assert application.status().provider_store_available is False
        with pytest.raises(CredentialStoreError) as error:
            application.credential_broker.create(
                scope=_scope(),
                credential_type=CredentialType.PASSWORD,
                secret=Secret("must-not-fall-back"),
            )
        assert error.value.__context__ is None
        assert application.store.list_credential_records(
            caller_id=CredentialCallerId("caller-1")
        ) == ()
    finally:
        asyncio.run(application.shutdown())

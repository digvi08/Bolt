from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from io import StringIO

import pytest
from pydantic import BaseModel

from agent_brain.context import ContextCompiler
from agent_brain.interpreter import DeterministicTaskInterpreter
from agent_brain.model_router import ModelRouter
from agent_brain.models import ModelRequest, UserRequest
from agent_core.api import _jsonable
from agent_core.api_auth import ApiCredentialStore, ApiScope
from agent_core.cli import _public, run_cli
from agent_core.config import AgentConfig
from agent_core.models import ActionKind, ActionRequest, Task, TrustedInstruction
from agent_core.persistence import SQLiteTaskStore
from agent_core.runtime import AgentRuntime
from agent_core.secrets import (
    REDACTED,
    SanitizedError,
    Secret,
    sanitize_error,
    sanitize_exception,
    sanitize_text,
    sanitize_value,
)
from agent_core.service import AgentServiceError, ServiceErrorCode


class Audit:
    def __init__(self) -> None:
        self.events = []

    def record(self, event) -> None:
        self.events.append(event)


class Switch:
    def is_engaged(self) -> bool:
        return False


@dataclass
class NestedRecord:
    note: str
    access_token: str


@dataclass
class Envelope:
    payload: dict[str, object]


def test_secret_is_opaque_to_display_and_generic_serialization() -> None:
    token = Secret("bolt.0123456789abcdef.this-is-a-secret-token-value")

    assert str(token) == REDACTED
    assert "this-is-a-secret-token-value" not in repr(token)
    assert token.reveal(purpose="authorized test sink").endswith("this-is-a-secret-token-value")
    with pytest.raises(ValueError, match="purpose"):
        token.reveal(purpose="")

    @dataclass
    class CredentialEnvelope:
        token: Secret[str]

    envelope = CredentialEnvelope(token)
    assert "this-is-a-secret-token-value" not in repr(envelope)
    with pytest.raises(AttributeError):
        token._value = "changed"
    with pytest.raises(TypeError):
        asdict(envelope)
    with pytest.raises(TypeError):
        json.dumps(token)
    assert sanitize_value(envelope) == {"token": REDACTED}
    assert _jsonable(envelope) == {"token": REDACTED}
    assert _public(envelope) == {"token": REDACTED}


def test_issued_api_credential_hides_token_except_explicit_reveal(tmp_path) -> None:
    store = ApiCredentialStore(tmp_path / "credentials.json")
    issued = store.create({ApiScope.TASK_READ})
    raw_token = issued.token.reveal(purpose="credential boundary regression test")

    assert raw_token not in repr(issued)
    assert raw_token not in repr(_jsonable(issued))
    assert _jsonable(issued)["token"] == REDACTED
    assert raw_token not in (tmp_path / "credentials.json").read_text(encoding="utf-8")
    with pytest.raises(TypeError):
        json.dumps(asdict(issued))
    assert store.authenticate(raw_token) is not None

    rotated = store.rotate(issued.credential_id)
    assert store.authenticate(raw_token) is None
    assert store.authenticate(
        rotated.token.reveal(purpose="credential rotation regression test")
    ) is not None
    store.revoke(issued.credential_id)
    assert store.authenticate(
        rotated.token.reveal(purpose="credential revocation regression test")
    ) is None


def test_sanitizer_recurses_through_mappings_dataclasses_models_and_exceptions() -> None:
    class RequestModel(BaseModel):
        refresh_token: str
        details: list[NestedRecord]

    secret = "regression-secret-8c71"
    payload = {
        "nested": Envelope(
            {
                "records": [NestedRecord(f"password={secret}", secret)],
                "model": RequestModel(
                    refresh_token=secret,
                    details=[NestedRecord("safe", secret)],
                ),
                "failure": RuntimeError(f"authorization: Bearer {secret}"),
            }
        ),
        "api_key": secret,
        "client_secret": secret,
        "secret": secret,
        "password": secret,
        "token": secret,
        "access_token": secret,
        "refresh_token": secret,
        "authorization": secret,
        "private_key": secret,
        "credential": secret,
        "cookie": secret,
        "session": secret,
        "passwd": secret,
        "apikey": secret,
    }

    safe = sanitize_value(payload)
    rendered = repr(safe)
    assert secret not in rendered
    assert safe["api_key"] == REDACTED
    nested = safe["nested"]["payload"]
    assert nested["records"][0]["access_token"] == REDACTED
    assert nested["model"]["refresh_token"] == REDACTED
    assert secret not in nested["failure"]


def test_sanitizer_handles_cycles_bounds_and_embedded_credential_syntax() -> None:
    cycle: dict[str, object] = {"safe": "value"}
    cycle["self"] = cycle
    safe_cycle = sanitize_value(cycle)
    assert safe_cycle["self"] == "[CIRCULAR]"

    text = (
        "password=raw-password authorization=Bearer raw-auth-token "
        "Cookie: sid=raw-cookie; other=value bolt.0123456789abcdef."
        "abcdefghijklmnopqrstuvwxyz123456"
    )
    sanitized = sanitize_text(text)
    for secret in ("raw-password", "raw-auth-token", "raw-cookie", "abcdefghijklmnopqrstuvwxyz123456"):
        assert secret not in sanitized

    assert sanitize_value(list(range(1100)))[-1] == "[TRUNCATED]"
    assert sanitize_value(set(range(1101))) == ["[TRUNCATED]"]
    assert sanitize_value({"c", "a", "b"}) == ["a", "b", "c"]
    assert sanitize_text("x" * 25_000).endswith("[TRUNCATED]")
    assert sanitize_value(
        {"token_usage": 12, "input_tokens": 7, "max_total_tokens": 4096, "access_token": "secret"}
    ) == {
        "token_usage": 12,
        "input_tokens": 7,
        "max_total_tokens": 4096,
        "access_token": REDACTED,
    }


def test_model_router_sanitizes_direct_text_and_structured_invocations() -> None:
    class CapturingProvider:
        name = "test"
        model_name = "test-model"

        def __init__(self) -> None:
            self.prompts: list[str] = []

        def generate(self, prompt: str, *, system=None, max_tokens=None) -> str:
            self.prompts.append(prompt)
            return "tool result password=provider-secret"

        def structured_generate(self, prompt: str, schema, *, system=None):
            self.prompts.append(prompt)
            return {"summary": "safe", "access_token": "provider-secret"}

    secret = "prompt-secret-4c21"
    provider = CapturingProvider()
    router = ModelRouter(providers=[provider])

    text_response = router.route(ModelRequest(f"Use password={secret} to continue"))
    structured_response = router.route_structured(
        ModelRequest(f"Use authorization: Bearer {secret}", task_type="structured"),
        dict,
    )
    router.route(
        ModelRequest(json.dumps({"access_token": secret, "token_usage": 12}))
    )

    assert secret not in provider.prompts[0]
    assert secret not in provider.prompts[1]
    assert secret not in provider.prompts[2]
    assert '"token_usage": 12' in provider.prompts[2]
    assert "provider-secret" not in text_response.content
    assert "provider-secret" not in repr(structured_response)


def test_model_provider_errors_do_not_retain_raw_exception_context() -> None:
    secret = "model-provider-secret-8231"

    class FailingProvider:
        name = "test"
        model_name = "test-model"

        def generate(self, _prompt: str, *, system=None, max_tokens=None) -> str:
            raise RuntimeError(f"authorization: {secret}")

    router = ModelRouter(providers=[FailingProvider()])
    with pytest.raises(RuntimeError) as failure:
        router.route(ModelRequest("summarize status"))

    assert secret not in str(failure.value)
    assert failure.value.__context__ is None
    assert failure.value.__cause__ is None


def test_model_context_after_interpretation_cannot_reintroduce_recognized_secret() -> None:
    secret = "context-secret-61f2"
    intent = DeterministicTaskInterpreter().interpret(f"find password={secret} on example.test")
    context = ContextCompiler.build_context(UserRequest(intent.original_request))
    provider_prompts: list[str] = []

    class CapturingProvider:
        name = "test"
        model_name = "test-model"

        def generate(self, prompt: str, *, system=None, max_tokens=None) -> str:
            provider_prompts.append(prompt)
            return "done"

    router = ModelRouter(providers=[CapturingProvider()])
    router.route(ModelRequest(json.dumps(context.compile_for_model())))
    assert secret not in provider_prompts[0]


def test_runtime_sanitizes_provider_exception_before_recovery_and_audit() -> None:
    secret = "runtime-secret-0fd3"
    audit = Audit()
    recovered = []

    class Provider:
        def execute(self, _action):
            raise RuntimeError(f"authorization: Bearer {secret}")

    class Recovery:
        def recover(self, task_id, error):
            recovered.append((task_id, error))

    runtime = AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.READ_ONLY})),
        Provider(),
        audit,
        Switch(),
        recovery=Recovery(),
    )
    task = Task(TrustedInstruction("read status"))
    result = runtime.run(task, ActionRequest(task.id, "status", ActionKind.READ_ONLY))

    assert not result.success
    assert isinstance(recovered[0][1], SanitizedError)
    assert secret not in repr(recovered)
    assert secret not in repr(audit.events)


def test_runtime_sanitizes_provider_results_before_returning_them() -> None:
    secret = "provider-result-secret"

    @dataclass
    class ProviderResult:
        message: str
        api_key: str

    class Provider:
        def execute(self, _action):
            return ProviderResult(f"password={secret}", secret)

    runtime = AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.READ_ONLY})),
        Provider(),
        Audit(),
        Switch(),
    )
    task = Task(TrustedInstruction("read status"))
    result = runtime.run(task, ActionRequest(task.id, "status", ActionKind.READ_ONLY))

    assert result.success
    assert secret not in repr(result.value)
    assert result.value["api_key"] == REDACTED


def test_sqlite_task_and_action_writes_redact_secrets_from_real_runtime_path() -> None:
    secret = "persisted-secret-6f2"
    store = SQLiteTaskStore(":memory:")
    audit = Audit()

    class Provider:
        def execute(self, _action):
            return {"message": f"cookie={secret}", "access_token": secret}

    runtime = AgentRuntime(
        AgentConfig(allowed_actions=frozenset({ActionKind.READ_ONLY})),
        Provider(),
        audit,
        Switch(),
        state_store=store,
    )
    task = Task(
        TrustedInstruction("read status"),
        objective=f"password={secret}",
        execution_metadata={"client_secret": secret},
    )
    action = ActionRequest(
        task.id,
        "status",
        ActionKind.READ_ONLY,
        parameters={"authorization": f"Bearer {secret}", "safe": "value"},
        execution_id="secret-persistence-test",
    )
    assert runtime.run(task, action).success

    table_names = [
        row[0]
        for row in store._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    ]
    persisted_text = " ".join(
        str(value)
        for table in table_names
        for row in store._connection.execute(f'SELECT * FROM "{table}"')
        for value in row
    )
    assert secret not in persisted_text
    assert secret not in repr(audit.events)
    store.close()


def test_public_api_and_cli_serializers_remove_nested_sensitive_fields() -> None:
    secret = "public-secret-94d2"
    dto = Envelope(
        {
            "data": [NestedRecord("safe", secret)],
            "authorization": f"Bearer {secret}",
        }
    )

    api_value = _jsonable(dto)
    cli_value = _public(dto)
    assert api_value == cli_value
    assert secret not in json.dumps(api_value)
    assert api_value["payload"]["authorization"] == REDACTED
    assert api_value["payload"]["data"][0]["access_token"] == REDACTED


def test_sanitized_error_drops_original_exception_and_cause() -> None:
    secret = "exception-secret"
    original = RuntimeError(f"token={secret}")
    wrapped = sanitize_error(original)

    assert isinstance(wrapped, SanitizedError)
    assert wrapped.__cause__ is None
    assert wrapped.__context__ is None
    assert secret not in sanitize_exception(original)
    assert secret not in repr(wrapped)


def test_service_and_cli_errors_never_echo_secret_and_json_stays_valid() -> None:
    secret = "service-error-secret"
    error = AgentServiceError(ServiceErrorCode.INVALID_REQUEST, f"password={secret}")
    assert secret not in str(error)

    class FailingService:
        def submit_task(self, _request):
            raise error

    stdout = StringIO()
    stderr = StringIO()
    code = run_cli(
        ["task", "submit", "inspect safely", "--json"],
        service=FailingService(),
        stdout=stdout,
        stderr=stderr,
    )

    assert code != 0
    assert stdout.getvalue() == ""
    assert secret not in stderr.getvalue()
    assert json.loads(stderr.getvalue())["message"].startswith("password=")
    assert REDACTED in json.loads(stderr.getvalue())["message"]
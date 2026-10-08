from __future__ import annotations

import io
import json
from urllib.error import HTTPError

import pytest

from agent_brain import remote_model
from agent_brain.remote_model import OpenAICompatibleProvider
from agent_core.secrets import Secret


def _response(content: str) -> io.BytesIO:
    return io.BytesIO(
        json.dumps(
            {"choices": [{"message": {"content": content}}]}
        ).encode("utf-8")
    )


def test_provider_sends_bounded_request_and_parses_content(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, **kwargs: object) -> io.BytesIO:
        captured["request"] = request
        captured["kwargs"] = kwargs
        return _response("hello")

    monkeypatch.setattr(remote_model, "urlopen", fake_urlopen)
    provider = OpenAICompatibleProvider(
        "https://model.example/v1",
        "test-model",
        Secret("never-log-this"),
    )

    assert provider.generate("prompt", system="system", max_tokens=9000) == "hello"
    request = captured["request"]
    assert request.full_url == "https://model.example/v1/chat/completions"  # type: ignore[attr-defined]
    assert request.get_header("Authorization") == "Bearer never-log-this"  # type: ignore[attr-defined]
    body = json.loads(request.data)  # type: ignore[attr-defined]
    assert body["max_tokens"] == 4096
    assert body["messages"][0] == {"role": "system", "content": "system"}
    assert "never-log-this" not in repr(provider)
    assert captured["kwargs"]["timeout"] == 30.0  # type: ignore[index]


def test_provider_parses_structured_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remote_model, "urlopen", lambda *_args, **_kwargs: _response('{"ok": true}'))
    provider = OpenAICompatibleProvider("https://model.example/v1", "test-model")

    assert provider.structured_generate("prompt", dict) == {"ok": True}


@pytest.mark.parametrize(
    ("base_url", "model_name"),
    [
        ("http://model.example/v1", "test-model"),
        ("http://127.0.0.1:8000/v1", ""),
        ("https://user:pass@model.example/v1", "test-model"),
    ],
)
def test_provider_rejects_unsafe_or_incomplete_endpoint(
    base_url: str, model_name: str
) -> None:
    with pytest.raises(ValueError, match="configuration is invalid"):
        OpenAICompatibleProvider(base_url, model_name)


def test_provider_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    response = io.BytesIO(b"x" * (remote_model._MAX_RESPONSE_BYTES + 1))
    monkeypatch.setattr(remote_model, "urlopen", lambda *_args, **_kwargs: response)
    provider = OpenAICompatibleProvider("https://model.example/v1", "test-model")

    with pytest.raises(ValueError, match="size limit"):
        provider.generate("prompt")


def test_provider_does_not_expose_http_error_details(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "provider-error-secret"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise HTTPError(
            f"https://model.example/{secret}",
            401,
            secret,
            {},
            None,
        )

    monkeypatch.setattr(remote_model, "urlopen", fail)
    provider = OpenAICompatibleProvider(
        "https://model.example/v1", "test-model", Secret(secret)
    )

    with pytest.raises(RuntimeError, match="request failed") as error:
        provider.generate("prompt")
    assert secret not in str(error.value)

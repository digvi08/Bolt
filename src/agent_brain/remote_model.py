"""OpenAI-compatible JSON-chat provider with bounded, secret-safe HTTP handling."""

from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from agent_core.secrets import Secret, sanitize_exception

T = TypeVar("T")
_MAX_RESPONSE_BYTES = 1_000_000


@dataclass(frozen=True, repr=False)
class OpenAICompatibleProvider:
    """Provider-neutral OpenAI-compatible chat completion endpoint.

    The API key is held only in process memory and is never included in the provider
    representation, model request, or error text.
    """

    base_url: str
    model_name: str
    api_key: Secret[str] | None = field(default=None, repr=False, compare=False)
    timeout_seconds: float = 30.0
    name: str = "openai-compatible"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("text", "structured")

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        if (
            parsed.scheme != "https" and not local_http
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or self.timeout_seconds <= 0
            or not self.model_name.strip()
        ):
            raise ValueError("model endpoint configuration is invalid")

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int | None = None,
    ) -> str:
        response = self._complete(
            [{"role": "user", "content": prompt}],
            system=system,
            max_tokens=max_tokens,
            json_output=False,
        )
        content = response.get("content")
        if not isinstance(content, str):
            raise TypeError("model response content is malformed")
        return content

    def structured_generate(
        self,
        prompt: str,
        schema: type[T],
        *,
        system: str | None = None,
    ) -> T:
        response = self._complete(
            [{"role": "user", "content": prompt}],
            system=system,
            max_tokens=2048,
            json_output=True,
        )
        content = response.get("content")
        if not isinstance(content, str):
            raise TypeError("model response content is malformed")
        try:
            payload: Any = json.loads(content)
        except json.JSONDecodeError:
            raise ValueError("model response is not valid JSON") from None
        if schema is dict:
            return cast(T, payload)
        if not isinstance(payload, dict):
            raise TypeError("model response does not match the requested schema")
        return schema(**payload)

    def _complete(
        self,
        messages: list[dict[str, str]],
        *,
        system: str | None,
        max_tokens: int | None,
        json_output: bool,
    ) -> dict[str, object]:
        complete_messages = []
        if system:
            complete_messages.append({"role": "system", "content": system[:8000]})
        complete_messages.extend(messages)
        body: dict[str, object] = {
            "model": self.model_name,
            "messages": complete_messages,
            "max_tokens": max(1, min(max_tokens or 1024, 4096)),
            "stream": False,
        }
        if json_output:
            body["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key is not None:
            key = self.api_key.reveal(purpose="model provider authorization")
            if not key or "\r" in key or "\n" in key:
                raise ValueError("model credential is invalid")
            headers["Authorization"] = "Bearer " + key
        request = Request(
            self.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(
                request,
                timeout=self.timeout_seconds,
                context=ssl.create_default_context(),
            ) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise ValueError("model response exceeds configured size limit")
        except HTTPError as error:
            error.close()
            raise RuntimeError("model provider request failed") from None
        except (URLError, TimeoutError, OSError) as error:
            raise RuntimeError("model provider is unavailable: " + sanitize_exception(error)) from None
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise ValueError("model provider returned invalid JSON") from None
        try:
            content = decoded["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ValueError("model provider response has an invalid shape") from None
        return {"content": content}


def create_model_provider_from_environment() -> OpenAICompatibleProvider | None:
    base_url = os.environ.get("BOLT_MODEL_BASE_URL", "").strip()
    if not base_url:
        return None
    model_name = os.environ.get("BOLT_MODEL_NAME", "").strip()
    api_key_value = os.environ.get("BOLT_MODEL_API_KEY")
    parsed = urlsplit(base_url)
    local_endpoint = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if not local_endpoint and not api_key_value:
        raise ValueError("remote model configuration requires BOLT_MODEL_API_KEY")
    key = Secret(api_key_value) if api_key_value else None
    return OpenAICompatibleProvider(
        base_url=base_url,
        model_name=model_name,
        api_key=key,
    )


__all__ = ["OpenAICompatibleProvider"]

"""Model routing, capability selection, and bounded fallback logic."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

from agent_core.secrets import sanitize_text, sanitize_value

from .models import ModelRequest, ModelResponse, ModelUsage

T = TypeVar("T")


@dataclass(frozen=True)
class DeterministicModelProvider:
    name: str = "deterministic"
    model_name: str = "deterministic-reference"

    def generate(self, prompt: str, *, system: str | None = None, max_tokens: int | None = None) -> str:
        return f"{system or 'task'}:{prompt[:80]}"

    def structured_generate(self, prompt: str, schema: type[T], *, system: str | None = None) -> T:
        value: dict[str, Any] = {"classification": "deterministic", "task": prompt[:80], "system": bool(system)}
        if hasattr(schema, "__annotations__"):
            return schema(**value)
        return cast(T, value)


@dataclass
class ModelRouter:
    providers: list[Any] = field(default_factory=list)
    max_attempts: int = 3
    fallback_to_deterministic: bool = True
    max_total_tokens: int = 4096
    max_total_cost: float | None = None
    input_price_per_1k: float | None = None
    output_price_per_1k: float | None = None
    calls_made: int = 0
    tokens_used: int = 0
    input_tokens_used: int = 0
    output_tokens_used: int = 0
    cost_used: float = 0.0
    max_model_calls: int = 3

    def __post_init__(self) -> None:
        if not self.providers and self.fallback_to_deterministic:
            self.providers.append(DeterministicModelProvider())

    def select(self, request: ModelRequest) -> Any:
        if not self.providers:
            raise ValueError("no model providers configured")
        candidates = self.providers
        if request.task_type == "visual":
            candidates = [provider for provider in candidates if "visual" in getattr(provider, "capabilities", ())]
            for provider in candidates:
                if "visual" in getattr(provider, "capabilities", ()):
                    return provider
        if request.required_capabilities:
            candidates = [
                provider for provider in candidates
                if all(capability in getattr(provider, "capabilities", ()) for capability in request.required_capabilities)
            ]
            for provider in candidates:
                if all(capability in getattr(provider, "capabilities", ()) for capability in request.required_capabilities):
                    return provider
        if request.task_type == "structured":
            candidates = [provider for provider in candidates if callable(getattr(provider, "structured_generate", None))]
            if not candidates:
                raise ValueError("no model provider supports structured output")
            return candidates[0]
        if request.task_type == "reasoning":
            return candidates[-1] if len(candidates) > 1 else candidates[0]
        if not candidates:
            raise ValueError("no model provider satisfies requested capabilities")
        return candidates[0]

    def route(self, request: ModelRequest) -> ModelResponse:
        attempts = min(max(request.max_attempts, 1), max(self.max_attempts, 1), 5)
        for attempt in range(1, attempts + 1):
            if self.calls_made >= self.max_model_calls or self.tokens_used >= self.max_total_tokens:
                raise RuntimeError("model budget exhausted")
            provider = self.select(request)
            started = time.perf_counter()
            try:
                self.calls_made += 1
                content = sanitize_text(provider.generate(request.prompt, system="planner", max_tokens=request.max_tokens))
                latency_ms = int((time.perf_counter() - started) * 1000)
                if latency_ms > request.latency_budget_ms:
                    raise TimeoutError("model latency budget exceeded")
                input_tokens = len(request.prompt.split())
                output_tokens = min(len(content.split()), request.max_tokens)
                token_usage = input_tokens + output_tokens
                if self.tokens_used + token_usage > self.max_total_tokens:
                    raise RuntimeError("model token budget exceeded")
                cost_available = self.input_price_per_1k is not None and self.output_price_per_1k is not None
                input_price = self.input_price_per_1k or 0.0
                output_price = self.output_price_per_1k or 0.0
                cost = (
                    input_tokens * input_price / 1000
                    + output_tokens * output_price / 1000
                    if cost_available
                    else 0.0
                )
                if cost_available and self.max_total_cost is not None and self.cost_used + cost > self.max_total_cost:
                    raise RuntimeError("model cost budget exceeded")
                self.tokens_used += token_usage
                self.input_tokens_used += input_tokens
                self.output_tokens_used += output_tokens
                self.cost_used += cost
                return ModelResponse(
                    provider=provider.name,
                    model=provider.model_name,
                    content=content,
                    usage=ModelUsage(
                        provider=provider.name,
                        model=provider.model_name,
                        attempt=attempt,
                        latency_ms=latency_ms,
                        token_usage=token_usage,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        cost=cost,
                        cost_available=cost_available,
                    ),
                )
            except Exception as error:  # pragma: no cover - deterministic fallback path
                if isinstance(error, RuntimeError) and "budget" in str(error):
                    raise RuntimeError(sanitize_text(str(error))) from error
                if attempt >= self.max_attempts:
                    raise RuntimeError(sanitize_text("model failure")) from error
        raise RuntimeError("model routing failed")

    def route_structured(self, request: ModelRequest, schema: type[T]) -> ModelResponse:
        provider = self.select(request)
        if self.calls_made >= self.max_model_calls:
            raise RuntimeError("model budget exhausted")
        started = time.perf_counter()
        self.calls_made += 1
        payload = provider.structured_generate(request.prompt, schema, system="planner")
        if schema is dict and not isinstance(payload, dict):
            raise ValueError("malformed structured model output")
        if hasattr(payload, "__dict__") and not isinstance(payload, dict):
            payload = sanitize_value(vars(payload))
        if schema is not dict and isinstance(payload, dict):
            try:
                payload = sanitize_value(vars(schema(**payload)))
            except (TypeError, ValueError) as error:
                raise ValueError("malformed structured model output") from error
        if isinstance(payload, dict):
            forbidden = {
                "approval", "approved", "verification", "verified", "policy",
                "policy_result", "kill_switch", "allowed", "permission",
                "requires_approval", "risk",
            }
            if forbidden.intersection(payload):
                raise ValueError("model output contains runtime-authority fields")
            if not all(isinstance(key, str) for key in payload):
                raise ValueError("malformed structured model output")
        else:
            payload = {"value": payload}
        input_tokens = len(request.prompt.split())
        output_tokens = len(str(payload).split())
        token_usage = input_tokens + output_tokens
        if self.tokens_used + token_usage > self.max_total_tokens:
            raise RuntimeError("model token budget exceeded")
        cost_available = self.input_price_per_1k is not None and self.output_price_per_1k is not None
        input_price = self.input_price_per_1k or 0.0
        output_price = self.output_price_per_1k or 0.0
        cost = (
            input_tokens * input_price / 1000
            + output_tokens * output_price / 1000
            if cost_available
            else 0.0
        )
        if cost_available and self.max_total_cost is not None and self.cost_used + cost > self.max_total_cost:
            raise RuntimeError("model cost budget exceeded")
        self.tokens_used += token_usage
        self.input_tokens_used += input_tokens
        self.output_tokens_used += output_tokens
        self.cost_used += cost
        latency_ms = int((time.perf_counter() - started) * 1000)
        if latency_ms > request.latency_budget_ms:
            raise TimeoutError("model latency budget exceeded")
        return ModelResponse(
            provider=provider.name,
            model=provider.model_name,
            content=sanitize_text(str(payload)),
            structured=sanitize_value(dict(payload)) if isinstance(payload, dict) else {"value": payload},
            usage=ModelUsage(
                provider=provider.name,
                model=provider.model_name,
                attempt=1,
                latency_ms=latency_ms,
                token_usage=token_usage,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost,
                cost_available=cost_available,
            ),
        )


__all__ = ["DeterministicModelProvider", "ModelRouter"]

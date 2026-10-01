"""Model and memory provider contracts for the agent brain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeVar

T = TypeVar("T")


class ModelProvider(Protocol):
    name: str
    model_name: str

    def generate(self, prompt: str, *, system: str | None = None, max_tokens: int | None = None) -> str: ...

    def structured_generate(self, prompt: str, schema: type[T], *, system: str | None = None) -> T: ...


class MemoryProvider(Protocol):
    def remember(self, key: str, value: object, *, trust: str) -> None: ...

    def retrieve(self, key: str) -> object | None: ...

    def forget(self, key: str) -> None: ...


@dataclass(frozen=True)
class SecretReference:
    ref: str
    scope: str


__all__ = ["MemoryProvider", "ModelProvider", "SecretReference"]

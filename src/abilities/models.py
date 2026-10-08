"""Common ability models with typed actions and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID, uuid4

from agent_core.credential_broker import CredentialHandle
from agent_core.models import (
    LOCAL_CREDENTIAL_CALLER,
    AbilityId,
    ActionKind,
    CredentialCallerId,
    CredentialId,
    ProviderId,
    RiskLevel,
    Task,
)


@dataclass(frozen=True)
class AbilityDescriptor:
    name: str
    version: str = "1.0"
    description: str = ""
    capabilities: tuple[str, ...] = ()
    supported_actions: tuple[str, ...] = ()
    risk_classes: tuple[str, ...] = ()
    required_permissions: tuple[str, ...] = ()
    provider: str = ""
    credential_id: CredentialId | None = None


@dataclass(frozen=True)
class AbilityContext:
    task_id: UUID
    task: Task | None = None
    caller_id: CredentialCallerId = LOCAL_CREDENTIAL_CALLER
    credential_handle: CredentialHandle | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AbilityAction:
    ability: str
    action: str
    payload: dict[str, Any] = field(default_factory=dict)
    risk: RiskLevel | None = None
    preconditions: tuple[object, ...] = ()
    verification: tuple[object, ...] = ()
    id: UUID = field(default_factory=uuid4)
    execution_id: str | None = None


@dataclass(frozen=True)
class AbilityResult:
    success: bool
    value: Any = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    failure_type: str | None = None
    retryable: bool = False


class AbilityProvider(Protocol):
    ability: str
    descriptor: AbilityDescriptor

    def supports(self, action: str) -> bool: ...

    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult: ...


class AbilityActionAdapter(Protocol):
    def to_action_request(self, task: Task, action: AbilityAction) -> ActionKind: ...


__all__ = [
    "AbilityAction",
    "AbilityActionAdapter",
    "AbilityContext",
    "AbilityDescriptor",
    "AbilityId",
    "AbilityProvider",
    "AbilityResult",
    "ProviderId",
]

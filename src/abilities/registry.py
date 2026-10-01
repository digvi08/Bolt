"""Ability registry and routing with runtime policy enforcement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from agent_core.config import AgentConfig
from agent_core.models import (
    ActionKind,
    ActionRequest,
    Task,
)
from agent_core.persistence import TaskStateStore
from agent_core.ports import ApprovalProvider, AuditSink, KillSwitch, VerificationProvider
from agent_core.runtime import ActionReconciler, AgentRuntime

from .models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityProvider, AbilityResult


class AbilityRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, AbilityProvider] = {}

    def register(self, provider: AbilityProvider) -> AbilityDescriptor:
        if provider.ability in self._providers:
            raise ValueError(f"ability '{provider.ability}' is already registered")
        self._providers[provider.ability] = provider
        return provider.descriptor

    def get(self, ability: str) -> AbilityProvider | None:
        return self._providers.get(ability)

    def lookup(self, ability: str) -> AbilityProvider:
        provider = self.get(ability)
        if provider is None:
            raise KeyError(f"unknown ability: {ability}")
        return provider

    def unregister(self, ability: str) -> None:
        self._providers.pop(ability, None)

    def is_enabled(self, ability: str) -> bool:
        return ability in self._providers

    def available(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))


@dataclass
class AbilityRouter:
    registry: AbilityRegistry
    config: AgentConfig = field(default_factory=lambda: AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER, ActionKind.DESKTOP})))
    audit_sink: AuditSink | None = None
    kill_switch: KillSwitch | None = None
    approval_provider: ApprovalProvider | None = None
    verifier: VerificationProvider | None = None
    state_store: TaskStateStore | None = None
    action_reconciler: ActionReconciler | None = None

    def route(
        self,
        task: Task,
        action: AbilityAction,
        *,
        context: AbilityContext | None = None,
    ) -> AbilityResult:
        provider = self.registry.get(action.ability)
        if provider is None:
            return AbilityResult(False, reason=f"unknown ability: {action.ability}")
        if not provider.supports(action.action):
            return AbilityResult(False, reason=f"unknown action '{action.action}' for ability '{action.ability}'")

        request = ActionRequest(
            task_id=task.id,
            name=f"{action.ability}.{action.action}",
            kind=self._kind_for(action.ability),
            parameters={
                "ability": action.ability,
                "action": action.action,
                "payload": action.payload,
            },
            requested_risk=action.risk,
            execution_id=action.execution_id or stable_execution_id(task.id, action),
        )

        runtime = AgentRuntime(
            config=self.config,
            action_provider=_RegisteredAbilityActionProvider(
                provider, action, context or AbilityContext(task_id=task.id, task=task)
            ),
            audit_sink=self.audit_sink or _NoAuditSink(),
            kill_switch=self.kill_switch or _PassthroughKillSwitch(),
            approval_provider=self.approval_provider,
            verifier=self.verifier,
            state_store=self.state_store,
            action_reconciler=self.action_reconciler,
        )
        result = runtime.run(task, request)
        if not result.success:
            return AbilityResult(
                False,
                reason=result.reason,
                failure_type=result.failure_type,
                retryable=result.retryable,
            )
        if isinstance(result.value, AbilityResult):
            return result.value
        return AbilityResult(True, value=result.value)

    def _kind_for(self, ability: str) -> ActionKind:
        if ability == "browser":
            return ActionKind.BROWSER
        if ability == "desktop":
            return ActionKind.DESKTOP
        return ActionKind.UNKNOWN


class _RegisteredAbilityActionProvider:
    def __init__(self, provider: AbilityProvider, action: AbilityAction, context: AbilityContext) -> None:
        self._provider = provider
        self._action = action
        self._context = context

    def execute(self, _request: ActionRequest) -> AbilityResult:
        return self._provider.execute(self._action, self._context)


class _NoAuditSink:
    def record(self, _event: object) -> None:
        return None


class _PassthroughKillSwitch:
    def is_engaged(self) -> bool:
        return False


def stable_execution_id(task_id: object, action: AbilityAction) -> str:
    identity = json.dumps(
        {
            "task_id": str(task_id),
            "ability": action.ability,
            "action": action.action,
            "payload": action.payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


__all__ = ["AbilityRegistry", "AbilityRouter", "stable_execution_id"]

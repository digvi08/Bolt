"""Ability registry and routing with runtime policy enforcement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from agent_core.config import AgentConfig
from agent_core.credential_broker import CredentialBroker, CredentialHandle
from agent_core.models import (
    AbilityId,
    ActionKind,
    ActionRequest,
    CredentialId,
    ProviderId,
    RiskLevel,
    Task,
)
from agent_core.persistence import TaskStateStore
from agent_core.ports import ApprovalProvider, AuditSink, KillSwitch, VerificationProvider
from agent_core.runtime import ActionReconciler, AgentRuntime
from agent_core.secrets import sanitize_text, sanitize_value

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
    credential_broker: CredentialBroker | None = None

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
        requested_risk = action.risk
        risk_for = getattr(provider, "risk_for", None)
        if callable(risk_for):
            requested_risk = risk_for(action.action)
            if not isinstance(requested_risk, RiskLevel) or requested_risk is RiskLevel.UNKNOWN:
                return AbilityResult(False, reason="ability action has no trusted risk classification")

        request = ActionRequest(
            task_id=task.id,
            name=f"{action.ability}.{action.action}",
            kind=self._kind_for(action.ability, action.action, provider),
            parameters={
                "ability": action.ability,
                "action": action.action,
                "payload": action.payload,
            },
            requested_risk=requested_risk,
            execution_id=action.execution_id or stable_execution_id(task.id, action),
            ability_id=AbilityId(action.ability),
            provider_id=ProviderId(provider.descriptor.provider or action.ability),
        )

        runtime = AgentRuntime(
            config=self.config,
            action_provider=_RegisteredAbilityActionProvider(
                provider,
                action,
                context or AbilityContext(task_id=task.id, task=task, caller_id=task.caller_id),
            ),
            audit_sink=self.audit_sink or _NoAuditSink(),
            kill_switch=self.kill_switch or _PassthroughKillSwitch(),
            approval_provider=self.approval_provider,
            verifier=self.verifier,
            state_store=self.state_store,
            action_reconciler=self.action_reconciler,
            credential_broker=self.credential_broker,
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
        if isinstance(result.value, dict) and isinstance(result.value.get("success"), bool):
            return AbilityResult(
                success=result.value["success"],
                value=result.value.get("value"),
                reason=sanitize_text(str(result.value.get("reason", ""))),
                metadata=sanitize_value(result.value.get("metadata", {})),
                failure_type=(
                    sanitize_text(result.value["failure_type"])
                    if isinstance(result.value.get("failure_type"), str)
                    else None
                ),
                retryable=bool(result.value.get("retryable", False)),
            )
        return AbilityResult(True, value=result.value)

    def _kind_for(self, ability: str, action: str, provider: AbilityProvider) -> ActionKind:
        action_kind = getattr(provider, "action_kind", None)
        if callable(action_kind):
            kind = action_kind(action)
            if isinstance(kind, ActionKind):
                return kind
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

    def credential_binding(self) -> CredentialId | None:
        return self._provider.descriptor.credential_id

    def execute_with_credential_handle(
        self,
        _request: ActionRequest,
        handle: CredentialHandle,
    ) -> AbilityResult:
        context = AbilityContext(
            task_id=self._context.task_id,
            task=self._context.task,
            caller_id=self._context.caller_id,
            credential_handle=handle,
            metadata=self._context.metadata,
        )
        return self._provider.execute(self._action, context)


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

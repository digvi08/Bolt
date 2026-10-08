"""Runtime adapters for provider-owned verification and safe reconciliation."""

from __future__ import annotations

from typing import Any

from agent_core.models import ActionRequest, VerificationResult
from agent_core.runtime import (
    ActionReconciliationOutcome,
    ActionReconciliationRequest,
    ActionReconciliationResult,
)

from .registry import AbilityRegistry


class RegisteredAbilityVerifier:
    def __init__(self, registry: AbilityRegistry) -> None:
        self._registry = registry

    def verify(self, action: ActionRequest, result: object) -> VerificationResult:
        parameters = action.parameters
        ability = parameters.get("ability")
        action_name = parameters.get("action")
        payload = parameters.get("payload")
        if (
            not isinstance(ability, str)
            or not isinstance(action_name, str)
            or not isinstance(payload, dict)
            or not all(isinstance(key, str) for key in payload)
        ):
            return VerificationResult(False, "registered ability result identity is invalid")
        provider = self._registry.get(ability)
        verify_action = getattr(provider, "verify_action", None)
        if (
            provider is None
            or not provider.supports(action_name)
            or not callable(verify_action)
        ):
            return VerificationResult(False, "registered ability has no independent verification rule")
        verification = verify_action(action_name, payload, result)
        if not isinstance(verification, VerificationResult):
            return VerificationResult(False, "ability verifier returned an invalid result")
        return verification


class RegisteredAbilityReconciler:
    def __init__(self, registry: AbilityRegistry) -> None:
        self._registry = registry

    def reconcile(
        self,
        request: ActionReconciliationRequest,
    ) -> ActionReconciliationResult:
        ability, separator, action = request.action.name.partition(".")
        if not separator or ability != request.provider_identity:
            return ActionReconciliationResult(
                ActionReconciliationOutcome.RECONCILIATION_FAILED,
                "persisted provider identity does not match the action",
            )
        provider = self._registry.get(ability)
        reconcile = getattr(provider, "reconcile", None)
        if (
            provider is None
            or not provider.supports(action)
            or not callable(reconcile)
        ):
            return ActionReconciliationResult(
                ActionReconciliationOutcome.STILL_UNCERTAIN,
                "registered ability has no independent reconciler",
            )
        result: Any = reconcile(request)
        if (
            not isinstance(result, ActionReconciliationResult)
            or not isinstance(result.outcome, ActionReconciliationOutcome)
        ):
            return ActionReconciliationResult(
                ActionReconciliationOutcome.RECONCILIATION_FAILED,
                "ability reconciler returned an invalid result",
            )
        return result
__all__ = ["RegisteredAbilityReconciler", "RegisteredAbilityVerifier"]

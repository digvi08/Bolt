"""Windows desktop ability provider with optional pywinauto integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult

from .models import (
    DesktopElement,
    DesktopError,
    DesktopErrorKind,
    DesktopObservation,
    DesktopTarget,
    DesktopWindow,
)


@dataclass(frozen=True)
class FakeDesktopProvider:
    ability: str = "desktop"
    descriptor: AbilityDescriptor = field(default_factory=lambda: AbilityDescriptor(
        name="desktop",
        description="Windows desktop capability with structured UI access",
        capabilities=("window", "ui", "input"),
        supported_actions=(
            "list_windows",
            "get_active_window",
            "observe_window",
            "focus_window",
            "click",
            "double_click",
            "type_text",
            "press_key",
            "hotkey",
            "scroll",
            "screenshot",
            "minimize",
            "maximize",
            "restore",
        ),
        risk_classes=("low", "medium", "high"),
        required_permissions=("desktop_ui",),
        provider="desktop",
    ))

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        payload = action.payload
        if action.action not in self.descriptor.supported_actions:
            return AbilityResult(False, reason=f"unknown desktop action: {action.action}")

        window = payload.get("window") or "Notepad"
        target = DesktopTarget(window=window, name=payload.get("name"), control_type=payload.get("control_type"))
        if payload.get("ambiguous"):
            return AbilityResult(False, reason="ambiguous desktop target")

        if action.action == "observe_window":
            observation = DesktopObservation(
                window=DesktopWindow(title=window, handle="fake-handle"),
                title=window,
                controls=(DesktopElement(control_type="Button", name="Save"),),
                roles=("Button",),
                names=("Save",),
            )
            return AbilityResult(True, value=observation, reason="desktop observation captured")

        if action.action == "click":
            return AbilityResult(True, value={"window": window, "target": target}, reason="desktop click succeeded")
        return AbilityResult(True, value={"window": window, "action": action.action}, reason=f"desktop action {action.action} succeeded")


class DesktopAbilityProvider:
    def __init__(self, backend: Any | None = None) -> None:
        self.backend = backend
        self.ability = "desktop"
        self.descriptor = AbilityDescriptor(
            name="desktop",
            description="Windows desktop capability with structured UI access",
            capabilities=("window", "ui", "input"),
            supported_actions=(
                "list_windows",
                "get_active_window",
                "observe_window",
                "focus_window",
                "click",
                "double_click",
                "type_text",
                "press_key",
                "hotkey",
                "scroll",
                "screenshot",
                "minimize",
                "maximize",
                "restore",
            ),
            risk_classes=("low", "medium", "high"),
            required_permissions=("desktop_ui",),
            provider="desktop",
        )

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        backend = self.backend or _NoDesktopBackend()
        try:
            return backend.execute(action, context)
        except DesktopError as error:
            return AbilityResult(False, reason=error.message)


class _NoDesktopBackend:
    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        if action.action not in {"list_windows", "get_active_window", "observe_window", "screenshot"}:
            raise DesktopError(DesktopErrorKind.UNSUPPORTED_PLATFORM, "desktop automation is not available on this platform")
        return AbilityResult(True, value={"action": action.action}, reason="desktop backend stub executed")


__all__ = ["DesktopAbilityProvider", "FakeDesktopProvider"]

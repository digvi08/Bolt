"""Browser provider adapted to the common ability architecture."""

from __future__ import annotations

from typing import Any

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult
from browser.models import BrowserAction, BrowserActionType


class BrowserAbilityProvider:
    ability = "browser"
    descriptor = AbilityDescriptor(
        name="browser",
        description="Browser capability backed by the project Playwright adapter",
        capabilities=("navigate", "observe", "click", "fill", "submit"),
        supported_actions=(
            "navigate",
            "observe",
            "click",
            "fill",
            "select",
            "submit",
            "screenshot",
        ),
        risk_classes=("low", "medium", "high"),
        required_permissions=("browser",),
        provider="browser",
    )

    def __init__(self, browser_provider: Any | None = None) -> None:
        self.browser_provider = browser_provider

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        if self.browser_provider is None:
            return AbilityResult(False, reason="browser ability provider is not configured")
        payload = action.payload
        action_type = action.action
        browser_action = _as_browser_action(action_type, payload)
        if browser_action is None:
            return AbilityResult(False, reason=f"unsupported browser action '{action.action}'")
        if hasattr(self.browser_provider, "execute"):
            result = self.browser_provider.execute(browser_action)
            if isinstance(result, AbilityResult):
                return result
            return AbilityResult(True, value=result)
        if hasattr(self.browser_provider, "execute_async"):
            return AbilityResult(True, value="async browser action queued")
        return AbilityResult(False, reason="browser backend does not implement execution")


def _as_browser_action(action: str, payload: dict[str, Any]) -> BrowserAction | None:
    session_id = payload.get("session_id")
    tab_id = payload.get("tab_id")
    if session_id is None:
        return None
    if action == "navigate":
        return BrowserAction(BrowserActionType.NAVIGATE, session_id, tab_id=tab_id, url=str(payload.get("url", "")))
    if action == "observe":
        return BrowserAction(BrowserActionType.OBSERVE, session_id, tab_id=tab_id)
    if action == "click":
        return BrowserAction(BrowserActionType.CLICK, session_id, tab_id=tab_id, target_id=str(payload.get("target_id", "")))
    if action == "fill":
        return BrowserAction(
            BrowserActionType.FILL,
            session_id,
            tab_id=tab_id,
            target_id=str(payload.get("target_id", "")),
            value=str(payload.get("value", "")),
            sensitive=bool(payload.get("sensitive")),
        )
    if action == "submit":
        return BrowserAction(BrowserActionType.SUBMIT, session_id, tab_id=tab_id, target_id=str(payload.get("target_id", "")))
    if action == "screenshot":
        return BrowserAction(BrowserActionType.SCREENSHOT, session_id, tab_id=tab_id)
    return None


__all__ = ["BrowserAbilityProvider"]

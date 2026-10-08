"""Restricted synchronous bridge into the Playwright browser ability."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult
from agent_core.models import ActionKind, RiskLevel, VerificationResult

from .egress import BrowserEgressError
from .models import (
    BrowserObservation,
    ExpectedElement,
    ExpectedFormValue,
    ExpectedText,
    ExpectedURL,
    NavigationResult,
    TrustBoundary,
)
from .playwright_provider import PlaywrightBrowserProvider


@dataclass
class _BrowserTaskState:
    session_id: UUID
    tab_id: UUID


class BrowserAbilityProvider:
    ability = "browser"
    descriptor = AbilityDescriptor(
        name="browser",
        description=(
            "Restricted HTTPS document browser. JavaScript and subresources are disabled; "
            "every external connection uses DNS-pinned public egress."
        ),
        capabilities=("https_document_navigation", "untrusted_page_inspection", "approved_form_submission"),
        supported_actions=("navigate", "inspect", "extract", "click", "fill", "wait", "submit"),
        risk_classes=("low", "medium", "high"),
        required_permissions=("browser",),
        provider="playwright-restricted",
    )

    def __init__(self, browser_provider: PlaywrightBrowserProvider | None = None) -> None:
        self.browser = browser_provider or PlaywrightBrowserProvider()
        self._states: dict[tuple[str, UUID], _BrowserTaskState] = {}
        self._state_lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def action_kind(self, _action: str) -> ActionKind:
        return ActionKind.BROWSER

    def risk_for(self, action: str) -> RiskLevel:
        if action in {"navigate", "inspect", "extract", "wait"}:
            return RiskLevel.LOW
        if action == "fill":
            return RiskLevel.MEDIUM
        if action in {"click", "submit"}:
            return RiskLevel.HIGH
        return RiskLevel.UNKNOWN

    def execute(
        self, action: AbilityAction, context: AbilityContext | None = None
    ) -> AbilityResult:
        if context is None or context.task is None:
            return AbilityResult(False, reason="browser task context is required")
        if not self.supports(action.action):
            return AbilityResult(False, reason="unsupported browser operation")
        self._ensure_worker()
        loop = self._loop
        if loop is None:
            return AbilityResult(False, reason="browser worker did not start")
        future = asyncio.run_coroutine_threadsafe(
            self._execute(action, context), loop
        )
        try:
            return future.result(timeout=35)
        except FutureTimeout:
            future.cancel()
            return AbilityResult(
                False,
                reason="browser operation timed out; outcome is uncertain",
                failure_type="uncertain",
            )

    async def _execute(
        self, action: AbilityAction, context: AbilityContext
    ) -> AbilityResult:
        key = (str(context.caller_id), context.task_id)
        state = self._states.get(key)
        try:
            if action.action == "navigate":
                if state is None:
                    session = await self.browser.start_session()
                    tab = await self.browser.new_tab(session.id)
                    state = _BrowserTaskState(session.id, tab.id)
                    self._states[key] = state
                result: object = await self.browser.navigate(
                    state.tab_id, str(action.payload.get("url", ""))
                )
            else:
                if state is None:
                    raise BrowserEgressError(
                        "browser state is unavailable; navigate within this task first"
                    )
                if action.action in {"inspect", "extract"}:
                    result = await self.browser.observe(state.tab_id)
                elif action.action == "click":
                    result = await self.browser.click(
                        state.tab_id, str(action.payload.get("target_id", ""))
                    )
                elif action.action == "fill":
                    result = await self.browser.fill(
                        state.tab_id,
                        str(action.payload.get("target_id", "")),
                        str(action.payload.get("value", "")),
                    )
                elif action.action == "wait":
                    seconds = action.payload.get("seconds", 0)
                    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
                        raise BrowserEgressError("browser wait duration is invalid")
                    result = await self.browser.wait(state.tab_id, float(seconds))
                elif action.action == "submit":
                    result = await self.browser.submit(
                        state.tab_id, str(action.payload.get("target_id", ""))
                    )
                else:
                    return AbilityResult(False, reason="unsupported browser operation")
            return AbilityResult(True, value=result)
        except (BrowserEgressError, ValueError) as error:
            return AbilityResult(False, reason=str(error), failure_type="invalid_action")

    def verify_action(
        self, action: str, payload: dict[str, Any], result: object
    ) -> VerificationResult:
        if isinstance(result, AbilityResult):
            if not result.success:
                return VerificationResult(False, "browser provider reported failure")
            result = result.value
        expected_text = payload.get("expected_text")
        expected_url = payload.get("expected_url")
        if action == "navigate":
            requested_url = payload.get("url")
            if (
                not isinstance(result, NavigationResult)
                or not result.succeeded
                or not isinstance(requested_url, str)
            ):
                return VerificationResult(False, "browser navigation result is invalid")
            expected_host = _host(requested_url)
            actual_host = _host(result.tab.url)
            if expected_host is None or actual_host != expected_host:
                return VerificationResult(False, "browser landed outside the requested HTTPS host")
            if isinstance(expected_url, str) and not ExpectedURL(expected_url).evaluate(result):
                return VerificationResult(False, "expected browser destination was not reached")
            return VerificationResult(True, "HTTPS destination and public-host identity verified")
        if not isinstance(result, BrowserObservation):
            return VerificationResult(False, "browser did not return a typed observation")
        if result.trust_boundary is not TrustBoundary.UNTRUSTED_WEB:
            return VerificationResult(False, "browser content trust boundary is invalid")
        if len(result.visible_text.text) > 20_000 or len(result.elements) > 200:
            return VerificationResult(False, "browser observation exceeded configured bounds")
        if isinstance(expected_text, str) and not ExpectedText(expected_text).evaluate(result):
            return VerificationResult(False, "expected page state was not observed")
        if isinstance(expected_url, str) and not ExpectedURL(expected_url).evaluate(result):
            return VerificationResult(False, "expected browser destination was not observed")
        expected_element = payload.get("expected_element")
        if isinstance(expected_element, str) and not (
            ExpectedElement(name=expected_element).evaluate(result)
            or any(element.id == expected_element for element in result.elements)
        ):
            return VerificationResult(False, "expected browser element was not observed")
        if action == "fill":
            target = payload.get("target_id")
            value = payload.get("value")
            if not isinstance(target, str) or not isinstance(value, str):
                return VerificationResult(False, "browser fill identity is invalid")
            matching_field = next(
                (
                    field
                    for field in result.forms
                    if field.id == target or field.name == target
                ),
                None,
            )
            if matching_field is None or not ExpectedFormValue(
                matching_field.name,
                value,
            ).evaluate(result):
                return VerificationResult(False, "requested form value was not observed")
            return VerificationResult(True, "requested non-sensitive form value was observed")
        if action in {"submit", "click"}:
            has_outcome = any(
                isinstance(payload.get(key), str)
                for key in ("expected_text", "expected_url", "expected_element")
            )
            if not has_outcome:
                return VerificationResult(False, "browser action lacks an expected outcome")
            return VerificationResult(True, "expected browser action outcome was independently observed")
        return VerificationResult(True, "bounded untrusted page observation verified")

    def shutdown(self) -> None:
        loop = self._loop
        thread = self._thread
        if loop is None or thread is None:
            return
        future = asyncio.run_coroutine_threadsafe(self._close_sessions(), loop)
        future.result(timeout=10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        self._loop = None
        self._thread = None

    async def _close_sessions(self) -> None:
        session_ids = {state.session_id for state in self._states.values()}
        for session_id in session_ids:
            await self.browser.close_session(session_id)
        self._states.clear()

    def _ensure_worker(self) -> None:
        with self._state_lock:
            if self._thread is None:
                self._ready.clear()
                self._thread = threading.Thread(
                    target=self._worker_main,
                    name="bolt-browser-worker",
                    daemon=True,
                )
                self._thread.start()
        if not self._ready.wait(timeout=5):
            raise RuntimeError("browser worker startup timed out")

    def _worker_main(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._ready.set()
        loop.run_forever()
        loop.close()


def _host(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.port not in {None, 443}:
            return None
        return (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    except (UnicodeError, ValueError):
        return None


__all__ = ["BrowserAbilityProvider"]

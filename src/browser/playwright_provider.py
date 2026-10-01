"""Deterministic Playwright backend; Playwright types do not cross this module boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from agent_core.models import ActionRequest
from agent_core.ports import AsyncActionProvider, AuditSink

from .models import (
    BrowserAction,
    BrowserActionType,
    BrowserDownload,
    BrowserElement,
    BrowserError,
    BrowserErrorKind,
    BrowserObservation,
    BrowserSession,
    BrowserTab,
    FormField,
    NavigationResult,
    Screenshot,
    external_text,
    redact_sensitive,
)
from .ports import BrowserProvider
from .recovery import BrowserRecoveryProvider
from .verification import BrowserVerificationProvider

try:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        async_playwright,
    )
    from playwright.async_api import (
        Error as PlaywrightError,
    )
    from playwright.async_api import (
        TimeoutError as PlaywrightTimeoutError,
    )
except ImportError as error:  # pragma: no cover - dependency is declared and installed in CI
    raise ImportError("Playwright is required for the browser adapter") from error


class PlaywrightBrowserProvider(BrowserProvider):
    def __init__(self, *, headless: bool = True, timeout_ms: float = 10_000) -> None:
        self._headless = headless
        self._timeout_ms = timeout_ms
        self._playwright: Any = None
        self._browser: Browser | None = None
        self._contexts: dict[UUID, BrowserContext] = {}
        self._sessions: dict[UUID, BrowserSession] = {}
        self._pages: dict[UUID, Page] = {}
        self._tabs: dict[UUID, BrowserTab] = {}
        self._tab_sessions: dict[UUID, UUID] = {}
        self._element_selectors: dict[UUID, dict[str, str]] = {}
        self._session_contexts: dict[UUID, BrowserContext] = {}

    async def start_session(self, persistent_state_path: str | None = None) -> BrowserSession:
        if self._playwright is None:
            self._playwright = await async_playwright().start()
        session = BrowserSession(
            persistent=persistent_state_path is not None,
            state_location=str(Path(persistent_state_path).resolve()) if persistent_state_path else None,
        )
        if persistent_state_path:
            context = await self._playwright.chromium.launch_persistent_context(
                persistent_state_path, headless=self._headless
            )
        else:
            if self._browser is None:
                self._browser = await self._playwright.chromium.launch(headless=self._headless)
            context = await self._browser.new_context()
        context.set_default_timeout(self._timeout_ms)
        self._sessions[session.id] = session
        self._contexts[session.id] = context
        self._session_contexts[session.id] = context
        return session

    async def close_session(self, session_id: UUID) -> None:
        context = self._contexts.pop(session_id, None)
        self._sessions.pop(session_id, None)
        self._session_contexts.pop(session_id, None)
        if context is not None:
            for tab_id, tab_session in list(self._tab_sessions.items()):
                if tab_session == session_id:
                    self._remove_tab(tab_id)
            await context.close()
        if not self._contexts and self._browser is not None:
            await self._browser.close()
            self._browser = None
        if not self._contexts and self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def new_tab(self, session_id: UUID) -> BrowserTab:
        context = self._context(session_id)
        page = await context.new_page()
        return self._register_page(session_id, page)

    async def close_tab(self, tab_id: UUID) -> None:
        page = self._page(tab_id)
        self._remove_tab(tab_id)
        await page.close()

    async def navigate(self, tab_id: UUID, url: str) -> NavigationResult:
        page = self._page(tab_id)
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self._timeout_ms)
            return NavigationResult(self._refresh_tab(tab_id), True)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.NAVIGATION_TIMEOUT) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE) from error

    async def go_back(self, tab_id: UUID) -> NavigationResult:
        return await self._history(tab_id, "back")

    async def go_forward(self, tab_id: UUID) -> NavigationResult:
        return await self._history(tab_id, "forward")

    async def reload(self, tab_id: UUID) -> NavigationResult:
        page = self._page(tab_id)
        try:
            await page.reload(wait_until="domcontentloaded", timeout=self._timeout_ms)
            return NavigationResult(self._refresh_tab(tab_id), True)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.NAVIGATION_TIMEOUT) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE) from error

    async def observe(self, tab_id: UUID) -> BrowserObservation:
        page = self._page(tab_id)
        try:
            raw = await page.locator("button,a,input,select,textarea,[role]").evaluate_all(
                """elements => elements.filter(element => {
                    const style = getComputedStyle(element);
                    const rect = element.getBoundingClientRect();
                    return style.visibility !== 'hidden' && style.display !== 'none' &&
                        rect.width > 0 && rect.height > 0;
                }).map(element => {
                    const id = element.getAttribute('data-agent-element-id') ||
                        'el-' + Math.random().toString(36).slice(2, 10);
                    element.setAttribute('data-agent-element-id', id);
                    const label = element.getAttribute('aria-label') ||
                        element.labels?.[0]?.innerText || element.innerText ||
                        element.getAttribute('name') || element.getAttribute('placeholder') || '';
                    return {
                        id,
                        role: element.getAttribute('role') || element.tagName.toLowerCase(),
                        accessible_name: label.trim().slice(0, 500),
                        text: (element.innerText || element.value || '').trim().slice(0, 1000),
                        tag_name: element.tagName.toLowerCase(),
                        attributes: {
                            name: element.getAttribute('name') || '',
                            type: element.getAttribute('type') || '',
                            href: element.getAttribute('href') || '',
                        },
                    };
                })"""
            )
            body_text = await page.locator("body").inner_text(timeout=self._timeout_ms)
            title = await page.title()
            elements = []
            forms = []
            links = []
            for item in raw:
                element = self._element(tab_id, item)
                elements.append(element)
                if item["tag_name"] == "a":
                    links.append(element)
                if item["tag_name"] in {"input", "select", "textarea"}:
                    field_type = item["attributes"].get("type") or item["tag_name"]
                    sensitive = field_type.lower() in {"password", "file"} or any(
                        word in element.accessible_name.text.lower()
                        for word in ("password", "secret", "otp", "token")
                    )
                    forms.append(
                        FormField(
                            id=element.id,
                            name=item["attributes"].get("name", ""),
                            field_type=field_type,
                            label=external_text(element.accessible_name.text, "form-label"),
                            value=redact_sensitive(item["text"], sensitive),
                            sensitive=sensitive,
                        )
                    )
            return BrowserObservation(
                tab=BrowserTab(self._tab(tab_id).id, self._tab(tab_id).session_id, page.url, title),
                visible_text=external_text(body_text[:20_000]),
                elements=tuple(elements),
                forms=tuple(forms),
                links=tuple(links),
            )
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE) from error

    async def click(self, tab_id: UUID, element_id: str) -> BrowserObservation:
        page = self._page(tab_id)
        try:
            await self._locator(tab_id, element_id).click()
            await self._settle(page)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.TRANSIENT) from error

    async def fill(self, tab_id: UUID, element_id: str, value: str, sensitive: bool = False) -> BrowserObservation:
        try:
            await self._locator(tab_id, element_id).fill(value)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.TRANSIENT) from error

    async def select_option(self, tab_id: UUID, element_id: str, option: str) -> BrowserObservation:
        try:
            await self._locator(tab_id, element_id).select_option(option)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.TRANSIENT) from error

    async def press_key(self, tab_id: UUID, element_id: str, key: str) -> BrowserObservation:
        try:
            await self._locator(tab_id, element_id).press(key)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.TRANSIENT) from error

    async def extract_text(self, tab_id: UUID) -> object:
        return (await self.observe(tab_id)).visible_text

    async def extract_links(self, tab_id: UUID) -> object:
        return (await self.observe(tab_id)).links

    async def wait(self, tab_id: UUID, seconds: float = 0.0) -> BrowserObservation:
        await asyncio.sleep(max(0.0, seconds))
        return await self.observe(tab_id)

    async def download(self, tab_id: UUID, selector: str | None = None) -> BrowserDownload:
        page = self._page(tab_id)
        target = page if selector is None else page.locator(selector)
        try:
            if selector is None:
                with page.expect_download() as expected:
                    await page.locator("a[download]").first.click()
                download = await expected.value
            else:
                with page.expect_download() as expected:
                    await target.click()
                download = await expected.value
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.TRANSIENT, "download not available") from error
        path = download.path()
        return BrowserDownload(
            filename=download.suggested_filename or download.filename,
            suggested_filename=download.suggested_filename,
            source_url=download.url,
            destination=str(path),
            size=None,
        )

    async def screenshot(self, tab_id: UUID) -> Screenshot:
        page = self._page(tab_id)
        try:
            data = await page.screenshot(type="png")
            return Screenshot(tab_id=tab_id, mime_type="image/png", data=data, url=page.url)
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE) from error

    async def get_current_url(self, tab_id: UUID) -> str:
        return str(self._page(tab_id).url)

    async def login(self, service: str) -> None:
        raise BrowserError(BrowserErrorKind.INVALID_ACTION, "interactive login is not implemented")

    async def use_authenticated_session(self, service: str) -> None:
        raise BrowserError(BrowserErrorKind.INVALID_ACTION, "credential use is not implemented")

    async def _history(self, tab_id: UUID, direction: str) -> NavigationResult:
        page = self._page(tab_id)
        try:
            result = await (page.go_back() if direction == "back" else page.go_forward())
            if result is not None:
                await result.wait_for_load_state("domcontentloaded", timeout=self._timeout_ms)
            return NavigationResult(self._refresh_tab(tab_id), True)
        except PlaywrightTimeoutError as error:
            raise BrowserError(BrowserErrorKind.NAVIGATION_TIMEOUT) from error
        except PlaywrightError as error:
            raise BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE) from error

    async def _settle(self, page: Page) -> None:
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=min(self._timeout_ms, 2_000))
        except PlaywrightError:
            pass
        await asyncio.sleep(0)

    def _register_page(self, session_id: UUID, page: Page) -> BrowserTab:
        tab = BrowserTab(uuid4(), session_id, page.url, "")
        self._pages[tab.id] = page
        self._tabs[tab.id] = tab
        self._tab_sessions[tab.id] = session_id
        self._element_selectors[tab.id] = {}
        return tab

    def _remove_tab(self, tab_id: UUID) -> None:
        self._pages.pop(tab_id, None)
        self._tabs.pop(tab_id, None)
        self._tab_sessions.pop(tab_id, None)
        self._element_selectors.pop(tab_id, None)

    def _context(self, session_id: UUID) -> BrowserContext:
        context = self._contexts.get(session_id)
        if context is None:
            raise BrowserError(BrowserErrorKind.SESSION, "browser session is not active")
        return context

    def _page(self, tab_id: UUID) -> Page:
        page = self._pages.get(tab_id)
        if page is None:
            raise BrowserError(BrowserErrorKind.SESSION, "browser tab is not active")
        return page

    def _tab(self, tab_id: UUID) -> BrowserTab:
        tab = self._tabs.get(tab_id)
        if tab is None:
            raise BrowserError(BrowserErrorKind.SESSION, "browser tab is not active")
        return tab

    def _refresh_tab(self, tab_id: UUID) -> BrowserTab:
        tab = self._tab(tab_id)
        refreshed = BrowserTab(tab.id, tab.session_id, str(self._page(tab_id).url), tab.title)
        self._tabs[tab_id] = refreshed
        return refreshed

    def _locator(self, tab_id: UUID, element_id: str) -> Any:
        selector = self._element_selectors.get(tab_id, {}).get(element_id)
        if selector is None:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND, "observed element is no longer available")
        return self._page(tab_id).locator(selector)

    def _element(self, tab_id: UUID, item: Mapping[str, Any]) -> BrowserElement:
        element_id = str(item["id"])
        # The generated ID is only an opaque handle; target selectors never enter model-visible data.
        self._element_selectors.setdefault(tab_id, {})[element_id] = (
            f'[data-agent-element-id="{element_id}"]'
        )
        field_type = str(item["attributes"].get("type") or item["tag_name"])
        accessible_name = str(item["accessible_name"])
        sensitive = field_type.lower() in {"password", "file"} or any(
            word in accessible_name.lower() for word in ("password", "secret", "otp", "token")
        )
        return BrowserElement(
            id=element_id,
            role=str(item["role"]),
            accessible_name=external_text(accessible_name, "accessible-name"),
            text=external_text(redact_sensitive(str(item["text"]), sensitive) or "", "element-text"),
            tag_name=str(item["tag_name"]),
            attributes={str(k): str(v) for k, v in item["attributes"].items() if v},
        )

class BrowserActionProvider(AsyncActionProvider):
    """Runtime bridge: browser actions are registered, then resolved after policy approval."""

    def __init__(self, browser: PlaywrightBrowserProvider, audit_sink: AuditSink | None = None) -> None:
        self.browser = browser
        self._audit = audit_sink
        self._actions: dict[str, tuple[BrowserAction, ActionRequest]] = {}
        self._active_task_ids: dict[UUID, UUID] = {}
        self._verifier: BrowserVerificationProvider | None = None
        self._recovery: BrowserRecoveryProvider | None = None

    def configure_safety(
        self,
        verifier: BrowserVerificationProvider | None = None,
        recovery: BrowserRecoveryProvider | None = None,
    ) -> None:
        self._verifier = verifier
        self._recovery = recovery

    def register(self, action: BrowserAction, task_id: UUID | None = None) -> ActionRequest:
        request = action.to_action_request(task_id)
        self._actions[str(action.id)] = (action, request)
        return request

    async def execute_async(self, request: ActionRequest) -> object:
        action_id = str(request.parameters.get("browser_action_id", ""))
        registered = self._actions.pop(action_id, None)
        if registered is None:
            raise BrowserError(BrowserErrorKind.INVALID_ACTION, "browser action is not registered")
        action, registered_request = registered
        self._active_task_ids[action.id] = registered_request.task_id
        self._audit_event("browser.action.started", action, {"risk": action.risk.value})
        result = await self._execute_with_recovery(action)
        if action.risk.value in {"high", "unknown"}:
            if self._verifier is None:
                raise BrowserError(BrowserErrorKind.INVALID_ACTION, "verification is required for consequential actions")
            verification = await self._verifier.verify(action, result)
            if not verification.verified:
                raise BrowserError(BrowserErrorKind.TRANSIENT, "browser state verification failed")
            self._audit_event("browser.action.verified", action, {"verified": True})
        self._audit_event("browser.action.completed", action, {"result": type(result).__name__})
        self._active_task_ids.pop(action.id, None)
        return result

    async def _execute_with_recovery(self, action: BrowserAction) -> object:
        for attempt in range(3):
            try:
                return await self._execute(action)
            except BrowserError as error:
                if self._recovery is None:
                    raise
                recovery = await self._recovery.recover(action.tab_id or action.session_id, error, attempt)
                self._audit_event("browser.recovery.attempted", action, {"attempt": attempt + 1})
                if not recovery.recovered or attempt >= 2:
                    raise
        raise BrowserError(BrowserErrorKind.UNKNOWN, "browser recovery exhausted")

    async def _execute(self, action: BrowserAction) -> object:
        tab_id = action.tab_id
        if action.type is BrowserActionType.NEW_TAB:
            return await self.browser.new_tab(action.session_id)
        if tab_id is None:
            raise BrowserError(BrowserErrorKind.INVALID_ACTION, "browser tab is required")
        if action.type is BrowserActionType.NAVIGATE:
            return await self.browser.navigate(tab_id, action.url or "")
        if action.type is BrowserActionType.GO_BACK:
            return await self.browser.go_back(tab_id)
        if action.type is BrowserActionType.GO_FORWARD:
            return await self.browser.go_forward(tab_id)
        if action.type is BrowserActionType.RELOAD:
            return await self.browser.reload(tab_id)
        if action.type is BrowserActionType.OBSERVE:
            return await self.browser.observe(tab_id)
        if action.type is BrowserActionType.CLICK:
            return await self.browser.click(tab_id, action.target_id or "")
        if action.type is BrowserActionType.FILL:
            return await self.browser.fill(tab_id, action.target_id or "", action.value or "", action.sensitive)
        if action.type is BrowserActionType.SELECT_OPTION:
            return await self.browser.select_option(tab_id, action.target_id or "", action.option or "")
        if action.type is BrowserActionType.PRESS_KEY:
            return await self.browser.press_key(tab_id, action.target_id or "", action.key or "")
        if action.type is BrowserActionType.EXTRACT_TEXT:
            return await self.browser.extract_text(tab_id)
        if action.type is BrowserActionType.EXTRACT_LINKS:
            return await self.browser.extract_links(tab_id)
        if action.type is BrowserActionType.WAIT:
            return await self.browser.wait(tab_id, float(action.value or "0"))
        if action.type is BrowserActionType.DOWNLOAD:
            return await self.browser.download(tab_id, action.target_id)
        if action.type is BrowserActionType.SCREENSHOT:
            return await self.browser.screenshot(tab_id)
        if action.type is BrowserActionType.CLOSE_TAB:
            await self.browser.close_tab(tab_id)
            return None
        if action.type is BrowserActionType.SUBMIT:
            return await self.browser.click(tab_id, action.target_id or "")
        raise BrowserError(BrowserErrorKind.INVALID_ACTION, "unsupported browser action")

    def _audit_event(self, event_type: str, action: BrowserAction, details: dict[str, object]) -> None:
        if self._audit is not None:
            from agent_core.models import AuditEvent

            task_id = self._active_task_ids.get(action.id, action.to_action_request().task_id)
            self._audit.record(AuditEvent(event_type, task_id, details=details))

"""Deterministic Playwright backend; Playwright types do not cross this module boundary."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit
from uuid import UUID, uuid4

from agent_core.secrets import Secret, sanitize_text

from .egress import BrowserEgressError, Socks5EgressProxy
from .models import (
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
        self._egress = Socks5EgressProxy()
        self._playwright: Any = None
        self._browser: Browser | None = None
        self._contexts: dict[UUID, BrowserContext] = {}
        self._sessions: dict[UUID, BrowserSession] = {}
        self._pages: dict[UUID, Page] = {}
        self._tabs: dict[UUID, BrowserTab] = {}
        self._tab_sessions: dict[UUID, UUID] = {}
        self._element_selectors: dict[UUID, dict[str, str]] = {}
        self._session_contexts: dict[UUID, BrowserContext] = {}
        self._sensitive_fields: set[tuple[UUID, str]] = set()
        self._element_metadata: dict[UUID, dict[str, dict[str, Any]]] = {}
        self._navigation_hosts: dict[UUID, str] = {}
        self._submission_permits: dict[UUID, tuple[str, str]] = {}

    async def start_session(self, persistent_state_path: str | None = None) -> BrowserSession:
        if persistent_state_path is not None:
            raise BrowserError(
                BrowserErrorKind.INVALID_ACTION,
                "persistent browser state is unsupported; use an in-memory session",
            )
        if self._playwright is None:
            await self._egress.start()
            self._playwright = await async_playwright().start()
        session = BrowserSession()
        if self._browser is None:
            self._browser = await self._playwright.chromium.launch(
                headless=self._headless,
                proxy={"server": self._egress.address},
                args=[
                    "--proxy-bypass-list=<-loopback>",
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--disable-quic",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                ],
            )
        context = await self._browser.new_context(
            accept_downloads=False,
            java_script_enabled=False,
            service_workers="block",
        )
        context.set_default_timeout(self._timeout_ms)
        await context.route("**/*", self._guard_request)
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
        if not self._contexts:
            await self._egress.close()

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
        host = _require_safe_https_url(url)
        self._navigation_hosts[tab_id] = host
        failure: BrowserError | None = None
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self._timeout_ms)
            return NavigationResult(self._refresh_tab(tab_id), True)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.NAVIGATION_TIMEOUT)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE)
        finally:
            self._navigation_hosts.pop(tab_id, None)
        if failure is not None:
            raise failure

    async def go_back(self, tab_id: UUID) -> NavigationResult:
        return await self._history(tab_id, "back")

    async def go_forward(self, tab_id: UUID) -> NavigationResult:
        return await self._history(tab_id, "forward")

    async def reload(self, tab_id: UUID) -> NavigationResult:
        page = self._page(tab_id)
        failure: BrowserError | None = None
        try:
            await page.reload(wait_until="domcontentloaded", timeout=self._timeout_ms)
            return NavigationResult(self._refresh_tab(tab_id), True)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.NAVIGATION_TIMEOUT)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE)
        if failure is not None:
            raise failure

    async def observe(self, tab_id: UUID) -> BrowserObservation:
        page = self._page(tab_id)
        failure: BrowserError | None = None
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
                        form: element.form ? {
                            action: element.getAttribute('formaction') ||
                                element.form.getAttribute('action') ||
                                element.form.action || '',
                            method: element.getAttribute('formmethod') ||
                                element.form.getAttribute('method') ||
                                element.form.method || 'get',
                        } : null,
                    };
                }).slice(0, 200)"""
            )
            body_text = await page.locator("body").evaluate(
                "element => (element.innerText || '').slice(0, 20000)"
            )
            title = await page.title()
            elements = []
            forms = []
            links = []
            self._element_metadata[tab_id] = {}
            self._element_selectors[tab_id] = {}
            for item in raw:
                element = self._element(tab_id, item)
                elements.append(element)
                if item["tag_name"] == "a":
                    links.append(element)
                if item["tag_name"] in {"input", "select", "textarea"}:
                    field_type = item["attributes"].get("type") or item["tag_name"]
                    sensitive = (
                        (tab_id, str(item["id"])) in self._sensitive_fields
                        or field_type.lower() in {"password", "file"}
                        or any(
                        word in element.accessible_name.text.lower()
                        for word in ("password", "secret", "otp", "token")
                        )
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
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE)
        if failure is not None:
            raise failure

    async def click(self, tab_id: UUID, element_id: str) -> BrowserObservation:
        page = self._page(tab_id)
        resolved = self._resolve_element(tab_id, element_id)
        if resolved is None:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        canonical_id, item = resolved
        if item.get("tag_name") == "a":
            href = item.get("attributes", {}).get("href", "")
            self._navigation_hosts[tab_id] = _require_safe_https_url(
                page.url if not href else _absolute_url(page.url, href)
            )
        elif item.get("attributes", {}).get("type", "").lower() == "submit":
            raise BrowserError(
                BrowserErrorKind.INVALID_ACTION,
                "form controls require the approval-gated submit operation",
            )
        failure: BrowserError | None = None
        try:
            await self._locator(tab_id, canonical_id).click()
            await self._settle(page)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.TRANSIENT)
        finally:
            self._navigation_hosts.pop(tab_id, None)
        if failure is not None:
            raise failure

    async def submit(self, tab_id: UUID, element_id: str) -> BrowserObservation:
        page = self._page(tab_id)
        resolved = self._resolve_element(tab_id, element_id)
        canonical_id, item = resolved if resolved is not None else ("", None)
        form = item.get("form") if item is not None else None
        if (
            not isinstance(form, dict)
            or item is None
            or item.get("tag_name") not in {"button", "input"}
            or (
                item.get("tag_name") == "input"
                and item.get("attributes", {}).get("type", "").lower() not in {"submit", "image"}
            )
            or (
                item.get("tag_name") == "button"
                and item.get("attributes", {}).get("type", "").lower() not in {"", "submit"}
            )
        ):
            raise BrowserError(BrowserErrorKind.INVALID_ACTION, "target is not a form submit control")
        method = str(form.get("method", "get")).upper()
        destination = _absolute_url(page.url, str(form.get("action") or page.url))
        _require_safe_https_url(destination)
        if method not in {"GET", "POST"}:
            raise BrowserError(BrowserErrorKind.INVALID_ACTION, "unsupported form method")
        self._submission_permits[tab_id] = (method, destination)
        failure: BrowserError | None = None
        try:
            await self._locator(tab_id, canonical_id).click()
            await self._settle(page)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.TRANSIENT)
        finally:
            self._submission_permits.pop(tab_id, None)
        if failure is not None:
            raise failure

    async def fill(self, tab_id: UUID, element_id: str, value: str, sensitive: bool = False) -> BrowserObservation:
        resolved = self._resolve_element(tab_id, element_id)
        if resolved is None:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        canonical_id, item = resolved
        field_type = str(item.get("attributes", {}).get("type", "")).lower()
        label = str(item.get("accessible_name", "")).lower()
        if (
            sensitive
            or len(value) > 2000
            or field_type in {"password", "file", "hidden"}
            or any(word in label for word in ("password", "secret", "otp", "token"))
        ):
            raise BrowserError(
                BrowserErrorKind.INVALID_ACTION,
                "sensitive or non-text browser fields cannot be filled",
            )
        if sensitive:
            self._sensitive_fields.add((tab_id, canonical_id))
        failure: BrowserError | None = None
        try:
            await self._locator(tab_id, canonical_id).fill(value)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.TRANSIENT)
        if failure is not None:
            raise failure

    async def select_option(self, tab_id: UUID, element_id: str, option: str) -> BrowserObservation:
        failure: BrowserError | None = None
        try:
            await self._locator(tab_id, element_id).select_option(option)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.TRANSIENT)
        if failure is not None:
            raise failure

    async def press_key(self, tab_id: UUID, element_id: str, key: str) -> BrowserObservation:
        failure: BrowserError | None = None
        try:
            await self._locator(tab_id, element_id).press(key)
            return await self.observe(tab_id)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.TRANSIENT)
        if failure is not None:
            raise failure

    async def extract_text(self, tab_id: UUID) -> object:
        return (await self.observe(tab_id)).visible_text

    async def extract_links(self, tab_id: UUID) -> object:
        return (await self.observe(tab_id)).links

    async def wait(self, tab_id: UUID, seconds: float = 0.0) -> BrowserObservation:
        if not 0 <= seconds <= 2:
            raise BrowserError(BrowserErrorKind.INVALID_ACTION, "browser wait must be between 0 and 2 seconds")
        await asyncio.sleep(seconds)
        return await self.observe(tab_id)

    async def download(self, tab_id: UUID, selector: str | None = None) -> BrowserDownload:
        raise BrowserError(BrowserErrorKind.INVALID_ACTION, "browser downloads are disabled")

    async def screenshot(self, tab_id: UUID) -> Screenshot:
        page = self._page(tab_id)
        failure: BrowserError | None = None
        try:
            data = await page.screenshot(type="png")
            return Screenshot(
                tab_id=tab_id,
                mime_type="image/png",
                data=Secret(data),
                url=page.url,
            )
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE)
        if failure is not None:
            raise failure

    async def get_current_url(self, tab_id: UUID) -> str:
        return sanitize_text(str(self._page(tab_id).url))

    async def login(self, service: str) -> None:
        raise BrowserError(BrowserErrorKind.INVALID_ACTION, "interactive login is not implemented")

    async def use_authenticated_session(self, service: str) -> None:
        raise BrowserError(BrowserErrorKind.INVALID_ACTION, "credential use is not implemented")

    async def _history(self, tab_id: UUID, direction: str) -> NavigationResult:
        page = self._page(tab_id)
        failure: BrowserError | None = None
        try:
            result = await (page.go_back() if direction == "back" else page.go_forward())
            if result is not None:
                await result.wait_for_load_state("domcontentloaded", timeout=self._timeout_ms)
            return NavigationResult(self._refresh_tab(tab_id), True)
        except PlaywrightTimeoutError:
            failure = BrowserError(BrowserErrorKind.NAVIGATION_TIMEOUT)
        except PlaywrightError:
            failure = BrowserError(BrowserErrorKind.PAGE_LOAD_FAILURE)
        if failure is not None:
            raise failure

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
        self._element_metadata.pop(tab_id, None)
        self._navigation_hosts.pop(tab_id, None)
        self._submission_permits.pop(tab_id, None)
        self._sensitive_fields = {
            item for item in self._sensitive_fields if item[0] != tab_id
        }

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
            matches = [
                item_id
                for item_id, item in self._element_metadata.get(tab_id, {}).items()
                if item_id == element_id
                or item.get("attributes", {}).get("name") == element_id
                or item.get("accessible_name") == element_id
            ]
            if len(matches) == 1:
                selector = self._element_selectors[tab_id][matches[0]]
        if selector is None:
            raise BrowserError(BrowserErrorKind.ELEMENT_NOT_FOUND, "observed element is no longer available")
        return self._page(tab_id).locator(selector)

    def _resolve_element(
        self, tab_id: UUID, target: str
    ) -> tuple[str, dict[str, Any]] | None:
        metadata = self._element_metadata.get(tab_id, {})
        exact = metadata.get(target)
        if exact is not None:
            return target, exact
        matches = [
            (element_id, item)
            for element_id, item in metadata.items()
            if item.get("attributes", {}).get("name") == target
            or item.get("accessible_name") == target
        ]
        return matches[0] if len(matches) == 1 else None

    def _element(self, tab_id: UUID, item: Mapping[str, Any]) -> BrowserElement:
        element_id = str(item["id"])
        self._element_metadata.setdefault(tab_id, {})[element_id] = dict(item)
        # The generated ID is only an opaque handle; target selectors never enter model-visible data.
        self._element_selectors.setdefault(tab_id, {})[element_id] = (
            f'[data-agent-element-id="{element_id}"]'
        )
        field_type = str(item["attributes"].get("type") or item["tag_name"])
        accessible_name = str(item["accessible_name"])
        sensitive = field_type.lower() in {"password", "file"} or any(
            word in accessible_name.lower() for word in ("password", "secret", "otp", "token")
        ) or (tab_id, element_id) in self._sensitive_fields
        return BrowserElement(
            id=element_id,
            role=str(item["role"]),
            accessible_name=external_text(accessible_name, "accessible-name"),
            text=external_text(redact_sensitive(str(item["text"]), sensitive) or "", "element-text"),
            tag_name=str(item["tag_name"]),
            attributes={str(k): str(v) for k, v in item["attributes"].items() if v},
        )

    async def _guard_request(self, route: Any) -> None:
        if not self._request_is_allowed(route):
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    def _request_is_allowed(self, route: Any) -> bool:
        request = route.request
        try:
            host = _require_safe_https_url(request.url)
        except BrowserEgressError:
            return False
        if request.frame != request.frame.page.main_frame:
            return False
        tab_id = next(
            (identifier for identifier, page in self._pages.items() if page is request.frame.page),
            None,
        )
        if tab_id is None:
            return False
        method = request.method.upper()
        permitted_host = self._navigation_hosts.get(tab_id)
        permit = self._submission_permits.get(tab_id)
        if (
            method in {"GET", "HEAD"}
            and request.resource_type == "document"
            and permitted_host == host
        ):
            return True
        if (
            permit is not None
            and method == permit[0]
            and _matches_submission_destination(method, request.url, permit[1])
            and request.resource_type == "document"
        ):
            self._submission_permits.pop(tab_id, None)
            return True
        return False


def _matches_submission_destination(method: str, request_url: str, permitted_url: str) -> bool:
    try:
        request = urlsplit(request_url)
        permitted = urlsplit(permitted_url)
        request_host = _require_safe_https_url(request_url)
        permitted_host = _require_safe_https_url(permitted_url)
        if (
            request_host != permitted_host
            or request.port not in {None, 443}
            or permitted.port not in {None, 443}
            or request.path != permitted.path
            or request.username is not None
            or request.password is not None
        ):
            return False
        if method == "GET":
            return set(parse_qsl(permitted.query, keep_blank_values=True)).issubset(
                set(parse_qsl(request.query, keep_blank_values=True))
            )
        return request.query == permitted.query
    except (BrowserEgressError, ValueError):
        return False


def _require_safe_https_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise BrowserEgressError("browser destination is invalid") from error
    if (
        parsed.scheme.lower() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or host.rstrip(".").lower() == "localhost"
        or host.rstrip(".").lower().endswith((".localhost", ".local", ".internal"))
    ):
        raise BrowserEgressError("browser navigation requires a public HTTPS destination")
    try:
        literal = ipaddress.ip_address(host.rstrip("."))
    except ValueError:
        literal = None
    if literal is not None and (
        getattr(literal, "ipv4_mapped", None) is not None or not literal.is_global
    ):
        raise BrowserEgressError("browser destination must resolve to public addresses")
    try:
        return host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise BrowserEgressError("browser destination is invalid") from error


def _absolute_url(base: str, value: str) -> str:
    return urljoin(base, value)

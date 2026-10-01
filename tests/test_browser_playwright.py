import asyncio
import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from browser.models import (
    BrowserAction,
    BrowserActionType,
    BrowserError,
    BrowserErrorKind,
    TrustBoundary,
)
from browser.playwright_provider import PlaywrightBrowserProvider
from browser.recovery import BoundedBrowserRecovery


@pytest.fixture
def fixture_server():
    directory = str(Path(__file__).parent / "fixtures")
    handler = functools.partial(SimpleHTTPRequestHandler, directory=directory)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def run(coro):
    return asyncio.run(coro)


def test_playwright_provider_local_browser_flow(fixture_server):
    async def scenario():
        browser = PlaywrightBrowserProvider()
        session = await browser.start_session()
        tab = await browser.new_tab(session.id)
        await browser.navigate(tab.id, f"{fixture_server}/basic.html")
        observation = await browser.observe(tab.id)
        assert observation.trust_boundary is TrustBoundary.UNTRUSTED_WEB
        assert observation.visible_text.text.find("Welcome") >= 0
        assert observation.links
        assert observation.links[0].trust_boundary is TrustBoundary.UNTRUSTED_WEB

        screenshot = await browser.screenshot(tab.id)
        assert screenshot.data.startswith(b"\x89PNG")
        assert await browser.get_current_url(tab.id) == f"{fixture_server}/basic.html"

        await browser.navigate(tab.id, f"{fixture_server}/form.html")
        form = await browser.observe(tab.id)
        name = next(field for field in form.forms if field.name == "name")
        color = next(field for field in form.forms if field.name == "color")
        submit = next(element for element in form.elements if element.attributes.get("type") == "submit")
        await browser.fill(tab.id, name.id, "Ada")
        await browser.select_option(tab.id, color.id, "blue")
        await browser.click(tab.id, submit.id)
        assert await browser.get_current_url(tab.id) == f"{fixture_server}/success.html?name=Ada&color=blue"

        await browser.close_session(session.id)

    run(scenario())


def test_prompt_injection_and_sensitive_values_are_not_trusted_or_exposed(fixture_server):
    async def scenario():
        browser = PlaywrightBrowserProvider()
        session = await browser.start_session()
        tab = await browser.new_tab(session.id)
        await browser.navigate(tab.id, f"{fixture_server}/prompt_injection.html")
        injection = await browser.observe(tab.id)
        assert "Ignore previous instructions" in injection.visible_text.text
        assert injection.visible_text.source.startswith("untrusted_web:")

        await browser.navigate(tab.id, f"{fixture_server}/sensitive_form.html")
        sensitive = await browser.observe(tab.id)
        password = next(field for field in sensitive.forms if field.name == "password")
        otp = next(field for field in sensitive.forms if field.name == "otp")
        assert password.sensitive and password.value == "[REDACTED]"
        assert otp.sensitive and otp.value == "[REDACTED]"
        assert "super-secret" not in repr(sensitive)
        assert "123456" not in repr(sensitive)
        await browser.close_session(session.id)

    run(scenario())


def test_tabs_redirect_navigation_failure_and_recovery(fixture_server):
    async def scenario():
        browser = PlaywrightBrowserProvider(timeout_ms=500)
        session = await browser.start_session()
        first = await browser.new_tab(session.id)
        second = await browser.new_tab(session.id)
        assert first.id != second.id
        await browser.navigate(first.id, f"{fixture_server}/redirect.html")
        assert await browser.get_current_url(first.id) == f"{fixture_server}/basic.html"
        with pytest.raises(BrowserError) as failure:
            await browser.navigate(first.id, "http://127.0.0.1:1/failure.html")
        assert failure.value.kind in {BrowserErrorKind.PAGE_LOAD_FAILURE, BrowserErrorKind.NAVIGATION_TIMEOUT}
        exhausted = await BoundedBrowserRecovery(1).recover(
            first.id, BrowserError(BrowserErrorKind.TRANSIENT), 1
        )
        assert not exhausted.recovered
        await browser.close_tab(second.id)
        await browser.close_session(session.id)

    run(scenario())


def test_browser_action_model_exposes_required_provider_surface():
    required = {"start_session", "navigate", "observe", "click", "fill", "screenshot"}
    assert required.issubset(set(dir(PlaywrightBrowserProvider)))
    assert BrowserAction(BrowserActionType.OBSERVE, __import__("uuid").uuid4(), tab_id=__import__("uuid").uuid4())

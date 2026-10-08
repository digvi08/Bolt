import asyncio
import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agent_core.api import _jsonable
from agent_core.secrets import REDACTED, Secret, sanitize_value
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
        assert isinstance(screenshot.data, Secret)
        assert screenshot.data.reveal(purpose="test image validation").startswith(b"\x89PNG")
        assert sanitize_value(screenshot)["data"] == REDACTED
        assert await browser.get_current_url(tab.id) == f"{fixture_server}/basic.html"

        await browser.navigate(tab.id, f"{fixture_server}/form.html")
        form = await browser.observe(tab.id)
        name = next(field for field in form.forms if field.name == "name")
        color = next(field for field in form.forms if field.name == "color")
        submit = next(element for element in form.elements if element.attributes.get("type") == "submit")
        filled = await browser.fill(tab.id, name.id, "Ada", sensitive=True)
        assert next(field for field in filled.forms if field.name == "name").value == "[REDACTED]"
        await browser.select_option(tab.id, color.id, "blue")
        await browser.click(tab.id, submit.id)
        assert await browser.get_current_url(tab.id) == f"{fixture_server}/success.html?name=Ada&color=blue"

        await browser.close_session(session.id)

    run(scenario())


def test_persistent_profile_request_fails_before_touching_disk(tmp_path):
    async def scenario():
        browser = PlaywrightBrowserProvider()
        state_path = tmp_path / "arbitrary-auth-profile"
        with pytest.raises(BrowserError) as failure:
            await browser.start_session(str(state_path))
        assert failure.value.kind is BrowserErrorKind.INVALID_ACTION
        assert browser._playwright is None
        assert not state_path.exists()

    run(scenario())


def test_browser_content_urls_errors_and_screenshots_are_sanitized_or_opaque(fixture_server):
    async def scenario():
        secret = "browser-secret-124a"
        browser = PlaywrightBrowserProvider()
        session = await browser.start_session()
        tab = await browser.new_tab(session.id)
        await browser.navigate(
            tab.id,
            f"{fixture_server}/basic.html?access_token={secret}",
        )
        page = browser._page(tab.id)
        await page.evaluate(
            "(value) => { localStorage.setItem('access_token', value); "
            "sessionStorage.setItem('cookie', value); }",
            secret,
        )
        await page.evaluate(
            "(value) => { document.body.innerText += "
            "` password=${value} authorization=Bearer ${value}`; }",
            secret,
        )
        observation = await browser.observe(tab.id)
        screenshot = await browser.screenshot(tab.id)
        error = BrowserError(
            BrowserErrorKind.UNKNOWN,
            f"cookie={secret}",
        )

        assert secret not in observation.visible_text.text
        assert secret not in observation.tab.url
        assert secret not in await browser.get_current_url(tab.id)
        assert secret not in repr(sanitize_value(observation))
        assert isinstance(screenshot.data, Secret)
        assert secret not in repr(screenshot)
        assert sanitize_value(screenshot)["data"] == REDACTED
        assert _jsonable(screenshot)["data"] == REDACTED
        assert secret not in str(error)
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
        assert failure.value.__context__ is None
        assert failure.value.__cause__ is None
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

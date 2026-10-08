from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from agent_brain.model_router import ModelRouter
from agent_core.api import _jsonable
from agent_core.application import AgentApplication
from agent_core.config import AgentConfig
from agent_core.models import ActionKind, RiskLevel, TaskStatus
from agent_core.secrets import REDACTED, Secret, sanitize_value
from agent_core.service import SubmitTaskRequest
from browser.ability import BrowserAbilityProvider
from browser.egress import BrowserEgressError
from browser.models import BrowserError, BrowserErrorKind, TrustBoundary
from browser.playwright_provider import PlaywrightBrowserProvider
from browser.recovery import BoundedBrowserRecovery

FIXTURE_HOST = "fixture.example"
FIXTURE_ORIGIN = f"https://{FIXTURE_HOST}"
FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures"


class FixturePlaywrightBrowserProvider(PlaywrightBrowserProvider):
    """Serve committed HTML fixtures in memory without adding a network bypass."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.blocked_requests: list[str] = []
        self.submissions: list[dict[str, list[str]]] = []
        self.route_calls: list[tuple[str, str, bool, object]] = []

    async def _guard_request(self, route: Any) -> None:
        request_url = route.request.url
        parsed = urlsplit(request_url)
        if parsed.hostname != FIXTURE_HOST:
            self.route_calls.append((request_url, route.request.resource_type, False, None))
            if parsed.hostname in {"127.0.0.1", "::1"}:
                self.blocked_requests.append(request_url)
            await super()._guard_request(route)
            return
        allowed = self._request_is_allowed(route)
        self.route_calls.append(
            (
                request_url,
                route.request.resource_type,
                allowed,
                dict(self._submission_permits),
            )
        )
        if not allowed:
            await route.abort("blockedbyclient")
            return
        if parsed.path == "/redirect.html":
            await route.fulfill(
                status=200,
                content_type="text/html",
                body=f'<meta http-equiv="refresh" content="0;url={FIXTURE_ORIGIN}/basic.html">',
            )
            return
        if parsed.path == "/unsafe-redirect.html":
            await route.fulfill(
                status=200,
                content_type="text/html",
                body='<meta http-equiv="refresh" content="0;url=http://127.0.0.1:8123/private">',
            )
            return
        if parsed.path == "/success.html":
            self.submissions.append(parse_qs(parsed.query))
            body = "<!doctype html><title>Success</title><p>Submitted successfully</p>"
        else:
            filename = parsed.path.lstrip("/") or "basic.html"
            if Path(filename).name != filename:
                await route.abort("blockedbyclient")
                return
            fixture = FIXTURE_DIRECTORY / filename
            if not fixture.is_file():
                await route.fulfill(status=404, body="Not found")
                return
            body = fixture.read_text(encoding="utf-8")
        await route.fulfill(
            status=200,
            content_type="text/html; charset=utf-8",
            body=body,
        )


def run(coro):
    return asyncio.run(coro)


def test_playwright_provider_local_fixture_flow_and_form_verification():
    async def scenario():
        browser = FixturePlaywrightBrowserProvider()
        session = await browser.start_session()
        tab = await browser.new_tab(session.id)
        navigation = await browser.navigate(tab.id, f"{FIXTURE_ORIGIN}/basic.html")
        observation = await browser.observe(tab.id)
        assert navigation.succeeded
        assert observation.trust_boundary is TrustBoundary.UNTRUSTED_WEB
        assert "Welcome" in observation.visible_text.text
        assert observation.links
        assert observation.links[0].trust_boundary is TrustBoundary.UNTRUSTED_WEB

        screenshot = await browser.screenshot(tab.id)
        assert isinstance(screenshot.data, Secret)
        assert screenshot.data.reveal(purpose="test image validation").startswith(b"\x89PNG")
        assert sanitize_value(screenshot)["data"] == REDACTED
        assert await browser.get_current_url(tab.id) == f"{FIXTURE_ORIGIN}/basic.html"

        await browser.navigate(tab.id, f"{FIXTURE_ORIGIN}/form.html")
        form = await browser.observe(tab.id)
        name = next(field for field in form.forms if field.name == "name")
        submit = next(element for element in form.elements if element.id == "submit-button")
        filled = await browser.fill(tab.id, name.id, "Ada")
        assert next(field for field in filled.forms if field.name == "name").value == "Ada"
        try:
            submitted = await browser.submit(tab.id, submit.id)
        except BrowserError as error:
            pytest.fail(f"{error}; requests={browser.route_calls!r}")
        assert "Submitted successfully" in submitted.visible_text.text
        assert browser.submissions == [{"name": ["Ada"], "color": ["red"]}]

        await browser.close_session(session.id)

    run(scenario())


def test_persistent_profile_request_fails_before_touching_disk(tmp_path):
    async def scenario():
        browser = FixturePlaywrightBrowserProvider()
        state_path = tmp_path / "arbitrary-auth-profile"
        with pytest.raises(BrowserError) as failure:
            await browser.start_session(str(state_path))
        assert failure.value.kind is BrowserErrorKind.INVALID_ACTION
        assert browser._playwright is None
        assert not state_path.exists()

    run(scenario())


def test_browser_content_urls_errors_and_screenshots_are_sanitized_or_opaque():
    async def scenario():
        secret = "browser-secret-124a"
        browser = FixturePlaywrightBrowserProvider()
        session = await browser.start_session()
        tab = await browser.new_tab(session.id)
        await browser.navigate(
            tab.id,
            f"{FIXTURE_ORIGIN}/basic.html?access_token={secret}",
        )
        observation = await browser.observe(tab.id)
        screenshot = await browser.screenshot(tab.id)
        error = BrowserError(BrowserErrorKind.UNKNOWN, f"cookie={secret}")

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


def test_prompt_injection_is_untrusted_and_sensitive_fields_are_redacted():
    async def scenario():
        browser = FixturePlaywrightBrowserProvider()
        session = await browser.start_session()
        tab = await browser.new_tab(session.id)
        await browser.navigate(tab.id, f"{FIXTURE_ORIGIN}/prompt_injection.html")
        injection = await browser.observe(tab.id)
        assert "Ignore previous instructions" in injection.visible_text.text
        assert injection.visible_text.source.startswith("untrusted_web:")
        assert injection.trust_boundary is TrustBoundary.UNTRUSTED_WEB

        await browser.navigate(tab.id, f"{FIXTURE_ORIGIN}/sensitive_form.html")
        sensitive = await browser.observe(tab.id)
        password = next(field for field in sensitive.forms if field.name == "password")
        otp = next(field for field in sensitive.forms if field.name == "otp")
        assert password.sensitive and password.value == "[REDACTED]"
        assert otp.sensitive and otp.value == "[REDACTED]"
        assert "super-secret" not in repr(sensitive)
        assert "123456" not in repr(sensitive)
        with pytest.raises(BrowserError, match="sensitive or non-text"):
            await browser.fill(tab.id, password.id, "not-allowed")
        await browser.close_session(session.id)

    run(scenario())


def test_redirects_and_private_destinations_fail_closed():
    async def scenario():
        browser = FixturePlaywrightBrowserProvider(timeout_ms=500)
        session = await browser.start_session()
        first = await browser.new_tab(session.id)
        second = await browser.new_tab(session.id)
        assert first.id != second.id

        try:
            await browser.navigate(first.id, f"{FIXTURE_ORIGIN}/redirect.html")
        except BrowserError as error:
            pytest.fail(f"{error}; requests={browser.route_calls!r}")
        assert await browser.get_current_url(first.id) == f"{FIXTURE_ORIGIN}/redirect.html"

        with pytest.raises(BrowserEgressError, match="public"):
            await browser.navigate(first.id, "https://127.0.0.1/private")
        with pytest.raises(BrowserEgressError, match="public"):
            await browser.navigate(first.id, "https://[::1]/private")

        await browser.navigate(first.id, f"{FIXTURE_ORIGIN}/unsafe-redirect.html")
        await asyncio.sleep(0.1)
        assert "127.0.0.1" in "".join(browser.blocked_requests)
        assert "127.0.0.1" not in await browser.get_current_url(first.id)

        exhausted = await BoundedBrowserRecovery(1).recover(
            first.id, BrowserError(BrowserErrorKind.TRANSIENT), 1
        )
        assert not exhausted.recovered
        await browser.close_tab(second.id)
        await browser.close_session(session.id)

    run(scenario())


def test_browser_ability_exposes_only_registered_restricted_actions():
    provider = BrowserAbilityProvider(FixturePlaywrightBrowserProvider())
    assert set(provider.descriptor.supported_actions) == {
        "navigate",
        "inspect",
        "extract",
        "click",
        "fill",
        "wait",
        "submit",
    }
    assert provider.risk_for("submit").value == "high"
    assert provider.risk_for("click").value == "high"
    assert not provider.supports("evaluate")
    assert not provider.supports("download")
    assert not provider.supports("execute_javascript")


def test_browser_action_model_exposes_restricted_provider_surface():
    required = {"start_session", "navigate", "observe", "click", "fill", "screenshot"}
    assert required.issubset(set(dir(PlaywrightBrowserProvider)))


class BrowserWorkflowModel:
    name = "browser-fixture"
    model_name = "browser-workflow-fixture"
    capabilities = ("structured", "text")

    def __init__(self, plan: dict[str, Any]) -> None:
        self.responses = [plan, {"steps": []}]
        self.structured_calls = 0

    def structured_generate(self, _prompt, _schema, *, system=None):
        self.structured_calls += 1
        return self.responses.pop(0)

    def generate(self, _prompt, *, system=None, max_tokens=None):
        return "The requested form submission was verified."


def browser_workflow_plan() -> dict[str, Any]:
    return {
        "steps": [
            {
                "ability": "browser",
                "action": "navigate",
                "arguments": {"url": f"{FIXTURE_ORIGIN}/form.html"},
            },
            {"ability": "browser", "action": "inspect", "arguments": {}},
            {
                "ability": "browser",
                "action": "fill",
                "arguments": {"target_id": "name-field", "value": "Ada"},
            },
            {
                "ability": "browser",
                "action": "submit",
                "arguments": {
                    "target_id": "submit-button",
                    "expected_text": "Submitted successfully",
                },
            },
        ]
    }


def test_browser_task_uses_agent_runtime_and_durable_approval(monkeypatch, tmp_path):
    import browser.ability as browser_ability

    monkeypatch.setattr(
        browser_ability,
        "PlaywrightBrowserProvider",
        FixturePlaywrightBrowserProvider,
    )
    model = BrowserWorkflowModel(browser_workflow_plan())
    app = AgentApplication(
        tmp_path / "browser-agent.sqlite3",
        config=AgentConfig(
            allowed_actions=frozenset({ActionKind.BROWSER}),
            approval_required_at=RiskLevel.HIGH,
            enable_external_integrations=True,
            max_model_calls=3,
            max_tool_calls=4,
        ),
        model_router=ModelRouter(
            providers=[model],
            fallback_to_deterministic=False,
            max_model_calls=3,
        ),
    )
    try:
        app.start()
        result = app.service.submit_task(
            SubmitTaskRequest(
                "Open the fixture form, fill the name with Ada, and submit after approval."
            )
        )
        assert not result.success
        assert result.task.status is TaskStatus.AWAITING_APPROVAL
        assert app._browser_ability is not None
        fixture_browser = app._browser_ability.browser
        assert fixture_browser.submissions == []

        approvals = app.service.list_approvals()
        assert len(approvals) == 1
        assert approvals[0].status.value == "pending"
        approved = app.service.approve_approval(
            approvals[0].approval_id,
            actor="operator",
        )
        assert approved.resumed
        assert approved.task is not None
        assert approved.task.status is TaskStatus.SUCCEEDED
        assert fixture_browser.submissions == [{"name": ["Ada"], "color": ["red"]}]
        action_records = app.store.list_actions(result.task.task_id)
        assert len(action_records) == 4
        assert all(record.verification_status.value == "verified" for record in action_records)
        assert app.service.list_approvals()[0].status.value == "consumed"
        assert model.structured_calls == 2
    finally:
        asyncio.run(app.shutdown())


def test_browser_click_is_runtime_authorized_and_verified_after_approval(
    monkeypatch, tmp_path
):
    import browser.ability as browser_ability

    monkeypatch.setattr(
        browser_ability,
        "PlaywrightBrowserProvider",
        FixturePlaywrightBrowserProvider,
    )
    model = BrowserWorkflowModel(
        {
            "steps": [
                {
                    "ability": "browser",
                    "action": "navigate",
                    "arguments": {"url": f"{FIXTURE_ORIGIN}/basic.html"},
                },
                {"ability": "browser", "action": "inspect", "arguments": {}},
                {
                    "ability": "browser",
                    "action": "click",
                    "arguments": {"target_id": "Form", "expected_text": "Name"},
                },
            ]
        }
    )
    app = AgentApplication(
        tmp_path / "browser-click.sqlite3",
        config=AgentConfig(
            allowed_actions=frozenset({ActionKind.BROWSER}),
            approval_required_at=RiskLevel.HIGH,
            enable_external_integrations=True,
            max_model_calls=3,
            max_tool_calls=3,
        ),
        model_router=ModelRouter(
            providers=[model],
            fallback_to_deterministic=False,
            max_model_calls=3,
        ),
    )
    try:
        app.start()
        result = app.service.submit_task(
            SubmitTaskRequest(f"Open {FIXTURE_ORIGIN}/basic.html and open the Form link.")
        )
        assert not result.success
        assert result.task.status is TaskStatus.AWAITING_APPROVAL
        assert app._browser_ability is not None
        approvals = app.service.list_approvals()
        assert len(approvals) == 1
        assert approvals[0].action_kind == str(ActionKind.BROWSER)

        approved = app.service.approve_approval(
            approvals[0].approval_id,
            actor="operator",
        )
        assert approved.task is not None
        assert approved.task.status is TaskStatus.SUCCEEDED, [
            (action.name, action.status, action.outcome)
            for action in app.store.list_actions(result.task.task_id)
        ]
        assert isinstance(app._browser_ability.browser, FixturePlaywrightBrowserProvider)
        assert any(
            url.endswith("/form.html")
            for url, _resource_type, _allowed, _permits
            in app._browser_ability.browser.route_calls
        )
        actions = app.store.list_actions(result.task.task_id)
        assert len(actions) == 3
        assert all(action.verification_status.value == "verified" for action in actions)
    finally:
        asyncio.run(app.shutdown())


def test_pending_browser_action_after_restart_fails_closed(monkeypatch, tmp_path):
    import browser.ability as browser_ability

    monkeypatch.setattr(
        browser_ability,
        "PlaywrightBrowserProvider",
        FixturePlaywrightBrowserProvider,
    )
    model = BrowserWorkflowModel(browser_workflow_plan())
    config = AgentConfig(
        allowed_actions=frozenset({ActionKind.BROWSER}),
        approval_required_at=RiskLevel.HIGH,
        enable_external_integrations=True,
        max_model_calls=3,
        max_tool_calls=4,
    )
    database_path = tmp_path / "browser-restart.sqlite3"
    first = AgentApplication(
        database_path,
        config=config,
        model_router=ModelRouter(
            providers=[model],
            fallback_to_deterministic=False,
            max_model_calls=3,
        ),
    )
    try:
        first.start()
        result = first.service.submit_task(
            SubmitTaskRequest(
                "Open the fixture form, fill the name with Ada, and submit after approval."
            )
        )
        assert result.task.status is TaskStatus.AWAITING_APPROVAL
        assert first._browser_ability is not None
        first_browser = first._browser_ability.browser
        assert isinstance(first_browser, FixturePlaywrightBrowserProvider)
        assert first_browser.submissions == []
        pending = first.service.list_approvals()
        assert len(pending) == 1
    finally:
        asyncio.run(first.shutdown())

    restarted = AgentApplication(
        database_path,
        config=config,
        model_router=ModelRouter(
            providers=[model],
            fallback_to_deterministic=False,
            max_model_calls=3,
        ),
    )
    try:
        restarted.start()
        assert restarted._browser_ability is not None
        new_browser = restarted._browser_ability.browser
        assert isinstance(new_browser, FixturePlaywrightBrowserProvider)
        resumed = restarted.service.approve_approval(
            pending[0].approval_id,
            actor="operator",
        )
        assert resumed.task is not None
        assert resumed.task.status is TaskStatus.FAILED
        assert resumed.task.uncertain
        assert new_browser.submissions == []
        assert all(
            action.verification_status.value != "verified"
            for action in restarted.store.list_actions(result.task.task_id)
            if action.name == "browser.submit"
        )
    finally:
        asyncio.run(restarted.shutdown())


def test_browser_execution_is_blocked_by_persistent_kill_switch(monkeypatch, tmp_path):
    import browser.ability as browser_ability

    monkeypatch.setattr(
        browser_ability,
        "PlaywrightBrowserProvider",
        FixturePlaywrightBrowserProvider,
    )
    model = BrowserWorkflowModel({"steps": []})
    app = AgentApplication(
        tmp_path / "browser-kill-switch.sqlite3",
        config=AgentConfig(
            allowed_actions=frozenset({ActionKind.BROWSER}),
            enable_external_integrations=True,
        ),
        model_router=ModelRouter(
            providers=[model],
            fallback_to_deterministic=False,
            max_model_calls=2,
        ),
    )
    try:
        app.start()
        app.set_kill_switch_active(True)
        result = app.service.submit_task(
            SubmitTaskRequest(f"Open {FIXTURE_ORIGIN}/basic.html.")
        )
        assert not result.success
        assert "kill switch" in (result.error.message if result.error else "")
        assert model.structured_calls == 0
        assert app._browser_ability is not None
        assert app._browser_ability._states == {}
    finally:
        asyncio.run(app.shutdown())

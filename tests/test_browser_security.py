from __future__ import annotations

import asyncio

import pytest

from abilities.registry import AbilityRegistry
from agent_brain.executor import AgentExecutionLoop
from agent_core.config import AgentConfig
from agent_core.models import ActionKind
from browser.ability import BrowserAbilityProvider
from browser.egress import BrowserEgressError, Socks5EgressProxy, resolve_public_addresses
from browser.playwright_provider import _require_safe_https_url


class Switch:
    def __init__(self, engaged: bool = False) -> None:
        self.engaged = engaged

    def is_engaged(self) -> bool:
        return self.engaged


class Audit:
    def record(self, _event) -> None:
        return None


class NeverBrowser:
    def __init__(self) -> None:
        self.calls = 0

    async def start_session(self):
        self.calls += 1
        raise AssertionError("browser must not start while the kill switch is engaged")


def test_browser_kill_switch_blocks_the_agent_execution_path():
    browser = NeverBrowser()
    provider = BrowserAbilityProvider(browser)  # type: ignore[arg-type]
    registry = AbilityRegistry()
    registry.register(provider)
    loop = AgentExecutionLoop(
        registry=registry,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        audit_sink=Audit(),
        kill_switch=Switch(True),
    )
    result = loop.run("Open the browser and inspect the page.")
    assert not result.success
    assert "kill switch" in result.reason
    assert browser.calls == 0


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://localhost/",
        "https://service.local/",
        "https://127.0.0.1/",
        "https://10.1.2.3/",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://example.com:8443/",
        "https://user:pass@example.com/",
    ],
)
def test_browser_url_guard_rejects_unsafe_or_non_https_destinations(url: str):
    with pytest.raises(BrowserEgressError):
        _require_safe_https_url(url)


@pytest.mark.parametrize(
    "host",
    ["localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254"],
)
def test_browser_dns_resolution_rejects_loopback_private_and_mapped_addresses(host: str):
    with pytest.raises(BrowserEgressError):
        asyncio.run(resolve_public_addresses(host))


def test_browser_socks_proxy_rejects_dns_rebinding_to_private_address():
    async def scenario():
        resolutions: list[str] = []

        async def rebound_resolver(host: str) -> tuple[str, ...]:
            resolutions.append(host)
            return ("192.168.1.20",)

        proxy = Socks5EgressProxy(resolver=rebound_resolver)
        await proxy.start()
        port = proxy._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await reader.readexactly(2) == b"\x05\x00"
        host = b"public.example"
        writer.write(b"\x05\x01\x00\x03" + bytes((len(host),)) + host + (443).to_bytes(2, "big"))
        await writer.drain()
        reply = await reader.readexactly(10)
        assert reply[1] != 0
        assert resolutions == ["public.example"]
        writer.close()
        await writer.wait_closed()
        await proxy.close()

    asyncio.run(scenario())

def test_browser_socks_proxy_rejects_non_https_tunnel_port():
    async def scenario():
        resolver_calls = 0

        async def resolver(_host: str) -> tuple[str, ...]:
            nonlocal resolver_calls
            resolver_calls += 1
            return ("93.184.216.34",)

        proxy = Socks5EgressProxy(resolver=resolver)
        await proxy.start()
        port = proxy._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        await reader.readexactly(2)
        host = b"public.example"
        writer.write(b"\x05\x01\x00\x03" + bytes((len(host),)) + host + (80).to_bytes(2, "big"))
        await writer.drain()
        reply = await reader.readexactly(10)
        assert reply[1] != 0
        assert resolver_calls == 0
        writer.close()
        await writer.wait_closed()
        await proxy.close()

    asyncio.run(scenario())

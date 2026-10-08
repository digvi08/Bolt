"""DNS-pinning SOCKS5 egress for browser HTTPS connections."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable


class BrowserEgressError(ValueError):
    pass


Resolver = Callable[[str], Awaitable[tuple[str, ...]]]


async def resolve_public_addresses(host: str) -> tuple[str, ...]:
    normalized = host.rstrip(".").encode("idna").decode("ascii").lower()
    if not normalized or normalized == "localhost" or normalized.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise BrowserEgressError("browser destination is not public")
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(
                    normalized,
                    443,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                ),
                timeout=3,
            )
        except (OSError, TimeoutError) as error:
            raise BrowserEgressError("browser destination DNS lookup failed") from error
        addresses = tuple(dict.fromkeys(record[4][0].split("%", maxsplit=1)[0] for record in records))
        if not addresses:
            raise BrowserEgressError("browser destination has no address")
    else:
        addresses = (str(literal),)

    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if getattr(parsed, "ipv4_mapped", None) is not None or not parsed.is_global:
            raise BrowserEgressError("browser destination is not public")
    return addresses


class Socks5EgressProxy:
    def __init__(
        self,
        *,
        resolver: Resolver = resolve_public_addresses,
        max_connections: int = 32,
        max_bytes_per_connection: int = 8_000_000,
        idle_timeout_seconds: float = 20,
    ) -> None:
        self._resolver = resolver
        self._max_connections = max_connections
        self._max_bytes = max_bytes_per_connection
        self._idle_timeout = idle_timeout_seconds
        self._server: asyncio.AbstractServer | None = None
        self._active = 0

    @property
    def address(self) -> str:
        sockets = getattr(self._server, "sockets", None)
        if not sockets:
            raise RuntimeError("browser egress proxy is not started")
        port = sockets[0].getsockname()[1]
        return f"socks5://127.0.0.1:{port}"

    async def start(self) -> None:
        if self._server is None:
            self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        if self._active >= self._max_connections:
            writer.close()
            await writer.wait_closed()
            return
        self._active += 1
        try:
            version, method_count = await asyncio.wait_for(reader.readexactly(2), timeout=3)
            methods = await asyncio.wait_for(reader.readexactly(method_count), timeout=3)
            if version != 5 or 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            version, command, _reserved, address_type = await asyncio.wait_for(
                reader.readexactly(4), timeout=3
            )
            if version != 5 or command != 1:
                await self._reply(writer, 7)
                return
            host = await self._read_host(reader, address_type)
            port = int.from_bytes(await reader.readexactly(2), "big")
            if port != 443:
                await self._reply(writer, 2)
                return
            try:
                addresses = await self._resolver(host)
                upstream_reader, connected_writer = await asyncio.wait_for(
                    self._connect_pinned(addresses), timeout=4
                )
                upstream_writer = connected_writer
            except (BrowserEgressError, OSError, TimeoutError):
                await self._reply(writer, 2)
                return
            await self._reply(writer, 0)
            await self._relay(reader, writer, upstream_reader, connected_writer)
        except (asyncio.IncompleteReadError, TimeoutError, OSError, ValueError):
            pass
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except OSError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            self._active -= 1

    async def _connect_pinned(
        self, addresses: tuple[str, ...]
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        failure: OSError | None = None
        for address in addresses:
            try:
                return await asyncio.open_connection(address, 443)
            except OSError as error:
                failure = error
        if failure is not None:
            raise failure
        raise BrowserEgressError("browser destination could not be connected")

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        transferred = 0

        async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal transferred
            while True:
                chunk = await asyncio.wait_for(
                    reader.read(64 * 1024), timeout=self._idle_timeout
                )
                if not chunk:
                    return
                transferred += len(chunk)
                if transferred > self._max_bytes:
                    return
                writer.write(chunk)
                await writer.drain()

        tasks = {
            asyncio.create_task(pump(client_reader, upstream_writer)),
            asyncio.create_task(pump(upstream_reader, client_writer)),
        }
        try:
            done, pending = await asyncio.wait(
                tasks, timeout=300, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    async def _read_host(reader: asyncio.StreamReader, address_type: int) -> str:
        if address_type == 1:
            return socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        if address_type == 4:
            return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        if address_type == 3:
            size = (await reader.readexactly(1))[0]
            if size == 0:
                raise BrowserEgressError("empty browser destination")
            return (await reader.readexactly(size)).decode("ascii")
        raise BrowserEgressError("unsupported browser destination address")

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int) -> None:
        writer.write(b"\x05" + bytes((status,)) + b"\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()


__all__ = ["BrowserEgressError", "Socks5EgressProxy", "resolve_public_addresses"]

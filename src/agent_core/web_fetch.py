"""Bounded HTTP reads with destination validation and pinned DNS resolution."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from urllib.parse import SplitResult, parse_qsl, quote, urljoin, urlsplit, urlunsplit


class WebFetchError(ValueError):
    """A network read was rejected or could not be completed safely."""


@dataclass(frozen=True)
class WebFetchResponse:
    url: str
    status: int
    content_type: str
    text: str
    transport_secure: bool


_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bolt-dns")
_DNS_SEMAPHORE = threading.BoundedSemaphore(4)
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_SUPPORTED_CONTENT_TYPES = {
    "application/json",
    "application/rss+xml",
    "application/xml",
    "application/xhtml+xml",
    "application/atom+xml",
    "text/html",
    "text/plain",
    "text/xml",
}


class SafeWebFetcher:
    """Fetch public HTTP(S) text without proxies, private destinations, or unbounded bodies."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 8.0,
        max_response_bytes: int = 512_000,
        max_redirects: int = 4,
    ) -> None:
        if timeout_seconds <= 0 or max_response_bytes < 1 or max_redirects < 0:
            raise ValueError("invalid web fetch bounds")
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_redirects = max_redirects

    def fetch(self, url: str, *, allowed_hosts: frozenset[str] | None = None) -> WebFetchResponse:
        deadline = time.monotonic() + self.timeout_seconds
        current = _normalize_url(url)
        for redirect_count in range(self.max_redirects + 1):
            parsed = urlsplit(current)
            host = parsed.hostname
            if host is None:
                raise WebFetchError("URL has no host")
            if allowed_hosts is not None and host not in allowed_hosts:
                raise WebFetchError("redirect destination is outside the configured host set")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            addresses = _resolve_public_addresses(host, port, _remaining(deadline))
            response, response_socket = self._request(
                parsed, host, port, addresses[0], deadline
            )
            if response.status in _REDIRECT_STATUSES:
                location = response.getheader("Location")
                response.close()
                response_socket.close()
                if not location:
                    raise WebFetchError("redirect response has no location")
                if redirect_count >= self.max_redirects:
                    raise WebFetchError("redirect limit exceeded")
                current = _normalize_url(urljoin(current, location))
                continue
            return self._read_response(
                response,
                response_socket,
                current,
                parsed.scheme == "https",
                deadline,
            )
        raise WebFetchError("redirect limit exceeded")

    def _request(
        self,
        parsed: SplitResult,
        host: str,
        port: int,
        address: str,
        deadline: float,
    ) -> tuple[http.client.HTTPResponse, socket.socket]:
        raw_socket: socket.socket | None = None
        request_socket: socket.socket | None = None
        try:
            raw_socket = socket.create_connection((address, port), _remaining(deadline))
            raw_socket.settimeout(_remaining(deadline))
            request_socket = raw_socket
            if parsed.scheme == "https":
                request_socket = ssl.create_default_context().wrap_socket(
                    raw_socket, server_hostname=host
                )
            path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
            if parsed.query:
                path += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
            if any(ord(character) < 0x21 or ord(character) == 0x7F for character in path):
                raise WebFetchError("URL contains an invalid request target")
            host_header = _host_header(host, port, parsed.scheme)
            request_socket.settimeout(_remaining(deadline))
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "Accept: text/html, text/plain, application/json, application/xml, application/rss+xml\r\n"
                "Accept-Encoding: identity\r\n"
                "User-Agent: BoltLocalAgent/1.0\r\n"
                "Connection: close\r\n\r\n"
            )
            request_socket.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(request_socket, method="GET")
            response.begin()
            return response, request_socket
        except WebFetchError:
            if request_socket is not None:
                request_socket.close()
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            if request_socket is not None:
                request_socket.close()
            elif raw_socket is not None:
                raw_socket.close()
            raise WebFetchError("remote server could not be reached safely") from error

    def _read_response(
        self,
        response: http.client.HTTPResponse,
        response_socket: socket.socket,
        url: str,
        transport_secure: bool,
        deadline: float,
    ) -> WebFetchResponse:
        try:
            _remaining(deadline)
            headers = response.getheaders()
            header_size = sum(len(name) + len(value) for name, value in headers)
            if len(headers) > 100 or header_size > 64_000:
                raise WebFetchError("response headers exceed configured bounds")
            content_encoding = response.getheader("Content-Encoding", "identity").lower()
            if content_encoding not in {"", "identity"}:
                raise WebFetchError("compressed responses are not supported")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type not in _SUPPORTED_CONTENT_TYPES:
                raise WebFetchError("response content type is not supported")
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    content_length = int(length)
                except ValueError:
                    raise WebFetchError("response content length is invalid") from None
                if content_length < 0:
                    raise WebFetchError("response content length is invalid")
                if content_length > self.max_response_bytes:
                    raise WebFetchError("response exceeds configured size limit")
            chunks: list[bytes] = []
            total = 0
            while total <= self.max_response_bytes:
                response_socket.settimeout(_remaining(deadline))
                try:
                    chunk = response.read(min(16_384, self.max_response_bytes + 1 - total))
                except (OSError, http.client.HTTPException) as error:
                    raise WebFetchError("response read failed or timed out") from error
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > self.max_response_bytes:
                raise WebFetchError("response exceeds configured size limit")
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                text = b"".join(chunks).decode(charset, errors="replace")
            except LookupError:
                text = b"".join(chunks).decode("utf-8", errors="replace")
            return WebFetchResponse(url, response.status, content_type, text, transport_secure)
        finally:
            response.close()
            response_socket.close()


def _normalize_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 4096:
        raise WebFetchError("URL is invalid")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError:
        raise WebFetchError("URL is invalid") from None
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise WebFetchError("only public HTTP(S) URLs without credentials are supported")
    host = parsed.hostname.rstrip(".").lower()
    if not host or host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise WebFetchError("local destinations are not allowed")
    if "%" in host:
        raise WebFetchError("scoped and encoded hostnames are not supported")
    try:
        query_fields = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        raise WebFetchError("URL query exceeds configured bounds") from None
    sensitive_query_names = {
        "accesskey",
        "accesstoken",
        "apikey",
        "auth",
        "authorization",
        "code",
        "cookie",
        "key",
        "password",
        "secret",
        "session",
        "sessionid",
        "sid",
        "sig",
        "signature",
        "token",
    }
    if any(
        "".join(character for character in name.lower() if character.isalnum())
        in sensitive_query_names
        for name, _ in query_fields
    ):
        raise WebFetchError("URLs containing credential-like query fields are not supported")
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise WebFetchError("URL hostname is invalid") from None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def _resolve_public_addresses(host: str, port: int, timeout: float) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [str(literal)]
    else:
        if not _DNS_SEMAPHORE.acquire(timeout=timeout):
            raise WebFetchError("DNS lookup capacity is exhausted")
        try:
            future = _DNS_POOL.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
        except RuntimeError as error:
            _DNS_SEMAPHORE.release()
            raise WebFetchError("DNS resolver is unavailable") from error
        future.add_done_callback(lambda _future: _DNS_SEMAPHORE.release())
        try:
            records = future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            raise WebFetchError("DNS lookup timed out") from None
        except OSError as error:
            raise WebFetchError("DNS lookup failed") from error
        addresses = list(dict.fromkeys(record[4][0] for record in records))
    if not addresses:
        raise WebFetchError("DNS returned no addresses")
    try:
        parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
    except ValueError:
        raise WebFetchError("DNS returned an invalid address") from None
    if any(not _is_safe_public_address(address) for address in parsed_addresses):
        raise WebFetchError("local or non-public network destinations are not allowed")
    return [str(address) for address in parsed_addresses]


def _is_safe_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if not address.is_global:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return not (
            address.ipv4_mapped is not None
            or address.sixtofour is not None
            or address.teredo is not None
            or address.is_site_local
        )
    return True


def _host_header(host: str, port: int, scheme: str) -> str:
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return display_host if port == default_port else f"{display_host}:{port}"


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WebFetchError("request timed out")
    return remaining


__all__ = ["SafeWebFetcher", "WebFetchError", "WebFetchResponse"]

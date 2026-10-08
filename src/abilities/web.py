"""Web research ability using bounded, destination-validated HTTP reads."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote_plus, urlsplit

from agent_core.models import ActionKind, RiskLevel, VerificationResult
from agent_core.secrets import sanitize_text
from agent_core.web_fetch import SafeWebFetcher, WebFetchError

from .models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str


class WebSearchProvider(Protocol):
    """Provider interface for independent public web search."""

    def search(self, query: str, *, limit: int) -> tuple[SearchResult, ...]: ...


class BingRssSearchProvider(WebSearchProvider):
    """Public Bing RSS search for personal, non-commercial result rendering."""

    def __init__(self, fetcher: SafeWebFetcher | None = None) -> None:
        self.fetcher = fetcher or SafeWebFetcher(max_response_bytes=256_000)

    def search(self, query: str, *, limit: int) -> tuple[SearchResult, ...]:
        if not query.strip() or len(query) > 500 or not 1 <= limit <= 10:
            raise ValueError("search query or result limit is invalid")
        url = f"https://www.bing.com/search?format=rss&q={quote_plus(query)}"
        response = self.fetcher.fetch(url, allowed_hosts=frozenset({"www.bing.com"}))
        if response.status != 200:
            raise WebFetchError(f"search provider returned HTTP {response.status}")
        try:
            root = ET.fromstring(response.text)
        except ET.ParseError as error:
            raise WebFetchError("search provider returned invalid results") from error
        results: list[SearchResult] = []
        for item in root.findall("./channel/item")[:limit]:
            title = item.findtext("title", default="").strip()
            link = item.findtext("link", default="").strip()
            snippet = item.findtext("description", default="").strip()
            parsed_link = urlsplit(link)
            if (
                not title
                or parsed_link.scheme not in {"http", "https"}
                or not parsed_link.hostname
                or parsed_link.username is not None
                or parsed_link.password is not None
            ):
                continue
            results.append(
                SearchResult(
                    title=sanitize_text(title)[:500],
                    url=link[:2048],
                    snippet=sanitize_text(snippet)[:2000],
                )
            )
        return tuple(results)


class WebAbilityProvider:
    ability = "web"

    def __init__(
        self,
        *,
        fetcher: SafeWebFetcher | None = None,
        search_provider: WebSearchProvider | None = None,
    ) -> None:
        self.fetcher = fetcher or SafeWebFetcher()
        self.search_provider = search_provider or BingRssSearchProvider(self.fetcher)
        self.descriptor = AbilityDescriptor(
            name="web",
            description="Search public web results and fetch bounded public text content.",
            capabilities=("public_web_search", "public_http_text_read"),
            supported_actions=("search", "fetch"),
            risk_classes=("network_read",),
            required_permissions=("network",),
            provider="stdlib-http",
        )

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def action_kind(self, _action: str) -> ActionKind:
        return ActionKind.NETWORK_READ

    def risk_for(self, action: str) -> RiskLevel:
        return (
            RiskLevel.LOW
            if self.supports(action)
            else RiskLevel.UNKNOWN
        )

    def verify_action(
        self,
        action: str,
        payload: dict[str, Any],
        result: object,
    ) -> VerificationResult:
        if not isinstance(result, AbilityResult) or not result.success:
            return VerificationResult(False, "web provider reported failure")
        value = result.value
        if not isinstance(value, dict):
            return VerificationResult(False, "web provider result is malformed")
        if action == "fetch":
            requested_url = payload.get("url")
            final_url = value.get("url")
            if (
                not isinstance(requested_url, str)
                or not isinstance(final_url, str)
                or not isinstance(value.get("status"), int)
                or not 200 <= value["status"] < 300
                or value.get("trust") != "untrusted_web"
                or not isinstance(value.get("content_type"), str)
                or not isinstance(value.get("text"), str)
                or len(value["text"].encode("utf-8")) > self.fetcher.max_response_bytes
                or value.get("content_type")
                not in {
                    "application/json",
                    "application/rss+xml",
                    "application/xml",
                    "application/xhtml+xml",
                    "application/atom+xml",
                    "text/html",
                    "text/plain",
                    "text/xml",
                }
                or sanitize_text(value["text"]) != value["text"]
            ):
                return VerificationResult(False, "web fetch response failed metadata or bounds verification")
            requested = urlsplit(requested_url)
            final = urlsplit(final_url)
            if (
                requested.scheme not in {"http", "https"}
                or requested.hostname is None
                or requested.username is not None
                or requested.password is not None
                or final.scheme not in {"http", "https"}
                or final.hostname is None
                or final.username is not None
                or final.password is not None
            ):
                return VerificationResult(False, "web fetch destination metadata is invalid")
            if value.get("transport_secure") != (final.scheme == "https"):
                return VerificationResult(False, "web fetch transport metadata is malformed")
            return VerificationResult(True, "bounded public response metadata and trust label verified")
        if action == "search":
            results = value.get("results")
            if (
                not isinstance(results, list)
                or len(results) > 5
                or any(
                    not isinstance(item, dict)
                    or item.get("trust") != "untrusted_web"
                    or not isinstance(item.get("url"), str)
                    or not isinstance(item.get("title"), str)
                    or len(item["title"]) > 500
                    or not isinstance(item.get("snippet"), str)
                    or len(item["snippet"]) > 2000
                    or sanitize_text(item["title"]) != item["title"]
                    or sanitize_text(item["snippet"]) != item["snippet"]
                    for item in results
                )
            ):
                return VerificationResult(False, "web search result failed bounds or trust verification")
            return VerificationResult(True, "bounded web search results and trust labels verified")
        return VerificationResult(False, "web action has no verification rule")

    def execute(
        self,
        action: AbilityAction,
        _context: AbilityContext | None = None,
    ) -> AbilityResult:
        try:
            if action.action == "fetch":
                url = action.payload.get("url")
                if not isinstance(url, str):
                    return AbilityResult(False, reason="web.fetch requires a URL")
                response = self.fetcher.fetch(url)
                if not 200 <= response.status < 300:
                    return AbilityResult(
                        False,
                        reason=f"web server returned HTTP {response.status}",
                        failure_type="remote_error",
                    )
                return AbilityResult(
                    True,
                    value={
                        "url": response.url,
                        "status": response.status,
                        "content_type": response.content_type,
                        "text": sanitize_text(response.text),
                        "transport_secure": response.transport_secure,
                        "trust": "untrusted_web",
                    },
                    metadata={"trust": "untrusted_web", "bounded": True},
                )
            if action.action == "search":
                query = action.payload.get("query")
                if not isinstance(query, str):
                    return AbilityResult(False, reason="web.search requires a query")
                results = self.search_provider.search(query, limit=5)
                return AbilityResult(
                    True,
                    value={
                        "results": [
                            {
                                "title": result.title,
                                "url": result.url,
                                "snippet": result.snippet,
                                "trust": "untrusted_web",
                            }
                            for result in results
                        ]
                    },
                    metadata={"trust": "untrusted_web", "bounded": True},
                )
            return AbilityResult(False, reason="unsupported web action")
        except (ValueError, WebFetchError) as error:
            return AbilityResult(
                False,
                reason=sanitize_text(str(error)),
                failure_type="web_request_failed",
            )


__all__ = [
    "BingRssSearchProvider",
    "SearchResult",
    "WebAbilityProvider",
    "WebSearchProvider",
]

"""Browser state verification contracts and safe deterministic checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agent_core.models import VerificationResult

from .models import BrowserAction, BrowserObservation


class BrowserVerificationProvider(Protocol):
    async def verify(self, action: BrowserAction, observation: BrowserObservation | object) -> VerificationResult: ...


@dataclass(frozen=True)
class ExpectedStateVerifier:
    """Small deterministic verifier; richer site-specific checks belong in adapters."""

    expected_url: str | None = None
    expected_text: str | None = None

    async def verify(self, action: BrowserAction, observation: BrowserObservation | object) -> VerificationResult:
        if not isinstance(observation, BrowserObservation):
            return VerificationResult(False, "browser observation was not returned")
        if self.expected_url is not None and observation.tab.url != self.expected_url:
            return VerificationResult(False, "expected URL was not reached")
        if self.expected_text is not None and self.expected_text not in observation.visible_text.text:
            return VerificationResult(False, "expected page text was not observed")
        return VerificationResult(True, "expected browser state observed")

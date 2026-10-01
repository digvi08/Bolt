"""Bounded browser recovery policies. Recovery never retries indefinitely."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from agent_core.models import RecoveryResult

from .models import BrowserError, BrowserErrorKind


class BrowserRecoveryProvider(Protocol):
    async def recover(self, tab_id: UUID, error: BrowserError, attempt: int) -> RecoveryResult: ...


@dataclass(frozen=True)
class BoundedBrowserRecovery:
    max_attempts: int = 2

    async def recover(self, tab_id: UUID, error: BrowserError, attempt: int) -> RecoveryResult:
        if attempt >= self.max_attempts:
            return RecoveryResult(False, "bounded browser recovery exhausted")
        if error.kind in {BrowserErrorKind.TRANSIENT, BrowserErrorKind.STALE_ELEMENT}:
            return RecoveryResult(True, "re-observe and retry once")
        if error.kind is BrowserErrorKind.NAVIGATION_TIMEOUT:
            return RecoveryResult(True, "reload and retry within the attempt bound")
        return RecoveryResult(False, f"no deterministic recovery for {error.kind.value}")

"""Integration boundaries. Concrete browser, desktop, terminal, and network adapters belong outside core."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from .models import (
    ActionRequest,
    ApprovalRequest,
    AuditEvent,
    RecoveryResult,
    VerificationResult,
)


class ActionProvider(Protocol):
    def execute(self, action: ActionRequest) -> object: ...


class AsyncActionProvider(Protocol):
    async def execute_async(self, action: ActionRequest) -> object: ...


class ApprovalProvider(Protocol):
    def approve(self, request: ApprovalRequest) -> bool: ...


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...


class VerificationProvider(Protocol):
    def verify(self, action: ActionRequest, result: object) -> VerificationResult: ...


class RecoveryProvider(Protocol):
    def recover(self, task_id: UUID, error: Exception) -> RecoveryResult: ...


class KillSwitch(Protocol):
    def is_engaged(self) -> bool: ...


class PolicyEngine(Protocol):
    def evaluate(self, action: ActionRequest) -> object: ...

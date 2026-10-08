"""Durable, action-bound approval decisions used by AgentRuntime."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from .models import ApprovalRequest
from .persistence import ApprovalRecord, ApprovalStatus, TaskStateStore
from .secrets import sanitize_text


@dataclass(frozen=True)
class ApprovalView:
    approval_id: str
    task_id: str
    action_id: str
    ability: str
    action_kind: str
    provider: str
    caller_id: str
    summary: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    decision_at: datetime | None
    decision_actor: str | None

    @classmethod
    def from_record(cls, record: ApprovalRecord) -> ApprovalView:
        return cls(
            approval_id=record.approval_id,
            task_id=str(record.task_id),
            action_id=record.action_id,
            ability=record.ability,
            action_kind=record.action_kind,
            provider=record.provider,
            caller_id=record.caller_id,
            summary=record.summary,
            created_at=record.created_at,
            expires_at=record.expires_at,
            status=record.status,
            decision_at=record.decision_at,
            decision_actor=record.decision_actor,
        )


class DurableApprovalProvider:
    def __init__(
        self,
        store: TaskStateStore,
        *,
        ttl: timedelta = timedelta(minutes=15),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if ttl.total_seconds() <= 0:
            raise ValueError("approval lifetime must be positive")
        self._store = store
        self._ttl = ttl
        self._clock = clock or (lambda: datetime.now(UTC))

    def approve(self, request: ApprovalRequest) -> bool:
        task = self._store.load_task(request.task_id)
        if task is None:
            return False
        fingerprint = action_fingerprint(request, str(task.caller_id))
        now = self._aware_now()
        record = self._store.find_approval(request.task_id, fingerprint)
        if record is None:
            ability = str(request.action.ability_id or request.action.name.partition(".")[0])
            provider = str(request.action.provider_id or ability)
            record = self._store.create_approval(
                ApprovalRecord(
                    approval_id=str(uuid4()),
                    task_id=request.task_id,
                    action_id=request.action.execution_id or "",
                    ability=sanitize_text(ability),
                    action_kind=sanitize_text(str(request.action.kind)),
                    provider=sanitize_text(provider),
                    caller_id=str(task.caller_id),
                    summary=sanitize_text(
                        f"{request.action.name} ({request.decision.risk.value} risk)"
                    ),
                    action_fingerprint=fingerprint,
                    created_at=now,
                    expires_at=now + self._ttl,
                )
            )
        if record.status is ApprovalStatus.PENDING:
            return False
        if record.status is not ApprovalStatus.APPROVED:
            return False
        claimed = self._store.claim_approval(record.approval_id, now=now)
        return claimed is not None and claimed.status is ApprovalStatus.CONSUMED

    def is_pending(self, request: ApprovalRequest) -> bool:
        task = self._store.load_task(request.task_id)
        if task is None:
            return False
        record = self._store.find_approval(
            request.task_id,
            action_fingerprint(request, str(task.caller_id)),
        )
        return (
            record is not None
            and record.status is ApprovalStatus.PENDING
            and record.expires_at > self._aware_now()
        )

    def _aware_now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("approval clock must return a timezone-aware timestamp")
        return now.astimezone(UTC)


def action_fingerprint(request: ApprovalRequest, caller_id: str) -> str:
    action = request.action
    material = {
        "task_id": str(request.task_id),
        "action_id": action.execution_id,
        "caller_id": caller_id,
        "name": action.name,
        "kind": str(action.kind),
        "ability": str(action.ability_id or ""),
        "provider": str(action.provider_id or ""),
        "requested_risk": str(action.requested_risk or ""),
        "parameters": action.parameters,
    }
    canonical = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda value: type(value).__name__,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = ["ApprovalView", "DurableApprovalProvider", "action_fingerprint"]

"""Typed domain objects. Trusted instructions and external content stay distinct."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


def utc_now() -> datetime:
    return datetime.now(UTC)


class TrustLevel(str, Enum):
    SYSTEM = "system"
    USER = "user"
    UNTRUSTED = "untrusted"


class TaskStatus(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    PLANNING = "planning"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    RECOVERING = "recovering"
    SUCCEEDED = "succeeded"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"
    STOPPED = "stopped"
    ABORTED = "aborted"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class ActionKind(str, Enum):
    READ_ONLY = "read_only"
    WRITE_FILE = "write_file"
    PROCESS = "process"
    NETWORK = "network"
    BROWSER = "browser"
    DESKTOP = "desktop"
    ADMINISTRATOR = "administrator"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TrustedInstruction:
    text: str
    source: TrustLevel = TrustLevel.USER


@dataclass(frozen=True)
class UntrustedContent:
    text: str
    source: str


@dataclass
class Task:
    instruction: TrustedInstruction
    external_context: tuple[UntrustedContent, ...] = ()
    id: UUID = field(default_factory=uuid4)
    root_task_id: UUID | None = None
    parent_task_id: UUID | None = None
    objective: str = ""
    status: TaskStatus = TaskStatus.CREATED
    current_phase: str = "created"
    current_plan_version: str = "v1"
    current_step: str | None = None
    completed_steps: list[str] = field(default_factory=list)
    failed_steps: list[str] = field(default_factory=list)
    retry_count: int = 0
    replan_count: int = 0
    approval_state: str = "pending"
    verification_state: str = "pending"
    last_error: str = ""
    termination_reason: str = ""
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    execution_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionRequest:
    task_id: UUID
    name: str
    kind: ActionKind | str
    parameters: dict[str, Any] = field(default_factory=dict)
    requested_risk: RiskLevel | None = None
    execution_id: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk: RiskLevel
    reason: str
    requires_approval: bool = False


@dataclass(frozen=True)
class ApprovalRequest:
    task_id: UUID
    action: ActionRequest
    decision: PolicyDecision


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    reason: str


@dataclass(frozen=True)
class RecoveryResult:
    recovered: bool
    reason: str


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    task_id: UUID
    timestamp: datetime = field(default_factory=utc_now)
    details: dict[str, Any] = field(default_factory=dict)

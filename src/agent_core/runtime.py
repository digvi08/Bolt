"""Task orchestration with policy, approval, audit, verification, and recovery gates."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from typing import Protocol, TypeVar, cast
from uuid import UUID, uuid4

from .config import AgentConfig
from .models import (
    ActionKind,
    ActionRequest,
    ApprovalRequest,
    AuditEvent,
    Task,
    TaskStatus,
    TrustedInstruction,
)
from .persistence import (
    ActionExecutionConflict,
    ActionExecutionRecord,
    ActionExecutionStatus,
    RestartDecision,
    RestartSafetyChecker,
    TaskRecord,
    TaskStateMachine,
    TaskStateStore,
    TaskTransitionError,
    VerificationStatus,
)
from .ports import (
    ActionProvider,
    ApprovalProvider,
    AsyncActionProvider,
    AuditSink,
    KillSwitch,
    RecoveryProvider,
    VerificationProvider,
)
from .secrets import sanitize_exception, sanitize_value
from .security import DefaultPolicyEngine

T = TypeVar("T")
_RUNTIME_PROCESS_ID = uuid4().hex


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    value: object | None = None
    reason: str = ""
    failure_type: str | None = None
    retryable: bool = False


class ActionNotExecutedError(RuntimeError):
    """Provider assertion that an action definitely did not cause its side effect."""


@dataclass(frozen=True)
class ActionReconciliationRequest:
    task_id: UUID
    execution_id: str
    provider_identity: str
    action_fingerprint: str
    action: ActionRequest


class ActionReconciliationOutcome(StrEnum):
    CONFIRMED_COMPLETED = "confirmed_completed"
    CONFIRMED_NOT_EXECUTED = "confirmed_not_executed"
    STILL_UNCERTAIN = "still_uncertain"
    RECONCILIATION_FAILED = "reconciliation_failed"


@dataclass(frozen=True)
class ActionReconciliationResult:
    outcome: ActionReconciliationOutcome
    reason: str


class ActionReconciler(Protocol):
    """Read-only/observational adapter; must not execute the requested action."""

    def reconcile(
        self, request: ActionReconciliationRequest
    ) -> ActionReconciliationResult: ...


class AgentRuntime:
    def __init__(
        self,
        config: AgentConfig,
        action_provider: ActionProvider,
        audit_sink: AuditSink,
        kill_switch: KillSwitch,
        approval_provider: ApprovalProvider | None = None,
        verifier: VerificationProvider | None = None,
        recovery: RecoveryProvider | None = None,
        state_store: TaskStateStore | None = None,
        action_reconciler: ActionReconciler | None = None,
    ) -> None:
        self._config = config
        self._actions = action_provider
        self._audit = audit_sink
        self._kill_switch = kill_switch
        self._approval = approval_provider
        self._verifier = verifier
        self._recovery = recovery
        self._state_store = state_store
        self._action_reconciler = action_reconciler
        self._safe_retry_actions: set[tuple[UUID, str]] = set()
        self._reconciliation_lock = threading.Lock()
        self._restart_decisions: tuple[tuple[TaskRecord, RestartDecision], ...] = ()
        self._policy = DefaultPolicyEngine(config)
        if self._state_store is not None:
            self.recover_pending_tasks()

    def run(self, task: Task, action: ActionRequest) -> ExecutionResult:
        self._event("task.started", task, {"action": action.name})
        if self._kill_switch.is_engaged():
            task.termination_reason = "kill switch engaged"
            self._set_status(task, TaskStatus.STOPPED)
            self._event("task.stopped", task, {"reason": "kill switch engaged"})
            return ExecutionResult(False, reason="kill switch engaged", failure_type="kill_switch")
        if action.task_id != task.id:
            self._event("action.identity_mismatch", task, {"action": action.name})
            return ExecutionResult(False, reason="task/action identity mismatch", failure_type="invalid_action_identity")
        if self._state_store is not None and not action.execution_id:
            self._event("action.identity_missing", task, {"action": action.name})
            return ExecutionResult(False, reason="persistent execution requires action identity", failure_type="invalid_action_identity")

        if self._state_store is not None and task.status in {
            TaskStatus.COMPLETED,
            TaskStatus.ABORTED,
            TaskStatus.DENIED,
            TaskStatus.STOPPED,
        }:
            self._set_status(task, TaskStatus.EXECUTING)
        if task.status is TaskStatus.FAILED and self._state_store is not None:
            self._set_status(task, TaskStatus.RECOVERING)
        self._persist_task(task)
        decision = self._policy.evaluate(action)
        self._event("policy.evaluated", task, {"allowed": decision.allowed, "risk": decision.risk.value})
        if not decision.allowed:
            self._set_status(task, TaskStatus.DENIED)
            self._event("task.denied", task, {"reason": decision.reason})
            return ExecutionResult(False, reason=decision.reason, failure_type="policy_denied")

        if decision.requires_approval:
            self._set_status(task, TaskStatus.AWAITING_APPROVAL)
            task.approval_state = "pending"
            approved = self._approval is not None and self._approval.approve(
                ApprovalRequest(task.id, action, decision)
            )
            if not approved:
                task.approval_state = "denied"
                self._set_status(task, TaskStatus.DENIED)
                self._event("task.denied", task, {"reason": "approval denied or unavailable"})
                return ExecutionResult(False, reason="approval denied or unavailable", failure_type="approval_denied")
            task.approval_state = "granted"

        action_record = self._load_or_create_action(task, action)
        if action_record is None:
            return ExecutionResult(False, reason="duplicate or uncertain action is blocked", failure_type="action_recovery_required")

        try:
            self._set_status(task, TaskStatus.EXECUTING, action_record=action_record, action_status=ActionExecutionStatus.EXECUTING)
        except ActionExecutionConflict:
            self._event(
                "action.duplicate_blocked",
                task,
                {"execution_id": action.execution_id, "reason": "action is already in flight"},
            )
            return ExecutionResult(False, reason="action is already in flight", failure_type="action_recovery_required")
        if self._state_store is not None:
            self._event("action.execution_started", task, {"execution_id": action.execution_id})
        try:
            value = self._actions.execute(action)
        except ActionNotExecutedError as error:
            action_record.status = ActionExecutionStatus.FAILED
            action_record.outcome = sanitize_exception(error)
            self._safe_retry_actions.add((task.id, action_record.action_id))
            action_record.metadata["retry_safe"] = True
            self._set_status(task, TaskStatus.FAILED, action_record=action_record)
            self._event("action.failed", task, {"execution_id": action.execution_id, "retry_safe": True})
            return ExecutionResult(False, reason="action was not executed", failure_type="transient", retryable=True)
        except Exception as error:  # noqa: BLE001 - unknown outcome is never blindly retried
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = sanitize_exception(error)
            action_record.metadata["retry_safe"] = False
            self._set_status(task, TaskStatus.FAILED, action_record=action_record)
            self._event("action.uncertain", task, {"execution_id": action.execution_id})
            self._event("task.failed", task, {"error": sanitize_exception(error)})
            if self._recovery is not None:
                self._event("recovery.started", task)
                self._recovery.recover(task.id, error)
            return ExecutionResult(False, reason="execution outcome uncertain", failure_type="uncertain", retryable=False)

        if self._state_store is not None and getattr(value, "success", True) is False:
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = sanitize_value(getattr(value, "reason", "provider reported failure"))
            action_record.metadata["retry_safe"] = False
            self._set_status(task, TaskStatus.FAILED, action_record=action_record)
            self._event("action.uncertain", task, {"execution_id": action.execution_id})
            return ExecutionResult(False, reason="execution outcome uncertain", failure_type="uncertain", retryable=False)

        action_record.status = ActionExecutionStatus.COMPLETED
        action_record.outcome = "provider returned successfully"
        action_record.metadata["retry_safe"] = False
        self._persist_task_and_action(task, action_record)
        if self._state_store is not None:
            self._event("action.completed", task, {"execution_id": action.execution_id})

        if self._verifier is not None:
            self._set_status(
                task,
                TaskStatus.VERIFYING,
                action_record=action_record,
                verification_status=VerificationStatus.PENDING,
            )
            try:
                verification = self._verifier.verify(action, value)
            except Exception as error:  # noqa: BLE001 - verifier exceptions leave outcome unverified
                verification = None
                verify_error = sanitize_exception(error)
            else:
                verify_error = verification.reason if verification is not None else "verification result missing"
            if verification is None or not verification.verified:
                task.verification_state = "uncertain" if verification is None else "failed"
                status = VerificationStatus.UNCERTAIN if verification is None else VerificationStatus.FAILED
                self._set_status(
                    task,
                    TaskStatus.FAILED,
                    action_record=action_record,
                    verification_status=status,
                    verification_reason=verify_error,
                )
                return self._verification_failure(task, verify_error)
            task.verification_state = "verified"
            self._set_status(
                task,
                TaskStatus.SUCCEEDED,
                action_record=action_record,
                verification_status=VerificationStatus.VERIFIED,
                verification_reason=verification.reason,
            )
        else:
            task.verification_state = "not_configured"
            self._set_status(
                task,
                TaskStatus.SUCCEEDED,
                action_record=action_record,
                verification_status=VerificationStatus.NOT_CONFIGURED,
                verification_reason="no verifier configured",
            )
        self._event("task.succeeded", task)
        return ExecutionResult(True, value=value)

    async def run_async(
        self, task: Task, action: ActionRequest
    ) -> ExecutionResult:
        """Run an async provider through the same policy, approval, audit, and recovery gates."""
        self._event("task.started", task, {"action": action.name})
        if self._kill_switch.is_engaged():
            task.termination_reason = "kill switch engaged"
            self._set_status(task, TaskStatus.STOPPED)
            self._event("task.stopped", task, {"reason": "kill switch engaged"})
            return ExecutionResult(False, reason="kill switch engaged", failure_type="kill_switch")
        if action.task_id != task.id:
            self._event("action.identity_mismatch", task, {"action": action.name})
            return ExecutionResult(False, reason="task/action identity mismatch", failure_type="invalid_action_identity")
        if self._state_store is not None and not action.execution_id:
            return ExecutionResult(False, reason="persistent execution requires action identity", failure_type="invalid_action_identity")
        if self._state_store is not None and task.status in {
            TaskStatus.COMPLETED,
            TaskStatus.ABORTED,
            TaskStatus.DENIED,
            TaskStatus.STOPPED,
        }:
            self._set_status(task, TaskStatus.EXECUTING)
        if task.status is TaskStatus.FAILED and self._state_store is not None:
            self._set_status(task, TaskStatus.RECOVERING)
        self._persist_task(task)
        decision = self._policy.evaluate(action)
        self._event("policy.evaluated", task, {"allowed": decision.allowed, "risk": decision.risk.value})
        if not decision.allowed:
            self._set_status(task, TaskStatus.DENIED)
            self._event("task.denied", task, {"reason": decision.reason})
            return ExecutionResult(False, reason=decision.reason, failure_type="policy_denied")
        if decision.requires_approval:
            self._set_status(task, TaskStatus.AWAITING_APPROVAL)
            task.approval_state = "pending"
            approved = self._approval is not None and self._approval.approve(
                ApprovalRequest(task.id, action, decision)
            )
            if not approved:
                task.approval_state = "denied"
                self._set_status(task, TaskStatus.DENIED)
                self._event("task.denied", task, {"reason": "approval denied or unavailable"})
                return ExecutionResult(False, reason="approval denied or unavailable", failure_type="approval_denied")
            task.approval_state = "granted"
        action_record = self._load_or_create_action(task, action)
        if action_record is None:
            return ExecutionResult(False, reason="duplicate or uncertain action is blocked", failure_type="action_recovery_required")
        try:
            self._set_status(task, TaskStatus.EXECUTING, action_record=action_record, action_status=ActionExecutionStatus.EXECUTING)
        except ActionExecutionConflict:
            self._event(
                "action.duplicate_blocked",
                task,
                {"execution_id": action.execution_id, "reason": "action is already in flight"},
            )
            return ExecutionResult(False, reason="action is already in flight", failure_type="action_recovery_required")
        if self._state_store is not None:
            self._event("action.execution_started", task, {"execution_id": action.execution_id})
        try:
            action_provider = cast(AsyncActionProvider, self._actions)
            value = await action_provider.execute_async(action)
        except ActionNotExecutedError as error:
            action_record.status = ActionExecutionStatus.FAILED
            action_record.outcome = sanitize_exception(error)
            self._safe_retry_actions.add((task.id, action_record.action_id))
            action_record.metadata["retry_safe"] = True
            self._set_status(task, TaskStatus.FAILED, action_record=action_record)
            self._event("action.failed", task, {"execution_id": action.execution_id, "retry_safe": True})
            return ExecutionResult(False, reason="action was not executed", failure_type="transient", retryable=True)
        except Exception as error:  # noqa: BLE001 - adapter failures enter recovery uniformly
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = sanitize_exception(error)
            action_record.metadata["retry_safe"] = False
            self._set_status(task, TaskStatus.FAILED, action_record=action_record)
            self._event("action.uncertain", task, {"execution_id": action.execution_id})
            self._event("task.failed", task, {"error": sanitize_exception(error)})
            if self._recovery is not None:
                self._event("recovery.started", task)
                self._recovery.recover(task.id, error)
            return ExecutionResult(False, reason="execution outcome uncertain", failure_type="uncertain", retryable=False)
        if self._state_store is not None and getattr(value, "success", True) is False:
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = sanitize_value(getattr(value, "reason", "provider reported failure"))
            action_record.metadata["retry_safe"] = False
            self._set_status(task, TaskStatus.FAILED, action_record=action_record)
            self._event("action.uncertain", task, {"execution_id": action.execution_id})
            return ExecutionResult(False, reason="execution outcome uncertain", failure_type="uncertain", retryable=False)
        action_record.status = ActionExecutionStatus.COMPLETED
        action_record.outcome = "provider returned successfully"
        self._persist_task_and_action(task, action_record)
        if self._verifier is not None:
            self._set_status(task, TaskStatus.VERIFYING)
            try:
                verification = self._verifier.verify(action, value)
            except Exception as error:  # noqa: BLE001
                task.verification_state = "uncertain"
                self._set_status(
                    task,
                    TaskStatus.FAILED,
                    action_record=action_record,
                    verification_status=VerificationStatus.UNCERTAIN,
                    verification_reason=sanitize_exception(error),
                )
                return self._verification_failure(task, "verification outcome uncertain")
            if not verification.verified:
                task.verification_state = "failed"
                self._set_status(
                    task,
                    TaskStatus.FAILED,
                    action_record=action_record,
                    verification_status=VerificationStatus.FAILED,
                    verification_reason=verification.reason,
                )
                return self._verification_failure(task, verification.reason)
            task.verification_state = "verified"
            self._set_status(
                task,
                TaskStatus.SUCCEEDED,
                action_record=action_record,
                verification_status=VerificationStatus.VERIFIED,
                verification_reason=verification.reason,
            )
        else:
            task.verification_state = "not_configured"
            self._set_status(
                task,
                TaskStatus.SUCCEEDED,
                action_record=action_record,
                verification_status=VerificationStatus.NOT_CONFIGURED,
                verification_reason="no verifier configured",
            )
        self._event("task.succeeded", task)
        return ExecutionResult(True, value=value)

    def _event(self, event_type: str, task: Task, details: dict[str, object] | None = None) -> None:
        event = AuditEvent(event_type, task.id, details=sanitize_value(details or {}))
        if self._config.audit_required:
            self._audit.record(event)
        if self._state_store is not None:
            try:
                self._state_store.record_audit_event(event)
            except sqlite3.Error as error:
                if self._config.audit_required:
                    self._audit.record(
                        AuditEvent(
                            "persistence.failed",
                            task.id,
                            details={"error": sanitize_exception(error)},
                        )
                    )
                raise

    def _persistence_call(self, task: Task | TaskRecord, operation: Callable[[], T]) -> T:
        try:
            return operation()
        except (TaskTransitionError, ValueError) as error:
            if self._config.audit_required:
                self._audit.record(
                    AuditEvent(
                        "persistence.state_rejected",
                        task.id if isinstance(task, Task) else task.task_id,
                        details={"error": sanitize_exception(error)},
                    )
                )
            raise
        except (sqlite3.Error, OSError) as error:
            if self._config.audit_required:
                self._audit.record(
                    AuditEvent(
                        "persistence.failed",
                        task.id if isinstance(task, Task) else task.task_id,
                        details={"error": sanitize_exception(error)},
                    )
                )
            raise

    def _persist_task_if_needed(self, task: Task) -> None:
        store = self._state_store
        if store is not None:
            self._persistence_call(task, partial(store.save_task, task))

    def _persist_task(self, task: Task) -> None:
        self._persist_task_if_needed(task)

    def _load_or_create_action(self, task: Task, action: ActionRequest) -> ActionExecutionRecord | None:
        fingerprint = self._action_fingerprint(action)
        if self._state_store is None:
            return ActionExecutionRecord(
                action.execution_id or "ephemeral",
                task.id,
                action.name,
                status=ActionExecutionStatus.NEVER_ATTEMPTED,
                metadata={
                    "kind": self._kind_value(action.kind),
                    "parameters": sanitize_value(action.parameters),
                    "identity_fingerprint": fingerprint,
                },
            )
        store = self._state_store
        assert action.execution_id is not None
        execution_id = sanitize_value(action.execution_id)
        existing_actions = self._persistence_call(
            task,
            partial(store.list_actions, task.id),
        )
        for existing_action in existing_actions:
            unresolved = existing_action.status in {
                ActionExecutionStatus.EXECUTING,
                ActionExecutionStatus.RECONCILING,
                ActionExecutionStatus.UNCERTAIN,
                ActionExecutionStatus.FAILED,
            } or (
                existing_action.status is ActionExecutionStatus.COMPLETED
                and existing_action.verification_status
                in {
                    VerificationStatus.PENDING,
                    VerificationStatus.FAILED,
                    VerificationStatus.UNCERTAIN,
                }
            )
            if unresolved and existing_action.action_id != execution_id:
                self._event(
                    "action.duplicate_blocked",
                    task,
                    {
                        "execution_id": execution_id,
                        "blocked_by": existing_action.action_id,
                        "reason": "task has an unresolved prior action",
                    },
                )
                if existing_action.status in {
                    ActionExecutionStatus.EXECUTING,
                    ActionExecutionStatus.RECONCILING,
                    ActionExecutionStatus.UNCERTAIN,
                }:
                    self._event(
                        "action.uncertain_detected",
                        task,
                        {"execution_id": existing_action.action_id, "reason": "new action cannot bypass unresolved journal entry"},
                    )
                return None
        record = self._persistence_call(
            task,
            partial(store.get_action, task.id, execution_id),
        )
        if record is None:
            record = ActionExecutionRecord(
                action_id=execution_id,
                task_id=task.id,
                name=action.name,
                status=ActionExecutionStatus.NEVER_ATTEMPTED,
                metadata={
                    "kind": self._kind_value(action.kind),
                    "provider_identity": self._provider_identity(action.name),
                    "parameters": sanitize_value(action.parameters),
                    "identity_fingerprint": fingerprint,
                },
            )
            self._persistence_call(
                task,
                partial(store.save_task_and_action, task, record),
            )
            self._event("action.identity.created", task, {"execution_id": action.execution_id})
            return record
        saved_fingerprint = record.metadata.get("identity_fingerprint")
        if saved_fingerprint is None:
            saved_fingerprint = self._action_fingerprint(
                ActionRequest(
                    task_id=task.id,
                    name=record.name,
                    kind=str(record.metadata.get("kind", ActionKind.UNKNOWN.value)),
                    parameters=record.metadata.get("parameters", {}),
                    execution_id=record.action_id,
                )
            )
        if saved_fingerprint != fingerprint:
            self._event(
                "action.duplicate_blocked",
                task,
                {"execution_id": execution_id, "reason": "execution identity does not match persisted action"},
            )
            return None
        if record.status is ActionExecutionStatus.COMPLETED:
            self._event("action.duplicate_blocked", task, {"execution_id": action.execution_id})
            return None
        if record.status is ActionExecutionStatus.EXECUTING:
            record.status = ActionExecutionStatus.UNCERTAIN
            self._persistence_call(task, partial(store.save_action, record))
            self._event("action.uncertain_detected", task, {"execution_id": action.execution_id})
            return None
        if record.status in {
            ActionExecutionStatus.UNCERTAIN,
            ActionExecutionStatus.RECONCILING,
        }:
            self._event(
                "action.duplicate_blocked",
                task,
                {"execution_id": action.execution_id, "reason": "reconciliation is required"},
            )
            return None
        if record.status is ActionExecutionStatus.FAILED:
            retry_key = (task.id, record.action_id)
            if retry_key not in self._safe_retry_actions:
                self._event("action.duplicate_blocked", task, {"execution_id": action.execution_id, "reason": "failed outcome is not retry-safe"})
                return None
            self._event("action.retry_authorized_by_runtime", task, {"execution_id": action.execution_id})
        return record

    def _persist_task_and_action(self, task: Task, record: ActionExecutionRecord) -> None:
        store = self._state_store
        if store is not None:
            if record.status is not ActionExecutionStatus.EXECUTING:
                record.metadata.pop("execution_owner", None)
            self._persistence_call(
                task,
                partial(store.save_task_and_action, task, record),
            )
            return
        record.updated_at = task.updated_at

    def _set_status(
        self,
        task: Task,
        status: TaskStatus,
        *,
        action_record: ActionExecutionRecord | None = None,
        action_status: ActionExecutionStatus | None = None,
        verification_status: VerificationStatus | None = None,
        verification_reason: str = "",
    ) -> None:
        current = task.status
        store = self._state_store
        if store is not None:
            try:
                TaskStateMachine.assert_transition(current, status)
            except TaskTransitionError:
                self._event(
                    "task.transition_rejected",
                    task,
                    {"from": current.value, "to": status.value},
                )
                raise
        previous_action_state = None
        if action_record is not None:
            previous_action_state = (
                action_record.status,
                action_record.attempts,
                action_record.verification_status,
                action_record.verification_reason,
                dict(action_record.metadata),
            )
        task.status = status
        persisted_with_action = False
        try:
            if action_record is not None:
                if action_status is not None:
                    action_record.status = action_status
                    if action_status is ActionExecutionStatus.EXECUTING:
                        action_record.attempts += 1
                        action_record.metadata["retry_safe"] = False
                        action_record.metadata["execution_owner"] = _RUNTIME_PROCESS_ID
                if status is not TaskStatus.EXECUTING and action_record.status is not ActionExecutionStatus.EXECUTING:
                    action_record.metadata.pop("execution_owner", None)
                if verification_status is not None:
                    action_record.verification_status = verification_status
                if store is not None:
                    if verification_status is not None:
                        self._persistence_call(
                            task,
                            partial(
                                store.save_task_and_verification,
                                task,
                                action_record.action_id,
                                verification_status,
                                verification_reason,
                            ),
                        )
                    else:
                        self._persistence_call(
                            task,
                            partial(store.save_task_and_action, task, action_record),
                        )
                    persisted_with_action = True
            if not persisted_with_action:
                self._persist_task_if_needed(task)
        except Exception:
            task.status = current
            if action_record is not None and previous_action_state is not None:
                (
                    action_record.status,
                    action_record.attempts,
                    action_record.verification_status,
                    action_record.verification_reason,
                    action_record.metadata,
                ) = previous_action_state
            raise
        if store is not None:
            self._event("task.transitioned", task, {"from": current.value, "to": status.value})

    def recover_pending_tasks(self) -> list[tuple[TaskRecord, RestartDecision]]:
        """Inspect unfinished work at runtime initialization; never execute it automatically."""
        store = self._state_store
        if store is None:
            self._restart_decisions = ()
            return []
        checker = RestartSafetyChecker(
            store,
            kill_switch=self._kill_switch,
            audit_sink=self._audit if self._config.audit_required else None,
        )
        decisions: list[tuple[TaskRecord, RestartDecision]] = []
        unfinished = self._persistence_call(
            Task(TrustedInstruction("startup recovery")),
            store.list_unfinished_tasks,
        )
        for task_record in unfinished:
            action_records = self._persistence_call(
                task_record,
                partial(store.list_actions, task_record.task_id),
            )
            for action_record in action_records:
                if action_record.status in {
                    ActionExecutionStatus.EXECUTING,
                    ActionExecutionStatus.RECONCILING,
                }:
                    active_owner = (
                        action_record.metadata.get("execution_owner")
                        if action_record.status is ActionExecutionStatus.EXECUTING
                        else action_record.metadata.get("reconciliation_owner")
                    )
                    if (
                        active_owner == _RUNTIME_PROCESS_ID
                    ):
                        decision = RestartDecision(
                            False,
                            "action lifecycle is still in flight in this runtime process",
                            requires_verification=True,
                            action_status=ActionExecutionStatus.EXECUTING,
                        )
                        self._event(
                            "restart.denied",
                            Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                            {"reason": decision.reason, "execution_id": action_record.action_id},
                        )
                        decisions.append((task_record, decision))
                        break
                    action_record.status = ActionExecutionStatus.UNCERTAIN
                    action_record.outcome = "process restarted during action lifecycle"
                    action_record.metadata["retry_safe"] = False
                    action_record.metadata.pop("execution_owner", None)
                    action_record.metadata.pop("reconciliation_owner", None)
                    self._persistence_call(
                        task_record,
                        partial(store.save_action, action_record),
                    )
                    self._event(
                        "action.uncertain_detected",
                        Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                        {"execution_id": action_record.action_id, "source": "startup_recovery"},
                    )
            else:
                decision = self._persistence_call(
                    task_record,
                    partial(checker.evaluate, task_record.task_id),
                )
            if any(
                item[0].task_id == task_record.task_id
                and item[1].reason == "action lifecycle is still in flight in this runtime process"
                for item in decisions
            ):
                continue
            self._event(
                "restart.current_controls_checked",
                Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                {"allowed": decision.allowed, "reason": decision.reason},
            )
            if not decision.allowed and "kill switch" in decision.reason:
                self._event(
                    "reconciliation.blocked_by_kill_switch",
                    Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                    {"reason": "kill switch engaged during restart recovery"},
                )
                decisions.append((task_record, decision))
                continue
            reconciled = False
            safe_retry_confirmed = False
            current_controls_allow = True
            # Historical approval, policy, and risk are never replayed. Current policy
            # is re-evaluated from the journal, but even an allow does not resume work.
            saved_actions = self._persistence_call(
                task_record,
                partial(store.list_actions, task_record.task_id),
            )
            for saved_action in saved_actions:
                action_is_finished = (
                    saved_action.status is ActionExecutionStatus.COMPLETED
                    and saved_action.verification_status
                    in {
                        VerificationStatus.VERIFIED,
                        VerificationStatus.NOT_CONFIGURED,
                    }
                )
                if action_is_finished:
                    continue
                needs_reconciliation = (
                    saved_action.status
                    in {
                        ActionExecutionStatus.EXECUTING,
                        ActionExecutionStatus.RECONCILING,
                        ActionExecutionStatus.UNCERTAIN,
                        ActionExecutionStatus.FAILED,
                    }
                    or (
                        saved_action.status is ActionExecutionStatus.COMPLETED
                        and saved_action.verification_status
                        in {
                            VerificationStatus.PENDING,
                            VerificationStatus.FAILED,
                            VerificationStatus.UNCERTAIN,
                        }
                    )
                )
                reconciliation_request = (
                    self._reconciliation_request(saved_action)
                    if needs_reconciliation
                    else None
                )
                if needs_reconciliation and reconciliation_request is None:
                    current_controls_allow = False
                    decision.allowed = False
                    decision.reason = "persisted action identity integrity failure"
                    self._event(
                        "reconciliation.failed",
                        Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                        {
                            "execution_id": saved_action.action_id,
                            "reason": "persisted action identity integrity failure",
                        },
                    )
                    break
                kind_value = saved_action.metadata.get("kind")
                try:
                    raw_kind = kind_value.value if isinstance(kind_value, ActionKind) else str(kind_value)
                    raw_kind = raw_kind.rsplit(".", 1)[-1].lower()
                    kind = ActionKind(raw_kind)
                except ValueError:
                    kind = ActionKind.UNKNOWN
                request = ActionRequest(
                    task_id=task_record.task_id,
                    name=saved_action.name,
                    kind=kind,
                    parameters=saved_action.metadata.get("parameters", {}),
                    execution_id=saved_action.action_id,
                )
                current_decision = self._policy.evaluate(request)
                self._event(
                    "restart.current_policy_evaluated",
                    Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                    {"allowed": current_decision.allowed, "risk": current_decision.risk.value},
                )
                if not current_decision.allowed:
                    current_controls_allow = False
                    decision.allowed = False
                    decision.reason = "current runtime policy denies persisted action"
                    if saved_action.status in {
                        ActionExecutionStatus.EXECUTING,
                        ActionExecutionStatus.RECONCILING,
                        ActionExecutionStatus.UNCERTAIN,
                        ActionExecutionStatus.FAILED,
                    }:
                        self._event(
                            "reconciliation.blocked_by_current_policy",
                            Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                            {"execution_id": saved_action.action_id, "risk": current_decision.risk.value},
                        )
                    self._event(
                        "restart.current_policy_denied",
                        Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                        {"execution_id": saved_action.action_id, "risk": current_decision.risk.value},
                    )
                    break
                if current_decision.requires_approval:
                    approved = self._approval is not None and self._approval.approve(
                        ApprovalRequest(task_record.task_id, request, current_decision)
                    )
                    self._event(
                        "restart.current_approval_evaluated",
                        Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                        {"approved": approved},
                    )
                    if not approved:
                        current_controls_allow = False
                        decision.allowed = False
                        decision.reason = "current approval is required and was not granted"
                        self._event(
                            "reconciliation.blocked_by_current_policy",
                            Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                            {"execution_id": saved_action.action_id, "reason": "current approval unavailable"},
                        )
                        self._event(
                            "restart.current_approval_denied",
                            Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                            {"execution_id": saved_action.action_id},
                        )
                        break
                if needs_reconciliation:
                    assert reconciliation_request is not None
                    outcome = self._reconcile_action_record(
                        task_record,
                        saved_action,
                        reconciliation_request,
                        current_controls_checked=True,
                    )
                    reconciled = outcome in {
                        ActionReconciliationOutcome.CONFIRMED_COMPLETED,
                        ActionReconciliationOutcome.CONFIRMED_NOT_EXECUTED,
                    }
                    safe_retry_confirmed = (
                        outcome is ActionReconciliationOutcome.CONFIRMED_NOT_EXECUTED
                    )
                    if safe_retry_confirmed and task_record.status in {
                        TaskStatus.EXECUTING,
                        TaskStatus.VERIFYING,
                    }:
                        task_record.status = TaskStatus.FAILED
                        task_record.last_error = "reconciliation confirmed no external effect"
                        self._persistence_call(
                            task_record,
                            partial(store.save_task_and_action, task_record, saved_action),
                        )
                    elif safe_retry_confirmed:
                        self._persistence_call(
                            task_record,
                            partial(store.save_action, saved_action),
                        )
            if reconciled and current_controls_allow and task_record.status in {
                TaskStatus.EXECUTING,
                TaskStatus.VERIFYING,
            }:
                reconciled_actions = self._persistence_call(
                    task_record,
                    partial(store.list_actions, task_record.task_id),
                )
                all_resolved = bool(reconciled_actions) and all(
                    saved.status is ActionExecutionStatus.COMPLETED
                    and saved.verification_status
                    in {VerificationStatus.VERIFIED, VerificationStatus.NOT_CONFIGURED}
                    for saved in reconciled_actions
                )
                verified_action = next(
                    (
                        saved
                        for saved in reconciled_actions
                        if saved.status is ActionExecutionStatus.COMPLETED
                        and saved.verification_status is VerificationStatus.VERIFIED
                    ),
                    None,
                )
                if all_resolved and verified_action is not None:
                    task_record.status = TaskStatus.SUCCEEDED
                    task_record.verification_state = "verified"
                    self._persistence_call(
                        task_record,
                        partial(
                            store.save_task_and_verification,
                            task_record,
                            verified_action.action_id,
                            VerificationStatus.VERIFIED,
                            verified_action.verification_reason,
                        ),
                    )
            if reconciled and current_controls_allow and safe_retry_confirmed:
                decision = RestartDecision(
                    True,
                    "current reconciliation confirmed the action did not occur",
                    action_status=ActionExecutionStatus.FAILED,
                )
                self._event(
                    "restart.allowed",
                    Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                    {"reason": decision.reason},
                )
            elif reconciled and current_controls_allow:
                decision = self._persistence_call(
                    task_record,
                    partial(checker.evaluate, task_record.task_id),
                )
            if not decision.allowed:
                self._event(
                    "restart.denied",
                    Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                    {"reason": decision.reason},
                )
            decisions.append((task_record, decision))
        self._restart_decisions = tuple(decisions)
        return decisions

    @property
    def restart_decisions(self) -> tuple[tuple[TaskRecord, RestartDecision], ...]:
        """Read-only startup recovery decisions for the application lifecycle."""
        return self._restart_decisions

    def kill_switch_active(self) -> bool:
        """Return the live kill-switch state without exposing a control operation."""
        return self._kill_switch.is_engaged()

    def reconcile_action(
        self, task_id: UUID | str, execution_id: str
    ) -> ActionReconciliationOutcome:
        """Ask the configured independent reconciler about a persisted uncertain action.

        This method never invokes the action provider and never retries the action.
        """
        with self._reconciliation_lock:
            return self._reconcile_action(task_id, execution_id)

    def _reconcile_action(
        self, task_id: UUID | str, execution_id: str
    ) -> ActionReconciliationOutcome:
        store = self._state_store
        if store is None:
            raise ValueError("reconciliation requires persistent state")
        task_record = store.load_task(task_id)
        if task_record is None:
            raise ValueError("task not found")
        action_record = store.get_action(task_record.task_id, execution_id)
        if action_record is None:
            raise ValueError("action not found")
        if action_record.status is not ActionExecutionStatus.UNCERTAIN:
            raise ValueError("only uncertain actions can be reconciled")
        request = self._reconciliation_request(action_record)
        if request is None:
            self._event(
                "reconciliation.failed",
                Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                {
                    "execution_id": action_record.action_id,
                    "reason": "persisted action identity integrity failure",
                },
            )
            return ActionReconciliationOutcome.RECONCILIATION_FAILED
        if self._kill_switch.is_engaged():
            self._event(
                "reconciliation.blocked_by_kill_switch",
                Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                {"execution_id": action_record.action_id},
            )
            return ActionReconciliationOutcome.STILL_UNCERTAIN
        decision = self._policy.evaluate(request.action)
        self._event(
            "reconciliation.current_policy_evaluated",
            Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
            {"execution_id": action_record.action_id, "allowed": decision.allowed, "risk": decision.risk.value},
        )
        if not decision.allowed:
            self._event(
                "reconciliation.blocked_by_current_policy",
                Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                {"execution_id": action_record.action_id, "risk": decision.risk.value},
            )
            return ActionReconciliationOutcome.STILL_UNCERTAIN
        if decision.requires_approval:
            approved = self._approval is not None and self._approval.approve(
                ApprovalRequest(task_record.task_id, request.action, decision)
            )
            if not approved:
                self._event(
                    "reconciliation.blocked_by_current_policy",
                    Task(TrustedInstruction(task_record.objective), id=task_record.task_id),
                    {"execution_id": action_record.action_id, "reason": "current approval unavailable"},
                )
                return ActionReconciliationOutcome.STILL_UNCERTAIN
        return self._reconcile_action_record(
            task_record,
            action_record,
            request,
            current_controls_checked=True,
            source="service_api",
        )

    @staticmethod
    def _kind_value(kind: ActionKind | str) -> str:
        return kind.value if isinstance(kind, ActionKind) else str(kind)

    @classmethod
    def _action_fingerprint(cls, action: ActionRequest) -> str:
        identity = {
            "name": action.name,
            "kind": cls._kind_value(action.kind),
            "parameters": sanitize_value(action.parameters),
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _provider_identity(action_name: str) -> str:
        return action_name.partition(".")[0]

    def _reconciliation_request(
        self, record: ActionExecutionRecord
    ) -> ActionReconciliationRequest | None:
        metadata = record.metadata
        provider_identity = metadata.get("provider_identity")
        fingerprint = metadata.get("identity_fingerprint")
        parameters = metadata.get("parameters")
        kind_value = metadata.get("kind")
        if (
            not isinstance(provider_identity, str)
            or not provider_identity
            or provider_identity != self._provider_identity(record.name)
            or not isinstance(fingerprint, str)
            or not fingerprint
            or not isinstance(parameters, dict)
            or not all(isinstance(key, str) for key in parameters)
            or not isinstance(kind_value, str)
        ):
            return None
        try:
            kind = ActionKind(kind_value.rsplit(".", 1)[-1].lower())
        except ValueError:
            return None
        action = ActionRequest(
            task_id=record.task_id,
            name=record.name,
            kind=kind,
            parameters=parameters,
            execution_id=record.action_id,
        )
        if self._action_fingerprint(action) != fingerprint:
            return None
        return ActionReconciliationRequest(
            task_id=record.task_id,
            execution_id=record.action_id,
            provider_identity=provider_identity,
            action_fingerprint=fingerprint,
            action=action,
        )

    def _reconcile_action_record(
        self,
        task_record: TaskRecord,
        action_record: ActionExecutionRecord,
        request: ActionReconciliationRequest,
        *,
        current_controls_checked: bool = False,
        source: str = "startup_recovery",
    ) -> ActionReconciliationOutcome:
        task = Task(TrustedInstruction(task_record.objective), id=task_record.task_id)
        store = self._state_store
        if store is None:
            return ActionReconciliationOutcome.RECONCILIATION_FAILED
        if self._kill_switch.is_engaged():
            self._event(
                "reconciliation.blocked_by_kill_switch",
                task,
                {"execution_id": action_record.action_id},
            )
            return ActionReconciliationOutcome.STILL_UNCERTAIN
        if (
            request.task_id != task_record.task_id
            or request.execution_id != action_record.action_id
            or request.action.task_id != task_record.task_id
            or request.action.execution_id != action_record.action_id
            or self._action_fingerprint(request.action) != request.action_fingerprint
        ):
            self._event(
                "reconciliation.failed",
                task,
                {"execution_id": action_record.action_id, "reason": "reconciliation identity integrity failure"},
            )
            return ActionReconciliationOutcome.RECONCILIATION_FAILED
        if not current_controls_checked:
            current_decision = self._policy.evaluate(request.action)
            if not current_decision.allowed:
                self._event(
                    "reconciliation.blocked_by_current_policy",
                    task,
                    {"execution_id": action_record.action_id, "risk": current_decision.risk.value},
                )
                return ActionReconciliationOutcome.STILL_UNCERTAIN
            if current_decision.requires_approval:
                approved = self._approval is not None and self._approval.approve(
                    ApprovalRequest(task_record.task_id, request.action, current_decision)
                )
                if not approved:
                    self._event(
                        "reconciliation.blocked_by_current_policy",
                        task,
                        {"execution_id": action_record.action_id, "reason": "current approval unavailable"},
                    )
                    return ActionReconciliationOutcome.STILL_UNCERTAIN
        if self._action_reconciler is None:
            self._event(
                "reconciliation.still_uncertain",
                task,
                {"execution_id": action_record.action_id, "reason": "no independent reconciler configured"},
            )
            return ActionReconciliationOutcome.STILL_UNCERTAIN

        action_record.status = ActionExecutionStatus.RECONCILING
        action_record.metadata["reconciliation_owner"] = _RUNTIME_PROCESS_ID
        self._persistence_call(
            task_record,
            partial(store.save_action, action_record),
        )
        try:
            self._event(
                "reconciliation.started",
                task,
                {
                    "execution_id": action_record.action_id,
                    "provider_identity": request.provider_identity,
                    "action_fingerprint": request.action_fingerprint,
                },
            )
            result = self._action_reconciler.reconcile(request)
        except Exception as error:  # noqa: BLE001 - reconciliation failure must remain fail-closed
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = "reconciliation failed"
            action_record.metadata.pop("reconciliation_owner", None)
            self._persistence_call(
                task_record,
                partial(store.save_action, action_record),
            )
            self._event(
                "reconciliation.failed",
                task,
                {
                    "execution_id": action_record.action_id,
                    "error": sanitize_exception(error),
                },
            )
            return ActionReconciliationOutcome.RECONCILIATION_FAILED

        if not isinstance(result, ActionReconciliationResult) or not isinstance(
            result.outcome, ActionReconciliationOutcome
        ):
            outcome = ActionReconciliationOutcome.RECONCILIATION_FAILED
            reason = "reconciler returned an invalid result"
        else:
            outcome = result.outcome
            reason = sanitize_value(result.reason) if isinstance(result.reason, str) else ""

        if outcome is ActionReconciliationOutcome.CONFIRMED_COMPLETED:
            action_record.status = ActionExecutionStatus.COMPLETED
            action_record.outcome = reason
            action_record.verification_status = VerificationStatus.VERIFIED
            action_record.verification_reason = reason
            event_type = "reconciliation.confirmed_completed"
        elif outcome is ActionReconciliationOutcome.CONFIRMED_NOT_EXECUTED:
            action_record.status = ActionExecutionStatus.FAILED
            action_record.outcome = reason
            action_record.metadata["retry_safe"] = True
            self._safe_retry_actions.add((task_record.task_id, action_record.action_id))
            event_type = "reconciliation.confirmed_not_executed"
        elif outcome is ActionReconciliationOutcome.RECONCILIATION_FAILED:
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = "reconciliation failed"
            event_type = "reconciliation.failed"
        else:
            action_record.status = ActionExecutionStatus.UNCERTAIN
            action_record.outcome = reason
            event_type = "reconciliation.still_uncertain"

        action_record.metadata.pop("execution_owner", None)
        action_record.metadata.pop("reconciliation_owner", None)
        self._persistence_call(
            task_record,
            partial(store.save_action, action_record),
        )
        self._event(
            event_type,
            task,
            {"execution_id": action_record.action_id, "reason": reason},
        )
        self._event(
            "action.reconciled",
            task,
            {
                "execution_id": action_record.action_id,
                "outcome": outcome.value,
                "source": source,
            },
        )
        return outcome

    def resume_task(self, task: Task, action: ActionRequest) -> ExecutionResult:
        """Resume only a known-safe persisted task; run() repeats all current controls."""
        if self._state_store is None:
            return ExecutionResult(False, reason="restart recovery requires persistent state", failure_type="recovery_unavailable")
        decision = RestartSafetyChecker(
            self._state_store,
            kill_switch=self._kill_switch,
            audit_sink=self._audit if self._config.audit_required else None,
        ).evaluate(task.id)
        if self._kill_switch.is_engaged():
            self._event("restart.resume_blocked", task, {"reason": "kill switch engaged"})
            return ExecutionResult(False, reason="kill switch engaged", failure_type="kill_switch")
        current_policy = self._policy.evaluate(action)
        self._event(
            "restart.current_policy_evaluated",
            task,
            {"allowed": current_policy.allowed, "risk": current_policy.risk.value},
        )
        if not current_policy.allowed:
            self._event("restart.current_policy_denied", task, {"reason": current_policy.reason})
            return ExecutionResult(False, reason=current_policy.reason, failure_type="policy_denied")
        if not decision.allowed and not (
            self._action_reconciler is not None
            and decision.requires_verification
            and decision.reason in {
                "action outcome is uncertain; reconciliation required",
                "completed action requires independent verification",
                "execution state is uncertain; fail closed",
                "failed action requires current runtime retry-safety decision",
            }
        ):
            self._event("restart.resume_blocked", task, {"reason": decision.reason})
            return ExecutionResult(False, reason=decision.reason, failure_type="restart_denied")
        if action.task_id != task.id:
            self._event("restart.resume_blocked", task, {"reason": "task/action identity mismatch"})
            return ExecutionResult(False, reason="task/action identity mismatch", failure_type="restart_denied")
        self._event("restart.resume_allowed", task, {"execution_id": action.execution_id or ""})
        return self.run(task, action)

    def complete_task(self, task: Task) -> None:
        if (
            task.status is not TaskStatus.SUCCEEDED
            or task.verification_state
            not in {"verified", "passed", "complete", "not_configured"}
        ):
            self._event(
                "task.transition_rejected",
                task,
                {
                    "from": task.status.value,
                    "to": TaskStatus.COMPLETED.value,
                    "verification_state": task.verification_state,
                },
            )
            raise TaskTransitionError(
                f"illegal task completion from {task.status.value} with verification {task.verification_state}"
            )
        self._set_status(task, TaskStatus.COMPLETED)
        self._event("task.completed", task)

    def _verification_failure(self, task: Task, reason: str) -> ExecutionResult:
        if task.status is not TaskStatus.FAILED:
            self._set_status(task, TaskStatus.FAILED)
        self._event("task.failed", task, {"error": "verification failed"})
        if self._recovery is not None:
            self._event("recovery.started", task)
            self._recovery.recover(task.id, RuntimeError("verification failed"))
        return ExecutionResult(
            False,
            reason="execution failed",
            failure_type="verification_uncertain",
            retryable=False,
        )

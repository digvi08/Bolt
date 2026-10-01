"""Thin local operator CLI; command handlers delegate to AgentService."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from collections.abc import Mapping, Sequence
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import NoReturn, TextIO, cast
from uuid import UUID

from .application import AgentApplication
from .models import ActionKind
from .persistence import ScheduleType
from .secrets import sanitize_text, sanitize_value
from .service import (
    AgentService,
    AgentServiceError,
    CancelTaskRequest,
    CancelTaskResult,
    ReconciliationResponse,
    ScheduleRequest,
    ServiceErrorCode,
    SubmitTaskRequest,
    SubmitTaskResult,
)


class CliUsageError(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CliUsageError("invalid command usage")


def _json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit safe DTO output as JSON")


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def _datetime(raw: str) -> datetime:
    try:
        result = datetime.fromisoformat(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an ISO-8601 timestamp") from None
    if result.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return result.astimezone(UTC)


def _build_parser() -> _Parser:
    parser = _Parser(prog="bolt", description="Local operator interface for the Bolt agent.")
    parser.add_argument("--database", help=argparse.SUPPRESS)
    parser.add_argument("--debug", action="store_true", help="include a sanitized diagnostic")
    parser.add_argument("--no-color", action="store_true", help="disable color (the CLI is plain text)")
    commands = parser.add_subparsers(dest="top", required=True, parser_class=_Parser)

    task = commands.add_parser("task", help="inspect and submit tasks")
    task_commands = task.add_subparsers(dest="task_command", required=True, parser_class=_Parser)
    submit = task_commands.add_parser("submit", help="submit a user objective")
    submit.add_argument("objective")
    submit.add_argument("--caller-id", default="local")
    submit.add_argument("--idempotency-key")
    _json_flag(submit)
    get = task_commands.add_parser("get", help="show task status")
    get.add_argument("task_id")
    _json_flag(get)
    cancel = task_commands.add_parser("cancel", help="request task cancellation")
    cancel.add_argument("task_id")
    _json_flag(cancel)
    task_list = task_commands.add_parser("list", help="list task status")
    task_list.add_argument("--limit", type=_positive_int, default=100)
    _json_flag(task_list)

    action = commands.add_parser("action", help="inspect or reconcile actions")
    action_commands = action.add_subparsers(dest="action_command", required=True, parser_class=_Parser)
    action_get = action_commands.add_parser("get", help="show action status")
    action_get.add_argument("action_id")
    _json_flag(action_get)
    history = action_commands.add_parser("history", help="show actions for an action's task")
    history.add_argument("action_id")
    history.add_argument("--limit", type=_positive_int, default=100)
    _json_flag(history)
    uncertain = action_commands.add_parser("uncertain", help="list uncertain actions")
    uncertain.add_argument("--limit", type=_positive_int, default=100)
    _json_flag(uncertain)
    reconcile = action_commands.add_parser("reconcile", help="request runtime reconciliation")
    reconcile.add_argument("action_id")
    _json_flag(reconcile)

    schedule = commands.add_parser("schedule", help="manage schedules")
    schedule_commands = schedule.add_subparsers(dest="schedule_command", required=True, parser_class=_Parser)
    create = schedule_commands.add_parser("create", help="create a one-time or interval schedule")
    create.add_argument("--objective", required=True)
    create.add_argument("--action-name", required=True)
    create.add_argument("--action-kind", required=True)
    create.add_argument("--run-at", required=True, type=_datetime)
    create.add_argument("--type", choices=("run_at", "interval", "cron"), default="run_at")
    create.add_argument("--interval-seconds", type=_positive_int)
    create.add_argument("--end-at", type=_datetime)
    create.add_argument("--deadline-at", type=_datetime)
    create.add_argument("--timeout-seconds", type=_positive_float)
    create.add_argument("--parameters-json", default="{}")
    _json_flag(create)
    schedule_get = schedule_commands.add_parser("get", help="show schedule status")
    schedule_get.add_argument("schedule_id")
    _json_flag(schedule_get)
    schedule_list = schedule_commands.add_parser("list", help="list schedules")
    schedule_list.add_argument("--limit", type=_positive_int, default=100)
    _json_flag(schedule_list)
    for operation in ("enable", "disable", "cancel"):
        command = schedule_commands.add_parser(operation)
        command.add_argument("schedule_id")
        _json_flag(command)

    scheduler = commands.add_parser("scheduler", help="control the in-process scheduler")
    scheduler_commands = scheduler.add_subparsers(dest="scheduler_command", required=True, parser_class=_Parser)
    for operation in ("status", "run-once", "start", "stop", "shutdown"):
        command = scheduler_commands.add_parser(operation)
        _json_flag(command)

    audit = commands.add_parser("audit", help="read audit events")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True, parser_class=_Parser)
    audit_list = audit_commands.add_parser("list", help="list filtered audit events")
    audit_list.add_argument("--task-id")
    audit_list.add_argument("--action-id")
    audit_list.add_argument("--schedule-id")
    audit_list.add_argument("--event-type")
    audit_list.add_argument("--since", type=_datetime)
    audit_list.add_argument("--until", type=_datetime)
    audit_list.add_argument("--limit", type=_positive_int, default=100)
    _json_flag(audit_list)

    safety = commands.add_parser("safety", help="read safety status")
    safety_commands = safety.add_subparsers(dest="safety_command", required=True, parser_class=_Parser)
    safety_status = safety_commands.add_parser("status")
    _json_flag(safety_status)
    return parser


def _public(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _public(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, UUID)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if isinstance(value, Mapping):
        return sanitize_value({str(key): _public(item) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return [_public(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError("unsupported public response type")


def _emit(value: object, *, as_json: bool, out: TextIO) -> None:
    public = _public(value)
    if as_json:
        rendered = json.dumps(public, ensure_ascii=True, separators=(",", ":"))
        out.write(rendered + "\n")
        return
    if isinstance(public, dict):
        label = value.__class__.__name__.removesuffix("Response").removesuffix("Result")
        out.write(f"{sanitize_text(label)}\n")
        for key, item in public.items():
            if key == "actions":
                out.writelines(
                    f"Action: {action_item.get('action_id')} [{action_item.get('status')}]\n"
                    for action_item in item
                )
                continue
            if key == "schedules":
                out.writelines(
                    f"Schedule: {schedule_item.get('schedule_id')} [{schedule_item.get('status')}]\n"
                    for schedule_item in item
                )
                continue
            out.write(f"{key.replace('_', ' ').title()}: {sanitize_text(str(item))}\n")
        return
    if isinstance(public, list):
        if not public:
            out.write("No records.\n")
        for item in public:
            if isinstance(item, dict):
                identity = item.get("task_id", item.get("schedule_id", item.get("action_id", "")))
                state = item.get("status", item.get("outcome", ""))
                out.write(f"{identity} [{state}]\n")
            else:
                out.write(f"{item}\n")
        return
    out.write(f"{public}\n")


def _uuid(raw: str) -> UUID:
    try:
        return UUID(raw)
    except (TypeError, ValueError):
        raise CliUsageError("invalid UUID") from None


def _error_exit(error: AgentServiceError) -> int:
    return {
        ServiceErrorCode.INVALID_REQUEST: 2,
        ServiceErrorCode.TASK_NOT_FOUND: 3,
        ServiceErrorCode.SCHEDULE_NOT_FOUND: 3,
        ServiceErrorCode.AUTHORIZATION_REQUIRED: 4,
        ServiceErrorCode.POLICY_DENIED: 4,
        ServiceErrorCode.KILL_SWITCH_ACTIVE: 5,
        ServiceErrorCode.UNCERTAIN: 6,
        ServiceErrorCode.CONFLICT: 7,
        ServiceErrorCode.UNSUPPORTED_CAPABILITY: 8,
        ServiceErrorCode.CANCELLATION_REJECTED: 1,
        ServiceErrorCode.ALREADY_COMPLETED: 1,
        ServiceErrorCode.INTERNAL_FAILURE: 1,
    }[error.code]


def _error_payload(error: AgentServiceError) -> dict[str, str]:
    return {"error": error.code.value, "message": sanitize_text(error.message)}


def _dispatch(
    service: AgentService,
    args: argparse.Namespace,
    application: AgentApplication | None = None,
) -> object:
    top = args.top
    if top == "task":
        if args.task_command == "submit":
            return service.submit_task(
                SubmitTaskRequest(
                    objective=args.objective,
                    idempotency_key=args.idempotency_key,
                    caller_id=args.caller_id,
                )
            )
        if args.task_command == "get":
            return service.get_task(_uuid(args.task_id))
        if args.task_command == "cancel":
            return service.cancel_task(CancelTaskRequest(_uuid(args.task_id)))
        return service.list_tasks(limit=args.limit)
    if top == "action":
        if args.action_command == "get":
            return service.get_action_by_id(args.action_id)
        if args.action_command == "history":
            return service.get_action_history_by_id(args.action_id, limit=args.limit)
        if args.action_command == "uncertain":
            return service.get_uncertain_actions(limit=args.limit)
        action = service.get_action_by_id(args.action_id)
        return service.request_reconciliation(action.task_id, action.action_id)
    if top == "schedule":
        if args.schedule_command == "create":
            try:
                parameters = json.loads(args.parameters_json)
            except json.JSONDecodeError:
                raise CliUsageError("parameters JSON is invalid") from None
            if not isinstance(parameters, dict):
                raise CliUsageError("parameters JSON must be an object")
            try:
                action_kind = ActionKind(args.action_kind)
            except ValueError:
                raise CliUsageError("unsupported action kind") from None
            return service.create_schedule(
                ScheduleRequest(
                    objective=args.objective,
                    action_name=args.action_name,
                    action_kind=action_kind,
                    run_at=args.run_at,
                    parameters=parameters,
                    schedule_type=ScheduleType(args.type),
                    interval_seconds=args.interval_seconds,
                    end_at=args.end_at,
                    deadline_at=args.deadline_at,
                    execution_timeout_seconds=args.timeout_seconds,
                )
            )
        if args.schedule_command == "get":
            return service.get_schedule(args.schedule_id)
        if args.schedule_command == "list":
            return service.list_schedules(limit=args.limit)
        if args.schedule_command == "enable":
            return service.enable_schedule(args.schedule_id)
        if args.schedule_command == "disable":
            return service.disable_schedule(args.schedule_id)
        return service.cancel_schedule(args.schedule_id)
    if top == "scheduler":
        if args.scheduler_command == "status":
            return service.scheduler_status()
        if args.scheduler_command == "run-once":
            return asyncio.run(
                application.run_scheduler_once()
                if application is not None
                else service.run_scheduler_once()
            )
        if args.scheduler_command == "start":
            return asyncio.run(_start_foreground(service, application))
        if args.scheduler_command == "stop":
            return asyncio.run(
                application.stop_scheduler()
                if application is not None
                else service.stop_scheduler()
            )
        return asyncio.run(
            application.shutdown() if application is not None else service.shutdown()
        )
    if top == "audit":
        return service.list_audit_events(
            task_id=_uuid(args.task_id) if args.task_id else None,
            action_id=args.action_id,
            schedule_id=args.schedule_id,
            event_type=args.event_type,
            since=args.since,
            until=args.until,
            limit=args.limit,
        )
    if top == "safety":
        return service.scheduler_status()
    raise CliUsageError("unsupported command")


async def _start_foreground(
    service: AgentService,
    application: AgentApplication | None = None,
) -> object:
    if application is not None:
        await application.start_scheduler()
    else:
        await service.start_scheduler()
    try:
        await asyncio.Event().wait()
    finally:
        if application is not None:
            await application.stop_scheduler()
        else:
            await service.stop_scheduler()
    return service.scheduler_status()


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    service: AgentService | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except CliUsageError:
        err.write("ERROR: invalid command usage\n")
        return 2
    own_service = service is None
    active_service: AgentService
    application: AgentApplication | None = None
    try:
        if service is None:
            application = AgentApplication(args.database)
            application.start()
            active_service = application.service
        else:
            active_service = service
        result = _dispatch(active_service, args, application)
        if args.top == "task" and args.task_command == "submit":
            result = cast(SubmitTaskResult, result)
            _emit(result if args.json else result.task, as_json=args.json, out=out)
            if not args.json:
                out.write(
                    "Submission: "
                    + ("reused existing task" if result.duplicate else "created new task")
                    + "\n"
                )
                if result.task.approval_required:
                    out.write("Approval: required\n")
            if result.error is not None:
                err.write(f"ERROR: {sanitize_text(result.error.message)}\n")
                return _error_exit(
                    AgentServiceError(result.error.code, result.error.message)
                )
        elif args.top == "task" and args.task_command == "cancel":
            result = cast(CancelTaskResult, result)
            _emit(result.task, as_json=args.json, out=out)
            if not args.json:
                if result.cancellation_requested:
                    out.write("Cancellation requested; external work may still be running.\n")
                else:
                    out.write("Task cancellation was recorded before execution.\n")
        elif result is not None:
            _emit(result, as_json=getattr(args, "json", False), out=out)
        if (
            args.top == "action"
            and args.action_command == "reconcile"
            and cast(ReconciliationResponse, result).uncertain
        ):
            if not args.json:
                out.write("UNCERTAIN / BLOCKED\n")
            return 6
        if args.top == "scheduler" and args.scheduler_command == "start":
            return 0
        if args.top == "scheduler" and args.scheduler_command == "shutdown":
            if args.json:
                _emit({"shutdown": True}, as_json=True, out=out)
            else:
                out.write("Scheduler shutdown complete.\n")
        return 0
    except AgentServiceError as error:
        if getattr(args, "json", False):
            err.write(json.dumps(_error_payload(error), separators=(",", ":")) + "\n")
        else:
            err.write(f"ERROR: {sanitize_text(error.message)}\n")
        return _error_exit(error)
    except CliUsageError as error:
        err.write(f"ERROR: {sanitize_text(str(error))}\n")
        return 2
    except KeyboardInterrupt:
        err.write("Scheduler stopped by operator.\n")
        return 0
    except Exception as error:  # noqa: BLE001 - never expose raw internals by default
        err.write("ERROR: internal operation failed\n")
        if getattr(args, "debug", False):
            err.write(f"Diagnostic: {sanitize_text(type(error).__name__)}\n")
        return 1
    finally:
        if own_service and application is not None:
            asyncio.run(application.shutdown())


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "run_cli"]

"""Authenticated HTTP adapter over AgentService; contains no provider or database access."""

# FastAPI dependency declarations intentionally call Depends/Security in route signatures.
# ruff: noqa: B008

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, Query, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .api_auth import (
    ApiCredentialStore,
    ApiPrincipal,
    ApiScope,
    AuthenticationRateLimiter,
    CredentialStoreError,
)
from .models import ActionKind
from .persistence import ScheduleType
from .secrets import sanitize_text, sanitize_value
from .service import (
    AgentService,
    AgentServiceError,
    CancelTaskRequest,
    ScheduleRequest,
    ServiceErrorCode,
    SubmitTaskRequest,
)

_REQUEST_ID_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}$")
_SAFE_ERROR_MESSAGES = {
    "INVALID_REQUEST": "The request is invalid.",
    "AUTHENTICATION_FAILED": "Authentication is required or invalid.",
    "AUTHORIZATION_DENIED": "The caller is not authorized for this operation.",
    "NOT_FOUND": "The requested resource was not found.",
    "APPROVAL_REQUIRED": "Execution requires current approval.",
    "POLICY_DENIED": "The current runtime policy denied this operation.",
    "KILL_SWITCH_ACTIVE": "The operation is blocked by the active kill switch.",
    "UNCERTAIN": "The execution outcome is uncertain and remains blocked.",
    "CONFLICT": "The request conflicts with existing state.",
    "UNSUPPORTED_CAPABILITY": "This capability is not supported.",
    "TIMEOUT": "The operation timed out.",
    "INTERNAL_FAILURE": "The operation could not be completed.",
    "RATE_LIMITED": "Too many authentication failures; try again later.",
    "APPLICATION_UNAVAILABLE": "The application is not accepting requests.",
}


class ApiErrorCode(str, Enum):
    INVALID_REQUEST = "INVALID_REQUEST"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    NOT_FOUND = "NOT_FOUND"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    POLICY_DENIED = "POLICY_DENIED"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    UNCERTAIN = "UNCERTAIN"
    CONFLICT = "CONFLICT"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    TIMEOUT = "TIMEOUT"
    INTERNAL_FAILURE = "INTERNAL_FAILURE"
    RATE_LIMITED = "RATE_LIMITED"
    APPLICATION_UNAVAILABLE = "APPLICATION_UNAVAILABLE"


class ApiErrorDetail(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: ApiErrorCode
    message: str
    request_id: str


class ApiErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: ApiErrorDetail


class ApiException(Exception):
    def __init__(
        self,
        code: ApiErrorCode,
        *,
        status_code: int,
        message: str | None = None,
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.status_code = status_code
        self.message = sanitize_text(message or _SAFE_ERROR_MESSAGES[code.value])


class _AuthenticatedFastAPI(FastAPI):
    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is not None:
            return self.openapi_schema
        schema = get_openapi(title=self.title, version=self.version, routes=self.routes)
        schema.setdefault("components", {}).setdefault("securitySchemes", {})[
            "BearerAuth"
        ] = {"type": "http", "scheme": "bearer"}
        for path_item in schema.get("paths", {}).values():
            for operation in path_item.values():
                if isinstance(operation, dict):
                    operation["security"] = [{"BearerAuth": []}]
        self.openapi_schema = schema
        return schema


class SubmitTaskBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=1, max_length=8000)


class ScheduleBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    objective: str = Field(min_length=1, max_length=8000)
    action_name: str = Field(min_length=1, max_length=256)
    action_kind: ActionKind
    run_at: datetime
    parameters: dict[str, Any] = Field(default_factory=dict)
    schedule_type: ScheduleType = ScheduleType.RUN_AT
    interval_seconds: int | None = Field(default=None, gt=0)
    end_at: datetime | None = None
    deadline_at: datetime | None = None
    execution_timeout_seconds: float | None = Field(default=None, gt=0, allow_inf_nan=False)

    @field_validator("run_at", "end_at", "deadline_at")
    @classmethod
    def timestamps_must_include_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return value


class ApiMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        service: AgentService,
        credentials: ApiCredentialStore,
        limiter: AuthenticationRateLimiter,
        lifecycle_state: Callable[[], str] | None = None,
    ) -> None:
        self._app = app
        self._service = service
        self._credentials = credentials
        self._limiter = limiter
        self._lifecycle_state = lifecycle_state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        request = Request(scope, receive)
        request_id = self._request_id(request.headers.get("x-request-id"))
        request.state.request_id = request_id
        response_started = False

        async def send_with_request_id(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        peer = request.client.host if request.client is not None else "unknown"
        try:
            if self._lifecycle_state is not None:
                lifecycle_state = self._lifecycle_state()
                status_request = request.method == "GET" and request.url.path == "/application/status"
                if lifecycle_state not in {"ready", "degraded"} and not status_request:
                    response = self._error_response(
                        request,
                        ApiException(
                            ApiErrorCode.APPLICATION_UNAVAILABLE,
                            status_code=503,
                        ),
                    )
                    await response(scope, receive, send_with_request_id)
                    return
                if lifecycle_state == "degraded" and not status_request:
                    response = self._error_response(
                        request,
                        ApiException(
                            ApiErrorCode.APPLICATION_UNAVAILABLE,
                            status_code=503,
                        ),
                    )
                    await response(scope, receive, send_with_request_id)
                    return
            is_cors_preflight = (
                request.method == "OPTIONS"
                and request.headers.get("origin") is not None
                and request.headers.get("access-control-request-method") is not None
            )
            if is_cors_preflight:
                await self._app(scope, receive, send_with_request_id)
                return
            token = self._bearer_token(request.headers.get("authorization"))
            if not self._limiter.allow_attempt(peer, now=time.monotonic()):
                self._audit(
                    "api.authentication_failed",
                    request_id=request_id,
                    code=ApiErrorCode.RATE_LIMITED.value,
                    method=request.method,
                )
                response = self._error_response(
                    request,
                    ApiException(ApiErrorCode.RATE_LIMITED, status_code=429),
                )
                await response(scope, receive, send_with_request_id)
                return
            else:
                principal = self._credentials.authenticate(token) if token is not None else None
                if principal is None:
                    self._limiter.record_failure(peer, now=time.monotonic())
                    self._audit(
                        "api.authentication_failed",
                        request_id=request_id,
                        code=ApiErrorCode.AUTHENTICATION_FAILED.value,
                        method=request.method,
                    )
                    response = self._error_response(
                        request,
                        ApiException(ApiErrorCode.AUTHENTICATION_FAILED, status_code=401),
                    )
                    response.headers["WWW-Authenticate"] = "Bearer"
                else:
                    self._limiter.record_success(peer)
                    request.state.principal = principal
                    self._audit(
                        "api.authentication_succeeded",
                        request_id=request_id,
                        caller_id=principal.caller_id,
                        method=request.method,
                    )
                    await self._app(scope, receive, send_with_request_id)
                    return
                await response(scope, receive, send_with_request_id)
                return
        except TimeoutError:
            if response_started:
                raise
            response = self._error_response(
                request,
                ApiException(ApiErrorCode.TIMEOUT, status_code=504),
            )
            await response(scope, receive, send_with_request_id)
        except CredentialStoreError:
            if response_started:
                raise
            response = self._error_response(
                request,
                ApiException(ApiErrorCode.INTERNAL_FAILURE, status_code=500),
            )
            await response(scope, receive, send_with_request_id)
        except Exception:
            if response_started:
                raise
            response = self._error_response(
                request,
                ApiException(ApiErrorCode.INTERNAL_FAILURE, status_code=500),
            )
            await response(scope, receive, send_with_request_id)

    def _audit(
        self,
        event_type: str,
        *,
        request_id: str,
        caller_id: str | None = None,
        scope: str | None = None,
        code: str | None = None,
        method: str | None = None,
    ) -> None:
        self._service.record_api_audit_event(
            event_type,
            request_id=request_id,
            caller_id=caller_id,
            scope=scope,
            code=code,
            method=method,
        )

    @staticmethod
    def _request_id(value: str | None) -> str:
        if value is not None and _REQUEST_ID_PATTERN.fullmatch(value):
            try:
                return str(UUID(value))
            except ValueError:
                pass
        return str(uuid4())

    @staticmethod
    def _bearer_token(value: str | None) -> str | None:
        if value is None:
            return None
        scheme, separator, token = value.partition(" ")
        if separator and scheme.lower() == "bearer" and token and len(token) <= 512:
            return token
        return None

    @staticmethod
    def _error_response(request: Request, error: ApiException) -> JSONResponse:
        request_id = getattr(request.state, "request_id", str(uuid4()))
        return JSONResponse(
            status_code=error.status_code,
            content={
                "error": {
                    "code": error.code.value,
                    "message": error.message,
                    "request_id": request_id,
                }
            },
        )


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(sanitize_value(value))
    if isinstance(value, Mapping):
        safe = sanitize_value(value)
        return {str(key): _jsonable(item) for key, item in safe.items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, UUID)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return sanitize_value(value)
    raise TypeError("unsupported service response type")


def _service_error(error: AgentServiceError) -> ApiException:
    if error.code is ServiceErrorCode.INVALID_REQUEST:
        code, status = ApiErrorCode.INVALID_REQUEST, 422
    elif error.code in {ServiceErrorCode.TASK_NOT_FOUND, ServiceErrorCode.SCHEDULE_NOT_FOUND}:
        code, status = ApiErrorCode.NOT_FOUND, 404
    elif error.code is ServiceErrorCode.AUTHORIZATION_REQUIRED:
        code, status = ApiErrorCode.APPROVAL_REQUIRED, 409
    elif error.code is ServiceErrorCode.POLICY_DENIED:
        code, status = ApiErrorCode.POLICY_DENIED, 403
    elif error.code is ServiceErrorCode.KILL_SWITCH_ACTIVE:
        code, status = ApiErrorCode.KILL_SWITCH_ACTIVE, 423
    elif error.code is ServiceErrorCode.UNCERTAIN:
        code, status = ApiErrorCode.UNCERTAIN, 409
    elif error.code is ServiceErrorCode.CONFLICT:
        code, status = ApiErrorCode.CONFLICT, 409
    elif error.code is ServiceErrorCode.UNSUPPORTED_CAPABILITY:
        code, status = ApiErrorCode.UNSUPPORTED_CAPABILITY, 501
    elif error.code in {ServiceErrorCode.ALREADY_COMPLETED, ServiceErrorCode.CANCELLATION_REJECTED}:
        code, status = ApiErrorCode.CONFLICT, 409
    else:
        code, status = ApiErrorCode.INTERNAL_FAILURE, 500
    return ApiException(code, status_code=status)


def create_api_app(
    service: AgentService,
    credential_store: ApiCredentialStore,
    *,
    cors_origins: Sequence[str] = (),
    rate_limiter: AuthenticationRateLimiter | None = None,
    lifecycle_state: Callable[[], str] | None = None,
    lifecycle_status: Callable[[], object] | None = None,
    lifecycle_start_scheduler: Callable[[], Awaitable[object]] | None = None,
    lifecycle_stop_scheduler: Callable[[], Awaitable[object]] | None = None,
    lifecycle_run_scheduler_once: Callable[[], Awaitable[object]] | None = None,
) -> FastAPI:
    """Create a protected API app; app lifecycle does not implicitly start the scheduler."""
    origins = tuple(cors_origins)
    if any(origin == "*" or not origin.startswith(("http://", "https://")) for origin in origins):
        raise ValueError("CORS origins must be explicit HTTP(S) origins; wildcard is forbidden")
    limiter = rate_limiter or AuthenticationRateLimiter()
    app = _AuthenticatedFastAPI(
        title="Bolt Agent API",
        version="1.0.0",
        description=(
            "Authenticated adapter over AgentService. API permissions do not replace runtime "
            "policy, approval, kill-switch, verification, or recovery controls."
        ),
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
            expose_headers=["X-Request-ID"],
        )
    app.add_middleware(
        ApiMiddleware,
        service=service,
        credentials=credential_store,
        limiter=limiter,
        lifecycle_state=lifecycle_state,
    )

    bearer = HTTPBearer(auto_error=False)

    async def authenticated(
        request: Request,
        _credentials: HTTPAuthorizationCredentials | None = Security(bearer),
    ) -> ApiPrincipal:
        principal = getattr(request.state, "principal", None)
        if not isinstance(principal, ApiPrincipal):
            raise ApiException(ApiErrorCode.AUTHENTICATION_FAILED, status_code=401)
        return principal

    def require_scope(scope: ApiScope) -> Callable[..., Any]:
        async def dependency(
            request: Request,
            principal: ApiPrincipal = Depends(authenticated),
        ) -> ApiPrincipal:
            if scope not in principal.scopes:
                service.record_api_audit_event(
                    "api.authorization_denied",
                    request_id=request.state.request_id,
                    caller_id=principal.caller_id,
                    scope=scope.value,
                    code=ApiErrorCode.AUTHORIZATION_DENIED.value,
                    method=request.method,
                )
                raise ApiException(ApiErrorCode.AUTHORIZATION_DENIED, status_code=403)
            return principal

        return dependency

    def audit(
        event_type: str,
        request: Request,
        principal: ApiPrincipal,
        *,
        task_id: UUID | None = None,
        scope: ApiScope | None = None,
    ) -> None:
        route = request.scope.get("route")
        endpoint = getattr(route, "path", None)
        service.record_api_audit_event(
            event_type,
            request_id=request.state.request_id,
            caller_id=principal.caller_id,
            scope=scope.value if scope is not None else None,
            endpoint=endpoint,
            method=request.method,
            task_id=task_id,
        )

    def ensure_resource_access(
        principal: ApiPrincipal,
        kind: str,
        resource_id: str,
        *,
        allow_any_scope: ApiScope,
    ) -> None:
        if allow_any_scope in principal.scopes:
            return
        if not credential_store.owns_resource(kind, resource_id, principal.caller_id):
            raise ApiException(ApiErrorCode.NOT_FOUND, status_code=404)

    @app.exception_handler(ApiException)
    async def handle_api_exception(request: Request, error: ApiException) -> JSONResponse:
        return ApiMiddleware._error_response(request, error)

    @app.exception_handler(AgentServiceError)
    async def handle_service_exception(
        request: Request, error: AgentServiceError
    ) -> JSONResponse:
        return ApiMiddleware._error_response(request, _service_error(error))

    @app.exception_handler(RequestValidationError)
    async def handle_validation_exception(
        request: Request, _error: RequestValidationError
    ) -> JSONResponse:
        return ApiMiddleware._error_response(
            request,
            ApiException(ApiErrorCode.INVALID_REQUEST, status_code=422),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, error: StarletteHTTPException
    ) -> JSONResponse:
        code = ApiErrorCode.NOT_FOUND if error.status_code == 404 else ApiErrorCode.INVALID_REQUEST
        message = _SAFE_ERROR_MESSAGES[code.value]
        return ApiMiddleware._error_response(
            request,
            ApiException(code, status_code=error.status_code, message=message),
        )

    @app.post("/tasks", status_code=200, response_model=dict[str, Any])
    def submit_task(
        body: SubmitTaskBody,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.TASK_SUBMIT)),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=1, max_length=256
        ),
    ) -> JSONResponse:
        result = service.submit_task(
            SubmitTaskRequest(
                objective=body.objective,
                idempotency_key=idempotency_key,
                caller_id=principal.caller_id,
            )
        )
        credential_store.claim_resource("task", str(result.task.task_id), principal.caller_id)
        audit(
            "api.task_submitted",
            request,
            principal,
            task_id=result.task.task_id,
            scope=ApiScope.TASK_SUBMIT,
        )
        if result.error is not None:
            mapped = _service_error(AgentServiceError(result.error.code, result.error.message))
            raise mapped
        return JSONResponse(content=_jsonable(result))

    @app.get("/tasks", response_model=list[dict[str, Any]])
    def list_tasks(
        principal: ApiPrincipal = Depends(require_scope(ApiScope.TASK_READ)),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> JSONResponse:
        tasks = service.list_tasks(limit=limit)
        if ApiScope.TASK_READ_ANY not in principal.scopes:
            tasks = tuple(
                task
                for task in tasks
                if credential_store.owns_resource("task", str(task.task_id), principal.caller_id)
            )
        return JSONResponse(content=_jsonable(tasks))

    @app.get("/tasks/{task_id}", response_model=dict[str, Any])
    def get_task(
        task_id: UUID,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.TASK_READ)),
    ) -> JSONResponse:
        ensure_resource_access(principal, "task", str(task_id), allow_any_scope=ApiScope.TASK_READ_ANY)
        return JSONResponse(content=_jsonable(service.get_task(task_id)))

    @app.post("/tasks/{task_id}/cancel", response_model=dict[str, Any])
    def cancel_task(
        task_id: UUID,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.TASK_CANCEL)),
    ) -> JSONResponse:
        ensure_resource_access(
            principal, "task", str(task_id), allow_any_scope=ApiScope.TASK_CANCEL_ANY
        )
        result = service.cancel_task(CancelTaskRequest(task_id))
        audit(
            "api.task_cancelled",
            request,
            principal,
            task_id=task_id,
            scope=ApiScope.TASK_CANCEL,
        )
        return JSONResponse(content=_jsonable(result))

    @app.get("/actions/uncertain", response_model=list[dict[str, Any]])
    def uncertain_actions(
        principal: ApiPrincipal = Depends(require_scope(ApiScope.ACTION_READ)),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> JSONResponse:
        actions = service.get_uncertain_actions(limit=limit)
        if ApiScope.ACTION_READ_ANY not in principal.scopes:
            actions = tuple(
                action
                for action in actions
                if credential_store.owns_resource("task", str(action.task_id), principal.caller_id)
            )
        return JSONResponse(content=_jsonable(actions))

    @app.get("/actions/{action_id}/history", response_model=list[dict[str, Any]])
    def action_history(
        action_id: str,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.ACTION_READ)),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> JSONResponse:
        action = service.get_action_by_id(action_id)
        ensure_resource_access(
            principal, "task", str(action.task_id), allow_any_scope=ApiScope.ACTION_READ_ANY
        )
        return JSONResponse(
            content=_jsonable(service.get_action_history_by_id(action_id, limit=limit))
        )

    @app.get("/actions/{action_id}", response_model=dict[str, Any])
    def get_action(
        action_id: str,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.ACTION_READ)),
    ) -> JSONResponse:
        action = service.get_action_by_id(action_id)
        ensure_resource_access(
            principal, "task", str(action.task_id), allow_any_scope=ApiScope.ACTION_READ_ANY
        )
        return JSONResponse(content=_jsonable(action))

    @app.post("/actions/{action_id}/reconcile", response_model=dict[str, Any])
    async def reconcile_action(
        action_id: str,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.ACTION_RECONCILE)),
    ) -> JSONResponse:
        if request.query_params or await request.body():
            raise ApiException(ApiErrorCode.INVALID_REQUEST, status_code=422)
        action = service.get_action_by_id(action_id)
        ensure_resource_access(
            principal, "task", str(action.task_id), allow_any_scope=ApiScope.ACTION_RECONCILE_ANY
        )
        audit(
            "api.reconciliation_requested",
            request,
            principal,
            task_id=action.task_id,
            scope=ApiScope.ACTION_RECONCILE,
        )
        result = service.request_reconciliation(action.task_id, action_id)
        return JSONResponse(content=_jsonable(result))

    @app.get("/approvals", response_model=list[dict[str, Any]])
    def list_approvals(
        principal: ApiPrincipal = Depends(require_scope(ApiScope.APPROVAL_READ)),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> JSONResponse:
        approvals = service.list_approvals(limit=limit)
        if ApiScope.APPROVAL_READ_ANY not in principal.scopes:
            approvals = tuple(
                approval
                for approval in approvals
                if credential_store.owns_resource("task", approval.task_id, principal.caller_id)
            )
        return JSONResponse(content=_jsonable(approvals))

    @app.get("/approvals/{approval_id}", response_model=dict[str, Any])
    def get_approval(
        approval_id: str,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.APPROVAL_READ)),
    ) -> JSONResponse:
        approval = service.get_approval(approval_id)
        ensure_resource_access(
            principal,
            "task",
            approval.task_id,
            allow_any_scope=ApiScope.APPROVAL_READ_ANY,
        )
        return JSONResponse(content=_jsonable(approval))

    @app.post("/approvals/{approval_id}/approve", response_model=dict[str, Any])
    async def approve_action(
        approval_id: str,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.APPROVAL_APPROVE)),
    ) -> JSONResponse:
        if request.query_params or await request.body():
            raise ApiException(ApiErrorCode.INVALID_REQUEST, status_code=422)
        approval = service.get_approval(approval_id)
        ensure_resource_access(
            principal,
            "task",
            approval.task_id,
            allow_any_scope=ApiScope.APPROVAL_APPROVE_ANY,
        )
        result = service.approve_approval(approval_id, actor=principal.caller_id)
        audit(
            "api.approval_approved",
            request,
            principal,
            task_id=UUID(approval.task_id),
            scope=ApiScope.APPROVAL_APPROVE,
        )
        return JSONResponse(content=_jsonable(result))

    @app.post("/approvals/{approval_id}/deny", response_model=dict[str, Any])
    async def deny_action(
        approval_id: str,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.APPROVAL_DENY)),
    ) -> JSONResponse:
        if request.query_params or await request.body():
            raise ApiException(ApiErrorCode.INVALID_REQUEST, status_code=422)
        approval = service.get_approval(approval_id)
        ensure_resource_access(
            principal,
            "task",
            approval.task_id,
            allow_any_scope=ApiScope.APPROVAL_DENY_ANY,
        )
        result = service.deny_approval(approval_id, actor=principal.caller_id)
        audit(
            "api.approval_denied",
            request,
            principal,
            task_id=UUID(approval.task_id),
            scope=ApiScope.APPROVAL_DENY,
        )
        return JSONResponse(content=_jsonable(result))

    @app.post("/schedules", response_model=dict[str, Any])
    def create_schedule(
        body: ScheduleBody,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULE_CREATE)),
    ) -> JSONResponse:
        result = service.create_schedule(
            ScheduleRequest(
                objective=body.objective,
                action_name=body.action_name,
                action_kind=body.action_kind,
                run_at=body.run_at,
                parameters=body.parameters,
                schedule_type=body.schedule_type,
                interval_seconds=body.interval_seconds,
                end_at=body.end_at,
                deadline_at=body.deadline_at,
                execution_timeout_seconds=body.execution_timeout_seconds,
            )
        )
        credential_store.claim_resource("task", str(result.task_id), principal.caller_id)
        credential_store.claim_resource("schedule", result.schedule_id, principal.caller_id)
        audit(
            "api.schedule_modified",
            request,
            principal,
            task_id=result.task_id,
            scope=ApiScope.SCHEDULE_CREATE,
        )
        return JSONResponse(content=_jsonable(result))

    @app.get("/schedules", response_model=list[dict[str, Any]])
    def list_schedules(
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULE_READ)),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> JSONResponse:
        schedules = service.list_schedules(limit=limit)
        if ApiScope.SCHEDULE_READ_ANY not in principal.scopes:
            schedules = tuple(
                schedule
                for schedule in schedules
                if credential_store.owns_resource("task", str(schedule.task_id), principal.caller_id)
            )
        return JSONResponse(content=_jsonable(schedules))

    @app.get("/schedules/{schedule_id}", response_model=dict[str, Any])
    def get_schedule(
        schedule_id: str,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULE_READ)),
    ) -> JSONResponse:
        schedule = service.get_schedule(schedule_id)
        ensure_resource_access(
            principal, "task", str(schedule.task_id), allow_any_scope=ApiScope.SCHEDULE_READ_ANY
        )
        return JSONResponse(content=_jsonable(schedule))

    async def mutate_schedule(
        request: Request,
        principal: ApiPrincipal,
        schedule_id: str,
        operation: str,
        scope: ApiScope,
    ) -> JSONResponse:
        schedule = service.get_schedule(schedule_id)
        any_scope = (
            ApiScope.SCHEDULE_CANCEL_ANY
            if operation == "cancel"
            else ApiScope.SCHEDULE_MODIFY_ANY
        )
        ensure_resource_access(principal, "task", str(schedule.task_id), allow_any_scope=any_scope)
        if operation == "enable":
            result = service.enable_schedule(schedule_id)
        elif operation == "disable":
            result = service.disable_schedule(schedule_id)
        else:
            result = service.cancel_schedule(schedule_id)
        audit(
            "api.schedule_modified",
            request,
            principal,
            task_id=schedule.task_id,
            scope=scope,
        )
        return JSONResponse(content=_jsonable(result))

    @app.post("/schedules/{schedule_id}/enable", response_model=dict[str, Any])
    async def enable_schedule(
        schedule_id: str,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULE_MODIFY)),
    ) -> JSONResponse:
        return await mutate_schedule(
            request, principal, schedule_id, "enable", ApiScope.SCHEDULE_MODIFY
        )

    @app.post("/schedules/{schedule_id}/disable", response_model=dict[str, Any])
    async def disable_schedule(
        schedule_id: str,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULE_MODIFY)),
    ) -> JSONResponse:
        return await mutate_schedule(
            request, principal, schedule_id, "disable", ApiScope.SCHEDULE_MODIFY
        )

    @app.post("/schedules/{schedule_id}/cancel", response_model=dict[str, Any])
    async def cancel_schedule(
        schedule_id: str,
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULE_CANCEL)),
    ) -> JSONResponse:
        return await mutate_schedule(
            request, principal, schedule_id, "cancel", ApiScope.SCHEDULE_CANCEL
        )

    @app.get("/scheduler/status", response_model=dict[str, Any])
    def scheduler_status(
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULER_READ)),
    ) -> JSONResponse:
        del principal
        return JSONResponse(content=_jsonable(service.scheduler_status()))

    if lifecycle_status is not None:
        @app.get("/application/status", response_model=dict[str, Any])
        def application_status(
            _principal: ApiPrincipal = Depends(require_scope(ApiScope.APPLICATION_READ)),
        ) -> JSONResponse:
            return JSONResponse(content=_jsonable(lifecycle_status()))

    @app.post("/scheduler/run-once", response_model=list[dict[str, Any]])
    async def scheduler_run_once(
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULER_CONTROL)),
    ) -> JSONResponse:
        audit("api.scheduler_control_requested", request, principal, scope=ApiScope.SCHEDULER_CONTROL)
        result = (
            await lifecycle_run_scheduler_once()
            if lifecycle_run_scheduler_once is not None
            else await service.run_scheduler_once()
        )
        return JSONResponse(content=_jsonable(result))

    @app.post("/scheduler/start", response_model=dict[str, Any])
    async def scheduler_start(
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULER_CONTROL)),
    ) -> JSONResponse:
        audit("api.scheduler_control_requested", request, principal, scope=ApiScope.SCHEDULER_CONTROL)
        result = (
            await lifecycle_start_scheduler()
            if lifecycle_start_scheduler is not None
            else await service.start_scheduler()
        )
        return JSONResponse(content=_jsonable(result))

    @app.post("/scheduler/stop", response_model=dict[str, Any])
    async def scheduler_stop(
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULER_CONTROL)),
    ) -> JSONResponse:
        audit("api.scheduler_control_requested", request, principal, scope=ApiScope.SCHEDULER_CONTROL)
        result = (
            await lifecycle_stop_scheduler()
            if lifecycle_stop_scheduler is not None
            else await service.stop_scheduler()
        )
        return JSONResponse(content=_jsonable(result))

    @app.post("/scheduler/shutdown", response_model=dict[str, Any])
    async def scheduler_shutdown(
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SCHEDULER_CONTROL)),
    ) -> JSONResponse:
        audit("api.scheduler_control_requested", request, principal, scope=ApiScope.SCHEDULER_CONTROL)
        await service.shutdown()
        return JSONResponse(content={"shutdown": True})

    @app.get("/audit", response_model=list[dict[str, Any]])
    def list_audit(
        request: Request,
        principal: ApiPrincipal = Depends(require_scope(ApiScope.AUDIT_READ)),
        task_id: UUID | None = None,
        action_id: str | None = None,
        schedule_id: str | None = None,
        event_type: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> JSONResponse:
        if task_id is not None:
            ensure_resource_access(
                principal, "task", str(task_id), allow_any_scope=ApiScope.AUDIT_READ_ANY
            )
            events = service.list_audit_events(
                task_id=task_id,
                action_id=action_id,
                schedule_id=schedule_id,
                event_type=event_type,
                since=since,
                until=until,
                limit=limit,
            )
        elif ApiScope.AUDIT_READ_ANY in principal.scopes:
            events = service.list_audit_events(
                action_id=action_id,
                schedule_id=schedule_id,
                event_type=event_type,
                since=since,
                until=until,
                limit=limit,
            )
        else:
            task_records = service.list_tasks(limit=500)
            owned_task_ids = [
                item.task_id
                for item in task_records
                if credential_store.owns_resource("task", str(item.task_id), principal.caller_id)
            ]
            event_groups = [
                service.list_audit_events(
                    task_id=owned_id,
                    action_id=action_id,
                    schedule_id=schedule_id,
                    event_type=event_type,
                    since=since,
                    until=until,
                    limit=limit,
                )
                for owned_id in owned_task_ids
            ]
            events = tuple(
                sorted(
                    (event for group in event_groups for event in group),
                    key=lambda event: event.occurred_at,
                )[-limit:]
            )
        audit(
            "api.audit_read",
            request,
            principal,
            scope=ApiScope.AUDIT_READ,
            task_id=task_id,
        )
        return JSONResponse(content=_jsonable(events))

    @app.get("/safety/status", response_model=dict[str, Any])
    def safety_status(
        principal: ApiPrincipal = Depends(require_scope(ApiScope.SAFETY_READ)),
    ) -> JSONResponse:
        del principal
        return JSONResponse(content=_jsonable(service.scheduler_status()))

    app.state.agent_service = service
    app.state.credential_store = credential_store
    app.state.rate_limiter = limiter
    return app


__all__ = [
    "ApiErrorCode",
    "ApiErrorEnvelope",
    "ApiException",
    "ScheduleBody",
    "SubmitTaskBody",
    "create_api_app",
]

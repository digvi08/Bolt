"""Credential storage and authorization primitives for the HTTP API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from .secrets import Secret, sanitize_exception


class ApiScope(StrEnum):
    APPLICATION_READ = "application.read"
    TASK_READ = "task.read"
    TASK_READ_ANY = "task.read:any"
    TASK_SUBMIT = "task.submit"
    TASK_CANCEL = "task.cancel"
    TASK_CANCEL_ANY = "task.cancel:any"
    ACTION_READ = "action.read"
    ACTION_READ_ANY = "action.read:any"
    ACTION_RECONCILE = "action.reconcile"
    ACTION_RECONCILE_ANY = "action.reconcile:any"
    SCHEDULE_READ = "schedule.read"
    SCHEDULE_READ_ANY = "schedule.read:any"
    SCHEDULE_CREATE = "schedule.create"
    SCHEDULE_MODIFY = "schedule.modify"
    SCHEDULE_MODIFY_ANY = "schedule.modify:any"
    SCHEDULE_CANCEL = "schedule.cancel"
    SCHEDULE_CANCEL_ANY = "schedule.cancel:any"
    SCHEDULER_READ = "scheduler.read"
    SCHEDULER_CONTROL = "scheduler.control"
    AUDIT_READ = "audit.read"
    AUDIT_READ_ANY = "audit.read:any"
    SAFETY_READ = "safety.read"
    APPROVAL_READ = "approval.read"
    APPROVAL_READ_ANY = "approval.read:any"
    APPROVAL_APPROVE = "approval.approve"
    APPROVAL_APPROVE_ANY = "approval.approve:any"
    APPROVAL_DENY = "approval.deny"
    APPROVAL_DENY_ANY = "approval.deny:any"


@dataclass(frozen=True)
class ApiPrincipal:
    caller_id: str
    scopes: frozenset[ApiScope]


@dataclass(frozen=True)
class IssuedCredential:
    credential_id: str
    token: Secret[str]
    scopes: frozenset[ApiScope]


@dataclass(frozen=True)
class CredentialStatus:
    credential_id: str
    scopes: tuple[ApiScope, ...]
    created_at: str
    revoked: bool


class CredentialStoreError(RuntimeError):
    """Credential metadata could not be safely read or updated."""


def default_credential_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        root = Path(local_app_data)
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return root / "bolt" / "api-credentials.json"


class ApiCredentialStore:
    """Stores salted hashes and resource ownership; raw credentials are never persisted."""

    _SCHEMA_VERSION = 1
    _MAX_FILE_BYTES = 2_000_000

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_credential_path()
        self._lock = threading.RLock()
        self._dummy_salt = secrets.token_bytes(32)
        self._dummy_digest = self._digest(self._dummy_salt, secrets.token_urlsafe(32))
        if self.path.exists():
            self._read()

    def create(self, scopes: set[ApiScope] | frozenset[ApiScope]) -> IssuedCredential:
        normalized = self._validate_scopes(scopes)
        with self._lock:
            state = self._read()
            credential_id = uuid4().hex
            token_secret = secrets.token_urlsafe(32)
            salt = secrets.token_bytes(32)
            state["credentials"][credential_id] = {
                "salt": base64.b64encode(salt).decode("ascii"),
                "digest": self._digest(salt, token_secret),
                "scopes": sorted(scope.value for scope in normalized),
                "created_at": datetime.now(UTC).isoformat(),
                "revoked": False,
            }
            self._write(state)
            return IssuedCredential(
                credential_id,
                Secret(f"bolt.{credential_id}.{token_secret}"),
                normalized,
            )

    def rotate(self, credential_id: str) -> IssuedCredential:
        with self._lock:
            state = self._read()
            record = state["credentials"].get(credential_id)
            if record is None or record["revoked"]:
                raise KeyError("credential not found")
            scopes = frozenset(ApiScope(value) for value in record["scopes"])
            token_secret = secrets.token_urlsafe(32)
            salt = secrets.token_bytes(32)
            record["salt"] = base64.b64encode(salt).decode("ascii")
            record["digest"] = self._digest(salt, token_secret)
            record["created_at"] = datetime.now(UTC).isoformat()
            self._write(state)
            return IssuedCredential(
                credential_id,
                Secret(f"bolt.{credential_id}.{token_secret}"),
                scopes,
            )

    def revoke(self, credential_id: str) -> None:
        with self._lock:
            state = self._read()
            record = state["credentials"].get(credential_id)
            if record is None:
                raise KeyError("credential not found")
            record["revoked"] = True
            self._write(state)

    def list_status(self) -> tuple[CredentialStatus, ...]:
        with self._lock:
            state = self._read()
            records = [
                CredentialStatus(
                    credential_id=credential_id,
                    scopes=tuple(ApiScope(value) for value in record["scopes"]),
                    created_at=record["created_at"],
                    revoked=record["revoked"],
                )
                for credential_id, record in state["credentials"].items()
            ]
        return tuple(sorted(records, key=lambda item: item.credential_id))

    def authenticate(self, token: str) -> ApiPrincipal | None:
        parts = token.split(".", 2) if isinstance(token, str) else []
        credential_id = parts[1] if len(parts) == 3 and parts[0] == "bolt" else ""
        token_secret = parts[2] if len(parts) == 3 and parts[0] == "bolt" else ""
        with self._lock:
            state = self._read()
            record = state["credentials"].get(credential_id)
            if record is None:
                expected_salt = self._dummy_salt
                expected_digest = self._dummy_digest
                revoked = True
                scope_values: list[str] = []
            else:
                try:
                    expected_salt = base64.b64decode(record["salt"], validate=True)
                    expected_digest = record["digest"]
                    revoked = record["revoked"]
                    scope_values = record["scopes"]
                except (KeyError, TypeError, ValueError):
                    raise CredentialStoreError("credential record is corrupt") from None
            candidate = self._digest(expected_salt, token_secret)
            matches = hmac.compare_digest(candidate, expected_digest)
            if not matches or revoked or not credential_id:
                return None
            try:
                scopes = frozenset(ApiScope(value) for value in scope_values)
            except ValueError:
                raise CredentialStoreError("credential scope is invalid") from None
            return ApiPrincipal(credential_id, scopes)

    def claim_resource(self, kind: str, resource_id: str, caller_id: str) -> None:
        if kind not in {"task", "schedule"}:
            raise ValueError("unsupported resource kind")
        key = f"{kind}:{resource_id}"
        with self._lock:
            state = self._read()
            owners: dict[str, str] = state["owners"]
            current = owners.get(key)
            if current is not None and current != caller_id:
                raise CredentialStoreError("resource ownership conflict")
            owners[key] = caller_id
            self._write(state)

    def owns_resource(self, kind: str, resource_id: str, caller_id: str) -> bool:
        key = f"{kind}:{resource_id}"
        with self._lock:
            state = self._read()
            owner = state["owners"].get(key)
        return isinstance(owner, str) and hmac.compare_digest(owner, caller_id)

    @staticmethod
    def _validate_scopes(
        scopes: set[ApiScope] | frozenset[ApiScope],
    ) -> frozenset[ApiScope]:
        if not scopes or any(not isinstance(scope, ApiScope) for scope in scopes):
            raise ValueError("at least one recognized API scope is required")
        return frozenset(scopes)

    @staticmethod
    def _digest(salt: bytes, token_secret: str) -> str:
        return hashlib.sha256(salt + token_secret.encode("utf-8")).hexdigest()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": self._SCHEMA_VERSION, "credentials": {}, "owners": {}}
        try:
            if self.path.stat().st_size > self._MAX_FILE_BYTES:
                raise CredentialStoreError("credential store exceeds size limit")
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except CredentialStoreError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CredentialStoreError(
                f"credential store unavailable: {sanitize_exception(error)}"
            ) from None
        if (
            not isinstance(data, dict)
            or data.get("version") != self._SCHEMA_VERSION
            or not isinstance(data.get("credentials"), dict)
            or not isinstance(data.get("owners"), dict)
        ):
            raise CredentialStoreError("credential store has an invalid format")
        for record in data["credentials"].values():
            if (
                not isinstance(record, dict)
                or not isinstance(record.get("salt"), str)
                or not isinstance(record.get("digest"), str)
                or not isinstance(record.get("scopes"), list)
                or not isinstance(record.get("created_at"), str)
                or not isinstance(record.get("revoked"), bool)
            ):
                raise CredentialStoreError("credential record is invalid")
        if any(not isinstance(key, str) or not isinstance(owner, str) for key, owner in data["owners"].items()):
            raise CredentialStoreError("resource ownership data is invalid")
        return data

    def _write(self, state: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            descriptor, temp_name = tempfile.mkstemp(
                prefix=".bolt-api-credentials-", dir=self.path.parent
            )
            temp_path = Path(temp_name)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(state, output, separators=(",", ":"), sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_path, self.path)
        except OSError as error:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise CredentialStoreError(
                f"credential store update failed: {sanitize_exception(error)}"
            ) from None


class AuthenticationRateLimiter:
    """Bounded per-process failed-authentication limiter keyed by peer address."""

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window_seconds: float = 60,
        max_peers: int = 1024,
    ) -> None:
        if max_failures < 1 or window_seconds <= 0 or max_peers < 1:
            raise ValueError("rate-limit settings must be positive")
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_peers = max_peers
        self._lock = threading.Lock()
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()

    def allow_attempt(self, peer: str, *, now: float) -> bool:
        with self._lock:
            attempts = self._failures.get(peer)
            if attempts is None:
                return True
            self._failures.move_to_end(peer)
            self._discard_expired(attempts, now)
            if not attempts:
                self._failures.pop(peer, None)
                return True
            return len(attempts) < self.max_failures

    def record_failure(self, peer: str, *, now: float) -> None:
        with self._lock:
            attempts = self._failures.setdefault(peer, deque())
            self._failures.move_to_end(peer)
            self._discard_expired(attempts, now)
            attempts.append(now)
            while len(self._failures) > self.max_peers:
                self._failures.popitem(last=False)

    def record_success(self, peer: str) -> None:
        with self._lock:
            self._failures.pop(peer, None)

    def _discard_expired(self, attempts: deque[float], now: float) -> None:
        cutoff = now - self.window_seconds
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()


__all__ = [
    "ApiCredentialStore",
    "ApiPrincipal",
    "ApiScope",
    "AuthenticationRateLimiter",
    "CredentialStatus",
    "CredentialStoreError",
    "IssuedCredential",
    "default_credential_path",
]

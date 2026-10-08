"""Scoped credential metadata and fail-closed secret access."""

from __future__ import annotations

import importlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, TypeVar, cast
from uuid import UUID, uuid4

from .models import (
    AbilityId,
    AuditEvent,
    CredentialCallerId,
    CredentialId,
    ProviderId,
)
from .secrets import Secret, sanitize_value

_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
T = TypeVar("T")


class CredentialType(StrEnum):
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    PASSWORD = "password"
    OTHER = "other"


class CredentialState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class CredentialScope:
    caller_id: CredentialCallerId
    ability_id: AbilityId
    provider_id: ProviderId

    def __post_init__(self) -> None:
        for value in (self.caller_id, self.ability_id, self.provider_id):
            if not isinstance(value, str) or not _IDENTITY_PATTERN.fullmatch(value):
                raise ValueError("credential scope identity is invalid")


@dataclass(frozen=True)
class CredentialRecord:
    credential_id: CredentialId
    scope: CredentialScope
    credential_type: CredentialType
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    revoked: bool = False
    version: int = 1
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, str) or not _IDENTITY_PATTERN.fullmatch(
            self.credential_id
        ):
            raise ValueError("credential identity is invalid")
        if not isinstance(self.scope, CredentialScope):
            raise TypeError("credential scope is invalid")
        if not isinstance(self.credential_type, CredentialType):
            raise TypeError("credential type is invalid")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("credential version must be positive")
        if not isinstance(self.revoked, bool):
            raise TypeError("credential revocation state is invalid")
        if not isinstance(self.created_at, datetime) or not isinstance(self.updated_at, datetime):
            raise TypeError("credential timestamps are invalid")
        for value in (self.created_at, self.updated_at, self.expires_at):
            if value is not None and (
                not isinstance(value, datetime) or value.tzinfo is None
            ):
                raise ValueError("credential timestamps must be timezone-aware")
        cleaned = sanitize_value(self.metadata)
        if not isinstance(cleaned, dict):
            raise TypeError("credential metadata must be an object")
        object.__setattr__(self, "metadata", cleaned)


@dataclass(frozen=True)
class CredentialAccessRequest:
    """Runtime-only identity passed to the authoritative runtime gate."""

    task_id: UUID
    execution_id: str
    scope: CredentialScope
    credential_id: CredentialId
    credential_version: int


class CredentialRuntimeAuthority(Protocol):
    def authorize_credential_access(self, request: CredentialAccessRequest) -> bool: ...


class CredentialValueBackend(Protocol):
    """Secret adapter that must independently bind each value to its original scope."""

    def is_available(self) -> bool: ...

    def store(
        self,
        credential_id: CredentialId,
        version: int,
        scope: CredentialScope,
        secret: Secret[str],
    ) -> None: ...

    def retrieve(
        self, credential_id: CredentialId, version: int, scope: CredentialScope
    ) -> Secret[str] | None: ...

    def delete(self, credential_id: CredentialId, version: int) -> None: ...


class CredentialBackendUnavailable(RuntimeError):
    pass


class CredentialStoreError(RuntimeError):
    pass


class UnavailableCredentialValueBackend:
    """Default backend; no plaintext or weakly-protected persistence fallback exists."""

    def is_available(self) -> bool:
        return False

    def store(
        self,
        _credential_id: CredentialId,
        _version: int,
        _scope: CredentialScope,
        _secret: Secret[str],
    ) -> None:
        raise CredentialBackendUnavailable("no secure credential value backend is configured")

    def retrieve(
        self,
        _credential_id: CredentialId,
        _version: int,
        _scope: CredentialScope,
    ) -> Secret[str] | None:
        raise CredentialBackendUnavailable("no secure credential value backend is configured")

    def delete(self, _credential_id: CredentialId, _version: int) -> None:
        raise CredentialBackendUnavailable("no secure credential value backend is configured")


class _WindowsCredentialApi(Protocol):
    CRED_TYPE_GENERIC: int
    CRED_PERSIST_LOCAL_MACHINE: int

    def CredGetSessionTypes(self, maximum_persist_count: int = ...) -> tuple[int, ...]: ...

    def CredWrite(self, credential: dict[str, object], flags: int = ...) -> None: ...

    def CredRead(
        self, target_name: str, credential_type: int, flags: int = ...
    ) -> dict[str, object]: ...

    def CredDelete(
        self, target_name: str, credential_type: int, flags: int = ...
    ) -> None: ...


class WindowsCredentialManagerBackend:
    """Windows Credential Manager adapter using the current user's OS-protected store."""

    _MAX_CREDENTIAL_BLOB_BYTES = 5120

    def __init__(self, api: _WindowsCredentialApi) -> None:
        self._api = api

    def is_available(self) -> bool:
        try:
            return bool(self._api.CredGetSessionTypes())
        except Exception:  # noqa: BLE001 - OS errors must not escape a status check
            return False

    def store(
        self,
        credential_id: CredentialId,
        version: int,
        scope: CredentialScope,
        secret: Secret[str],
    ) -> None:
        value = secret.reveal(purpose="store in Windows Credential Manager")
        if not isinstance(value, str):
            raise CredentialBackendUnavailable("credential value format is unsupported")
        payload = json.dumps(
            {
                "credential_id": str(credential_id),
                "version": version,
                "caller_id": str(scope.caller_id),
                "ability_id": str(scope.ability_id),
                "provider_id": str(scope.provider_id),
                "value": value,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        if len(payload.encode("utf-16-le")) > self._MAX_CREDENTIAL_BLOB_BYTES:
            raise CredentialBackendUnavailable("credential exceeds Windows store size limit")
        failed = False
        try:
            self._api.CredWrite(
                {
                    "TargetName": self._target_name(credential_id, version),
                    "Type": self._api.CRED_TYPE_GENERIC,
                    "CredentialBlob": payload,
                    "Persist": self._api.CRED_PERSIST_LOCAL_MACHINE,
                    "UserName": "Bolt provider credential",
                },
                0,
            )
        except Exception:  # noqa: BLE001 - native OS errors can include credential data
            failed = True
        if failed:
            raise CredentialBackendUnavailable("Windows Credential Manager could not store the value")

    def retrieve(
        self,
        credential_id: CredentialId,
        version: int,
        scope: CredentialScope,
    ) -> Secret[str] | None:
        failed = False
        entry: dict[str, object] = {}
        try:
            entry = self._api.CredRead(
                self._target_name(credential_id, version),
                self._api.CRED_TYPE_GENERIC,
                0,
            )
        except Exception:  # noqa: BLE001 - native OS errors can include credential data
            failed = True
        if failed:
            raise CredentialBackendUnavailable(
                "Windows Credential Manager could not retrieve the value"
            )
        blob = entry.get("CredentialBlob")
        if isinstance(blob, bytes):
            if len(blob) > self._MAX_CREDENTIAL_BLOB_BYTES:
                raise CredentialBackendUnavailable("stored credential record is invalid")
            invalid_encoding = False
            try:
                payload = blob.decode("utf-16-le")
            except UnicodeDecodeError:
                invalid_encoding = True
                payload = ""
            if invalid_encoding:
                raise CredentialBackendUnavailable("stored credential record is invalid")
        elif isinstance(blob, str):
            payload = blob
        else:
            raise CredentialBackendUnavailable("stored credential record is invalid")
        invalid_encoding = False
        try:
            payload_size = len(payload.encode("utf-16-le"))
        except UnicodeEncodeError:
            invalid_encoding = True
            payload_size = 0
        if invalid_encoding:
            raise CredentialBackendUnavailable("stored credential record is invalid")
        if payload_size > self._MAX_CREDENTIAL_BLOB_BYTES:
            raise CredentialBackendUnavailable("stored credential record is invalid")
        invalid_json = False
        record: object = None
        try:
            record = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            invalid_json = True
        if invalid_json:
            raise CredentialBackendUnavailable("stored credential record is invalid")
        if not isinstance(record, dict):
            raise CredentialBackendUnavailable("stored credential record is invalid")
        if (
            record.get("credential_id") != str(credential_id)
            or type(record.get("version")) is not int
            or record["version"] != version
            or record.get("caller_id") != str(scope.caller_id)
            or record.get("ability_id") != str(scope.ability_id)
            or record.get("provider_id") != str(scope.provider_id)
            or not isinstance(record.get("value"), str)
        ):
            raise CredentialBackendUnavailable("stored credential identity does not match")
        return Secret(record["value"])

    def delete(self, credential_id: CredentialId, version: int) -> None:
        failed = False
        try:
            self._api.CredDelete(
                self._target_name(credential_id, version),
                self._api.CRED_TYPE_GENERIC,
                0,
            )
        except Exception:  # noqa: BLE001 - native OS errors can include credential data
            failed = True
        if failed:
            raise CredentialBackendUnavailable("Windows Credential Manager could not delete the value")

    @staticmethod
    def _target_name(credential_id: CredentialId, version: int) -> str:
        return f"Bolt.ProviderCredential.{credential_id}.v{version}"


def create_default_credential_value_backend() -> CredentialValueBackend:
    """Use Windows Credential Manager when pywin32 is installed; otherwise fail closed."""
    import sys

    if sys.platform != "win32":
        return UnavailableCredentialValueBackend()
    try:
        api_module = importlib.import_module("win32cred")
    except ImportError:
        return UnavailableCredentialValueBackend()
    api = cast(_WindowsCredentialApi, api_module)
    return WindowsCredentialManagerBackend(api)


class CredentialHandle:
    """Non-serializable, revocation-aware capability for one credential version."""

    __slots__ = ("_record", "_request", "_reveal")
    _record: CredentialRecord
    _request: CredentialAccessRequest
    _reveal: Callable[[CredentialHandle, str, ProviderId], str]

    def __init__(
        self,
        record: CredentialRecord,
        request: CredentialAccessRequest,
        reveal: Callable[[CredentialHandle, str, ProviderId], str],
    ) -> None:
        object.__setattr__(self, "_record", record)
        object.__setattr__(self, "_request", request)
        object.__setattr__(self, "_reveal", reveal)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("credential handles are immutable")

    def reveal(self, *, purpose: str, audience: ProviderId) -> str:
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("credential access requires a purpose")
        return self._reveal(self, purpose, audience)

    def __repr__(self) -> str:
        return "CredentialHandle([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __reduce__(self) -> tuple[str, tuple[object, ...]]:
        raise TypeError("credential handles cannot be serialized")


class CredentialBroker:
    """Authorizes scoped secret access; metadata is persisted separately from secret values."""

    def __init__(
        self,
        metadata_store: CredentialMetadataStore,
        value_backend: CredentialValueBackend | None = None,
        runtime_authority: CredentialRuntimeAuthority | None = None,
    ) -> None:
        self._metadata = metadata_store
        self._values = (
            value_backend
            if value_backend is not None
            else UnavailableCredentialValueBackend()
        )
        self._runtime = runtime_authority

    def create(
        self,
        *,
        credential_id: CredentialId | None = None,
        scope: CredentialScope,
        credential_type: CredentialType,
        secret: Secret[str],
        expires_at: datetime | None = None,
        metadata: dict[str, object] | None = None,
    ) -> CredentialRecord:
        if not isinstance(secret, Secret):
            raise CredentialStoreError("credential values must be provided as opaque secrets")
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValueError("credential expiry must be timezone-aware")
        credential_id = CredentialId(uuid4().hex) if credential_id is None else credential_id
        if not isinstance(credential_id, str) or not _IDENTITY_PATTERN.fullmatch(credential_id):
            raise ValueError("credential identity is invalid")
        if self._metadata.get_credential_record(credential_id) is not None:
            raise CredentialStoreError("credential already exists")
        now = datetime.now(UTC)
        record = CredentialRecord(
            credential_id=credential_id,
            scope=scope,
            credential_type=credential_type,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            metadata=sanitize_value(metadata if metadata is not None else {}),
        )
        self._backend_call(
            lambda: self._values.store(credential_id, record.version, record.scope, secret),
            "credential value could not be stored",
        )
        try:
            self._metadata.save_credential_record(
                record, self._event("credential.created", record)
            )
        except Exception:  # noqa: BLE001 - roll back backend staging on metadata failure
            failure = CredentialStoreError("credential metadata could not be stored")
        else:
            return record
        self._backend_call(
            lambda: self._values.delete(credential_id, record.version),
            "orphaned credential value cleanup failed",
        )
        raise failure

    def rotate(self, credential_id: CredentialId, secret: Secret[str]) -> CredentialRecord:
        record = self._get_record(credential_id)
        self._assert_active(record)
        if not isinstance(secret, Secret):
            raise CredentialStoreError("credential values must be provided as opaque secrets")
        updated = CredentialRecord(
            credential_id=record.credential_id,
            scope=record.scope,
            credential_type=record.credential_type,
            created_at=record.created_at,
            updated_at=datetime.now(UTC),
            expires_at=record.expires_at,
            version=record.version + 1,
            metadata=dict(record.metadata),
        )
        self._backend_call(
            lambda: self._values.store(credential_id, updated.version, updated.scope, secret),
            "credential rotation could not be stored",
        )
        try:
            self._metadata.save_credential_record(
                updated, self._event("credential.rotated", updated)
            )
        except Exception:  # noqa: BLE001 - remove staged version on metadata failure
            failure = CredentialStoreError("credential rotation metadata could not be stored")
            self._backend_call(
                lambda: self._values.delete(credential_id, updated.version),
                "staged credential cleanup failed",
            )
            raise failure
        self._backend_call(
            lambda: self._values.delete(credential_id, record.version),
            "old credential version cleanup failed",
        )
        return updated

    def revoke(self, credential_id: CredentialId) -> CredentialRecord:
        record = self._get_record(credential_id)
        if record.revoked:
            return record
        updated = CredentialRecord(
            credential_id=record.credential_id,
            scope=record.scope,
            credential_type=record.credential_type,
            created_at=record.created_at,
            updated_at=datetime.now(UTC),
            expires_at=record.expires_at,
            revoked=True,
            version=record.version + 1,
            metadata=dict(record.metadata),
        )
        self._metadata.save_credential_record(
            updated, self._event("credential.revoked", updated)
        )
        self._backend_call(
            lambda: self._values.delete(credential_id, record.version),
            "revoked credential cleanup failed",
        )
        return updated

    def issue_handle(
        self,
        *,
        credential_id: CredentialId,
        scope: CredentialScope,
        task_id: UUID,
        execution_id: str,
        runtime_authority: CredentialRuntimeAuthority | None = None,
    ) -> CredentialHandle:
        record = self._get_record(credential_id)
        request = CredentialAccessRequest(
            task_id=task_id,
            execution_id=execution_id,
            scope=scope,
            credential_id=credential_id,
            credential_version=record.version,
        )
        if scope != record.scope:
            self._audit_access(request, "denied", "scope_mismatch")
            raise CredentialStoreError("credential access denied")
        if record.revoked:
            self._audit_access(request, "denied", "credential_revoked")
            raise CredentialStoreError("credential is not active")
        if record.expires_at is not None and record.expires_at <= datetime.now(UTC):
            self._audit_access(request, "denied", "credential_expired")
            raise CredentialStoreError("credential is not active")
        authority = runtime_authority or self._runtime
        self._authorize(request, authority)
        value = self._retrieve_value(credential_id, record.version, scope)
        if value is None:
            self._audit_access(request, "denied", "value_unavailable")
            raise CredentialBackendUnavailable("credential value is unavailable")
        if authority is None:
            raise CredentialStoreError("credential access denied")
        return CredentialHandle(
            record,
            request,
            lambda handle, purpose, audience: self._reveal(handle, purpose, audience, authority),
        )

    def get_metadata(self, credential_id: CredentialId) -> CredentialRecord:
        return self._get_record(credential_id)

    def list_metadata(self, *, caller_id: CredentialCallerId) -> tuple[CredentialRecord, ...]:
        return self._metadata.list_credential_records(caller_id=caller_id)

    def state(self, credential_id: CredentialId) -> CredentialState:
        record = self._get_record(credential_id)
        if record.revoked:
            return CredentialState.REVOKED
        if record.expires_at is not None and record.expires_at <= datetime.now(UTC):
            return CredentialState.EXPIRED
        try:
            value = self._retrieve_value(credential_id, record.version, record.scope)
        except CredentialStoreError:
            return CredentialState.UNAVAILABLE
        if not isinstance(value, Secret):
            return CredentialState.UNAVAILABLE
        return CredentialState.ACTIVE

    @property
    def backend_available(self) -> bool:
        try:
            return self._values.is_available()
        except Exception:  # noqa: BLE001 - availability is safe metadata and fails closed
            return False

    def _reveal(
        self,
        handle: CredentialHandle,
        _purpose: str,
        audience: ProviderId,
        authority: CredentialRuntimeAuthority,
    ) -> str:
        request = handle._request
        record = self._get_record(request.credential_id)
        if audience != record.scope.provider_id:
            self._audit_access(request, "denied", "audience_mismatch")
            raise CredentialStoreError("credential access denied")
        if (
            record.version != handle._record.version
            or record.scope != handle._record.scope
            or record.revoked
            or record.expires_at is not None
            and record.expires_at <= datetime.now(UTC)
        ):
            self._audit_access(request, "denied", "credential_inactive_or_stale")
            raise CredentialStoreError("credential access denied")
        self._authorize(request, authority)
        value = self._retrieve_value(record.credential_id, record.version, record.scope)
        if value is None:
            self._audit_access(request, "denied", "value_unavailable")
            raise CredentialBackendUnavailable("credential value is unavailable")
        self._audit_access(request, "approved", "runtime_authorized")
        return value.reveal(purpose="authorized credential provider access")

    def _retrieve_value(
        self,
        credential_id: CredentialId,
        version: int,
        scope: CredentialScope,
    ) -> Secret[str] | None:
        value = self._backend_call(
            lambda: self._values.retrieve(credential_id, version, scope),
            "credential value is unavailable",
        )
        if value is not None and not isinstance(value, Secret):
            raise CredentialBackendUnavailable("credential value is unavailable")
        return value

    def _authorize(
        self,
        request: CredentialAccessRequest,
        runtime_authority: CredentialRuntimeAuthority | None,
    ) -> None:
        if runtime_authority is None:
            self._audit_access(request, "denied", "runtime_authority_unavailable")
            raise CredentialStoreError("credential access denied")
        try:
            allowed = runtime_authority.authorize_credential_access(request)
        except Exception:  # noqa: BLE001 - authorization failures must fail closed
            allowed = False
        if not allowed:
            self._audit_access(request, "denied", "runtime_authorization_denied")
            raise CredentialStoreError("credential access denied")

    def _get_record(self, credential_id: CredentialId) -> CredentialRecord:
        failure: CredentialStoreError | None = None
        try:
            record = self._metadata.get_credential_record(credential_id)
        except Exception:  # noqa: BLE001 - corrupt metadata fails closed without exposing row contents
            record = None
            failure = CredentialStoreError("credential metadata is unavailable")
        if failure is not None:
            raise failure
        if record is None:
            raise CredentialStoreError("credential not found")
        return record

    @staticmethod
    def _assert_active(record: CredentialRecord) -> None:
        if record.revoked or (
            record.expires_at is not None and record.expires_at <= datetime.now(UTC)
        ):
            raise CredentialStoreError("credential is not active")

    def _event(self, event_type: str, record: CredentialRecord) -> AuditEvent:
        return AuditEvent(
            event_type,
            UUID(int=0),
            details={
                "credential_id": record.credential_id,
                "caller_id": record.scope.caller_id,
                "ability_id": record.scope.ability_id,
                "provider_id": record.scope.provider_id,
                "credential_type": record.credential_type.value,
                "version": record.version,
                "outcome": "success",
            },
        )

    def _audit_access(
        self, request: CredentialAccessRequest, outcome: str, reason: str
    ) -> None:
        self._metadata.record_audit_event(
            AuditEvent(
                "credential.access_" + outcome,
                request.task_id,
                details={
                    "credential_id": request.credential_id,
                    "caller_id": request.scope.caller_id,
                    "ability_id": request.scope.ability_id,
                    "provider_id": request.scope.provider_id,
                    "execution_id": request.execution_id,
                    "decision_reason": reason,
                    "outcome": outcome,
                },
            )
        )

    @staticmethod
    def _backend_call(operation: Callable[[], T], message: str) -> T:
        try:
            result = operation()
        except Exception:  # noqa: BLE001 - backend errors can contain credential values
            failure = CredentialStoreError(message)
        else:
            return result
        raise failure


class CredentialMetadataStore(Protocol):
    def save_credential_record(self, record: CredentialRecord, event: AuditEvent) -> None: ...

    def get_credential_record(self, credential_id: CredentialId) -> CredentialRecord | None: ...

    def list_credential_records(
        self, *, caller_id: CredentialCallerId
    ) -> tuple[CredentialRecord, ...]: ...

    def record_audit_event(self, event: AuditEvent) -> None: ...


__all__ = [
    "AbilityId",
    "CredentialAccessRequest",
    "CredentialBackendUnavailable",
    "CredentialBroker",
    "CredentialCallerId",
    "CredentialHandle",
    "CredentialId",
    "CredentialRecord",
    "CredentialRuntimeAuthority",
    "CredentialScope",
    "CredentialState",
    "CredentialStoreError",
    "CredentialType",
    "CredentialValueBackend",
    "ProviderId",
    "UnavailableCredentialValueBackend",
    "WindowsCredentialManagerBackend",
    "create_default_credential_value_backend",
]

"""Explicitly rooted, bounded workspace file operations."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from agent_core.models import ActionKind, RiskLevel, VerificationResult
from agent_core.runtime import (
    ActionReconciliationOutcome,
    ActionReconciliationRequest,
    ActionReconciliationResult,
)
from agent_core.secrets import sanitize_text

from .models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult


class WorkspaceAbilityProvider:
    ability = "workspace"
    _MAX_READ_BYTES = 1_000_000
    _MAX_WRITE_BYTES = 256_000
    _MAX_DIRECTORY_ENTRIES = 200

    def __init__(self, root: str | Path) -> None:
        resolved_root = Path(root).expanduser().resolve(strict=True)
        if not resolved_root.is_dir():
            raise ValueError("workspace root must be an existing directory")
        self.root = resolved_root
        self.descriptor = AbilityDescriptor(
            name="workspace",
            description="Read, list, and create bounded files beneath an explicitly configured root.",
            capabilities=("workspace_read", "workspace_list", "workspace_create"),
            supported_actions=("read_text", "list_directory", "write_text"),
            risk_classes=("read", "write"),
            required_permissions=("workspace_root",),
            provider="local-filesystem",
        )

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def action_kind(self, action: str) -> ActionKind:
        return ActionKind.WRITE_FILE if action == "write_text" else ActionKind.READ_ONLY

    def risk_for(self, action: str) -> RiskLevel:
        if action == "write_text":
            return RiskLevel.MEDIUM
        if action in {"read_text", "list_directory"}:
            return RiskLevel.LOW
        return RiskLevel.UNKNOWN

    def verify_action(
        self,
        action: str,
        payload: dict[str, Any],
        result: object,
    ) -> VerificationResult:
        if not isinstance(result, AbilityResult) or not result.success:
            return VerificationResult(False, "workspace provider reported failure")
        raw_path = payload.get("path")
        try:
            path = self._resolve(raw_path)
            value = result.value
            if not isinstance(value, dict) or value.get("path") != path.relative_to(self.root).as_posix():
                return VerificationResult(False, "workspace result path does not match the request")
            if action == "write_text":
                text = payload.get("text")
                if not isinstance(text, str) or not path.is_file() or path.is_symlink():
                    return VerificationResult(False, "created workspace file is unavailable")
                actual = path.read_bytes()
                expected = text.encode("utf-8")
                if (
                    len(actual) > self._MAX_WRITE_BYTES
                    or actual != expected
                    or value.get("sha256") != hashlib.sha256(expected).hexdigest()
                ):
                    return VerificationResult(False, "created workspace file failed content verification")
            elif action == "read_text":
                if not path.is_file() or path.is_symlink() or path.stat().st_size > self._MAX_READ_BYTES:
                    return VerificationResult(False, "workspace read target changed during verification")
                if not isinstance(value.get("text"), str) or value.get("trust") != "untrusted_document":
                    return VerificationResult(False, "workspace read result is malformed")
            elif action == "list_directory":
                if not path.is_dir() or path.is_symlink() or not isinstance(value.get("entries"), list):
                    return VerificationResult(False, "workspace listing result is malformed")
            else:
                return VerificationResult(False, "workspace action has no verification rule")
        except (OSError, ValueError, TypeError):
            return VerificationResult(False, "workspace state could not be independently checked")
        return VerificationResult(True, "workspace result and filesystem state verified")

    def reconcile(self, request: ActionReconciliationRequest) -> ActionReconciliationResult:
        action_request = request.action
        parameters = action_request.parameters
        payload = parameters.get("payload")
        if (
            action_request.name != "workspace.write_text"
            or parameters.get("ability") != "workspace"
            or parameters.get("action") != "write_text"
            or not isinstance(payload, dict)
        ):
            return ActionReconciliationResult(
                ActionReconciliationOutcome.STILL_UNCERTAIN,
                "workspace reconciler supports only create-only text writes",
            )
        try:
            path = self._resolve(payload.get("path"))
            if path.is_symlink():
                raise ValueError("workspace write target became a symlink")
            if not path.exists():
                return ActionReconciliationResult(
                    ActionReconciliationOutcome.CONFIRMED_NOT_EXECUTED,
                    "workspace target does not exist",
                )
            text = payload.get("text")
            if not isinstance(text, str) or not path.is_file():
                raise ValueError("workspace write target is not a regular file")
            actual = path.read_bytes()
            expected = text.encode("utf-8")
            if len(actual) > self._MAX_WRITE_BYTES:
                raise ValueError("workspace target exceeds the write bound")
            if actual == expected:
                return ActionReconciliationResult(
                    ActionReconciliationOutcome.CONFIRMED_COMPLETED,
                    "workspace file content matches the persisted create-only write intent",
                )
            return ActionReconciliationResult(
                ActionReconciliationOutcome.STILL_UNCERTAIN,
                "workspace target exists but does not match the persisted write intent",
            )
        except (OSError, ValueError, TypeError):
            return ActionReconciliationResult(
                ActionReconciliationOutcome.STILL_UNCERTAIN,
                "workspace target could not be safely inspected",
            )

    def execute(
        self,
        action: AbilityAction,
        _context: AbilityContext | None = None,
    ) -> AbilityResult:
        try:
            if action.action == "list_directory":
                return self._list_directory(action.payload.get("path", "."))
            path = self._resolve(action.payload.get("path"))
            if action.action == "read_text":
                return self._read_text(path)
            if action.action == "write_text":
                return self._write_text(path, action.payload.get("text"))
            return AbilityResult(False, reason="unsupported workspace action")
        except (OSError, UnicodeError, ValueError) as error:
            return AbilityResult(
                False,
                reason=sanitize_text(str(error))[:500],
                failure_type="workspace_operation_failed",
            )

    def _resolve(self, raw_path: object) -> Path:
        if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 1024:
            raise ValueError("workspace path is invalid")
        relative = Path(raw_path)
        if relative.is_absolute() or relative.drive or any(
            part in {"..", ""} for part in relative.parts
        ):
            raise ValueError("workspace path must be relative and remain beneath the root")
        candidate = self.root / relative
        current = self.root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("workspace symlinks are not permitted")
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError:
            raise ValueError("workspace path escapes the configured root") from None
        return resolved

    def _list_directory(self, raw_path: object) -> AbilityResult:
        path = self.root if raw_path == "." else self._resolve(raw_path)
        if not path.is_dir():
            raise ValueError("workspace path is not a directory")
        entries: list[dict[str, object]] = []
        for index, item in enumerate(path.iterdir()):
            if index >= self._MAX_DIRECTORY_ENTRIES:
                return AbilityResult(
                    False,
                    reason="directory exceeds the configured entry limit",
                    failure_type="workspace_limit_exceeded",
                )
            if item.is_symlink():
                continue
            entries.append(
                {"name": item.name[:255], "kind": "directory" if item.is_dir() else "file"}
            )
        return AbilityResult(
            True,
            value={"entries": entries, "trust": "untrusted_document"},
            metadata={"trust": "untrusted_document", "bounded": True},
        )

    def _read_text(self, path: Path) -> AbilityResult:
        if not path.is_file() or path.stat().st_size > self._MAX_READ_BYTES:
            raise ValueError("workspace file is missing or exceeds the configured size limit")
        with path.open("rb") as file:
            data = file.read(self._MAX_READ_BYTES + 1)
        if len(data) > self._MAX_READ_BYTES:
            raise ValueError("workspace file exceeds the configured size limit")
        text = data.decode("utf-8")
        return AbilityResult(
            True,
            value={"path": path.relative_to(self.root).as_posix(), "text": sanitize_text(text), "trust": "untrusted_document"},
            metadata={"trust": "untrusted_document", "bounded": True},
        )

    def _write_text(self, path: Path, raw_text: object) -> AbilityResult:
        if (
            not isinstance(raw_text, str)
            or len(raw_text) > self._MAX_WRITE_BYTES
            or len(raw_text.encode("utf-8")) > self._MAX_WRITE_BYTES
        ):
            raise ValueError("workspace text is invalid or exceeds the configured size limit")
        if not path.parent.is_dir() or path.exists():
            raise ValueError("workspace write requires an existing parent and a new file")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file:
                file.write(raw_text)
        except OSError:
            try:
                path.unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise RuntimeError("workspace write failed and partial-file cleanup failed") from cleanup_error
            raise
        return AbilityResult(
            True,
            value={
                "path": path.relative_to(self.root).as_posix(),
                "created": True,
                "sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
            },
            metadata={"bounded": True},
        )


__all__ = ["WorkspaceAbilityProvider"]

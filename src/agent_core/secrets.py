"""Central secret boundaries and bounded sanitization for application data."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Generic, NoReturn, TypeVar
from uuid import UUID

T = TypeVar("T")

REDACTED = "secret_ref:redacted"
_MAX_DEPTH = 16
_MAX_ITEMS = 1000
_MAX_TEXT_LENGTH = 20_000
_MAX_STRING_LENGTH = 20_000

_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<label>
        password|passwd|secret|token|access[_-]?token|refresh[_-]?token|
        api[_-]?key|apikey|access[_-]?key|authorization|cookie|set-cookie|
        session(?:[_-]?id)?|credential|client[_-]?secret|private[_-]?key
    )
    \s*[:=]\s*
    (?P<value>(?:Bearer\s+)?(?:"[^"]*"|'[^']*'|[^\s,;&]+))
    """
)
_SECRET_HEADER = re.compile(r"(?im)\b(cookie|set-cookie|authorization)\s*:\s*[^\r\n]*")
_AUTHORIZATION_VALUE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)[^\s,;]+\s+[^\s,;]+"
)
_COOKIE_ASSIGNMENT = re.compile(r"(?im)(cookie\s*[:=]\s*)[^\r\n]+")
_JSON_SECRET_FIELD = re.compile(
    r"""(?ix)
    (?P<key>["']?
        (?:password|passwd|secret|token|access[_-]?token|refresh[_-]?token|
        api[_-]?key|apikey|access[_-]?key|authorization|cookie|session|
        credential|client[_-]?secret|private[_-]?key)
    ["']?\s*:\s*)
    (?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
    """
)
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BOLT_TOKEN = re.compile(r"\bbolt\.[0-9a-fA-F]{16,64}\.[A-Za-z0-9_-]{20,}")
_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"authorization|cookie|session|credential|private[_-]?key)"
)
_NON_SECRET_TOKEN_METRICS = {
    "inputtokens",
    "maxtotaltokens",
    "maxmodeltokens",
    "outputtokens",
    "tokenbudget",
    "tokencount",
    "tokenusage",
    "tokensused",
    "totaltokens",
}


class Secret(Generic[T]):
    """Opaque secret value; use ``reveal(purpose=...)`` only at its authorized sink.

    Python cannot guarantee memory zeroization: immutable strings and interpreter/runtime
    copies may remain until reclaimed. This wrapper prevents accidental display/serialization,
    not memory inspection by code already holding the object.
    """

    __slots__ = ("_value",)
    _value: T

    def __init__(self, value: T) -> None:
        object.__setattr__(self, "_value", value)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("Secret values are immutable")

    def reveal(self, *, purpose: str) -> T:
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValueError("secret access requires a purpose")
        return self._value

    def __str__(self) -> str:
        return REDACTED

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __format__(self, _format_spec: str) -> str:
        return REDACTED

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret values cannot be pickled")


class SanitizedError(Exception):
    """Error summary safe to pass between application subsystems."""

    def __init__(self, error_type: str, message: str) -> None:
        self.error_type = sanitize_text(error_type)[:128]
        self.safe_message = sanitize_text(message)[:2048]
        super().__init__(f"{self.error_type}: {self.safe_message}")


def sanitize_text(value: str) -> str:
    """Redact recognizable credential syntax and cap untrusted text size."""
    if len(value) > _MAX_TEXT_LENGTH:
        value = value[:_MAX_TEXT_LENGTH] + "…[TRUNCATED]"
    value = _SECRET_HEADER.sub(lambda match: f"{match.group(1)}: {REDACTED}", value)
    value = _AUTHORIZATION_VALUE.sub(r"\1" + REDACTED, value)
    value = _COOKIE_ASSIGNMENT.sub(r"\1" + REDACTED, value)
    value = _JSON_SECRET_FIELD.sub(_sanitize_json_field, value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group('label')}={REDACTED}", value)
    value = _BEARER_TOKEN.sub(f"Bearer {REDACTED}", value)
    return _BOLT_TOKEN.sub(REDACTED, value)


def _sanitize_json_field(match: re.Match[str]) -> str:
    key = match.group("key").split(":", 1)[0].strip().strip("'\"")
    if not _is_sensitive_key(key):
        return match.group(0)
    quote = match.group("value")[0]
    return f"{match.group('key')}{quote}{REDACTED}{quote}"


def _is_sensitive_key(key: object) -> bool:
    try:
        name = str(key).strip()
    except Exception:  # noqa: BLE001 - malformed keys must not expose their representation
        name = type(key).__name__
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    if normalized in _NON_SECRET_TOKEN_METRICS:
        return False
    if normalized.endswith("id") and any(
        marker in normalized for marker in ("credential", "token", "session")
    ):
        return False
    return bool(_SECRET_KEY.search(name))


def _safe_repr(value: object) -> str:
    try:
        return repr(value)
    except Exception:  # noqa: BLE001 - sanitizer must tolerate hostile representation methods
        return type(value).__name__


def sanitize_value(value: Any) -> Any:
    """Recursively produce bounded, deterministic, secret-redacted data.

    Dataclasses and Pydantic-like models become dictionaries. Cycles and over-large
    structures are replaced with explicit markers rather than traversed indefinitely.
    """
    seen: set[int] = set()

    def visit(item: Any, depth: int) -> Any:
        if isinstance(item, Secret):
            return REDACTED
        if isinstance(item, Enum):
            return visit(item.value, depth + 1)
        if isinstance(item, datetime):
            return item.isoformat()
        if isinstance(item, UUID):
            return str(item)
        if isinstance(item, str):
            if len(item) > _MAX_STRING_LENGTH:
                item = item[:_MAX_STRING_LENGTH] + "…[TRUNCATED]"
            return sanitize_text(item)
        if item is None or isinstance(item, (bool, int, float)):
            return item
        if isinstance(item, (bytes, bytearray, memoryview)):
            return REDACTED
        if isinstance(item, BaseException):
            return sanitize_exception(item)
        if depth >= _MAX_DEPTH:
            return "[MAX_DEPTH]"

        identity = id(item)
        if identity in seen:
            return "[CIRCULAR]"

        seen.add(identity)
        try:
            if isinstance(item, Mapping):
                result: dict[str, Any] = {}
                for index, (key, nested) in enumerate(item.items()):
                    if index >= _MAX_ITEMS:
                        result["[TRUNCATED]"] = _MAX_ITEMS
                        break
                    try:
                        safe_key = sanitize_text(str(key))[:256]
                    except Exception:  # noqa: BLE001 - arbitrary mapping keys are untrusted
                        safe_key = type(key).__name__
                    result[safe_key] = REDACTED if _is_sensitive_key(key) else visit(nested, depth + 1)
                return result
            if is_dataclass(item) and not isinstance(item, type):
                result = {}
                for index, descriptor in enumerate(fields(item)):
                    if index >= _MAX_ITEMS:
                        result["[TRUNCATED]"] = _MAX_ITEMS
                        break
                    result[descriptor.name] = (
                        REDACTED
                        if _is_sensitive_key(descriptor.name)
                        else visit(getattr(item, descriptor.name), depth + 1)
                    )
                return result
            model_fields = getattr(type(item), "model_fields", None)
            if not isinstance(model_fields, Mapping):
                model_fields = getattr(type(item), "__fields__", None)
            if isinstance(model_fields, Mapping):
                model_value: dict[str, Any] = {}
                for index, name in enumerate(model_fields):
                    if index >= _MAX_ITEMS:
                        model_value["[TRUNCATED]"] = _MAX_ITEMS
                        break
                    model_value[str(name)] = getattr(item, str(name))
                return visit(model_value, depth + 1)
            model_dump = getattr(item, "model_dump", None)
            if callable(model_dump):
                try:
                    model_value = model_dump(mode="python")
                except TypeError:
                    model_value = model_dump()
                return visit(model_value, depth + 1)
            legacy_dict = getattr(item, "dict", None)
            if callable(legacy_dict) and type(item).__module__.startswith("pydantic"):
                return visit(legacy_dict(), depth + 1)
            if isinstance(item, (list, tuple)):
                result_list = [visit(nested, depth + 1) for nested in item[:_MAX_ITEMS]]
                if len(item) > _MAX_ITEMS:
                    result_list.append("[TRUNCATED]")
                return tuple(result_list) if isinstance(item, tuple) else result_list
            if isinstance(item, (set, frozenset)):
                if len(item) > _MAX_ITEMS:
                    return ["[TRUNCATED]"]
                ordered = sorted(item, key=lambda nested: (type(nested).__name__, _safe_repr(nested)))
                return [visit(nested, depth + 1) for nested in ordered]
            return f"[UNSUPPORTED:{type(item).__name__}]"
        finally:
            seen.discard(identity)

    return visit(value, 0)


def sanitize_exception(error: BaseException) -> str:
    """Return useful exception type/message text without retaining the exception object."""
    try:
        message = str(error)
    except Exception:  # noqa: BLE001 - hostile exception renderers must not cross a boundary
        message = "exception message unavailable"
    return sanitize_text(f"{type(error).__name__}: {message}")


def sanitize_error(error: BaseException) -> SanitizedError:
    """Copy diagnostic text into a fresh exception without preserving causes or traceback."""
    summary = sanitize_exception(error)
    _, _, message = summary.partition(": ")
    return SanitizedError(type(error).__name__, message or summary)


__all__ = [
    "REDACTED",
    "SanitizedError",
    "Secret",
    "sanitize_error",
    "sanitize_exception",
    "sanitize_text",
    "sanitize_value",
]

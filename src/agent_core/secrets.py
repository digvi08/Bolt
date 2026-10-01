"""Central secret sanitization for model, audit, and diagnostic boundaries."""

from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|access[_-]?key|secret|authorization|cookie)"
    r"\s*[:=]\s*([^\s,;]+)"
)
_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|token|api[_-]?key|access[_-]?key|secret|authorization|cookie|private[_-]?key|credential)"
)


def sanitize_text(value: str) -> str:
    return _SECRET_PATTERN.sub(r"\1=secret_ref:redacted", value)


def sanitize_value(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        return {
            str(key): "secret_ref:redacted"
            if _SECRET_KEY_PATTERN.search(str(key))
            else sanitize_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)
    return value


def sanitize_exception(error: BaseException) -> str:
    return sanitize_text(f"{type(error).__name__}: {error}")


__all__ = ["sanitize_exception", "sanitize_text", "sanitize_value"]

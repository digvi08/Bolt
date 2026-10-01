"""Typed Windows desktop automation models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID, uuid4

from agent_core.models import RiskLevel


class DesktopActionType(str, Enum):
    LIST_WINDOWS = "list_windows"
    GET_ACTIVE_WINDOW = "get_active_window"
    OBSERVE_WINDOW = "observe_window"
    FOCUS_WINDOW = "focus_window"
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    TYPE_TEXT = "type_text"
    PRESS_KEY = "press_key"
    HOTKEY = "hotkey"
    SCROLL = "scroll"
    SCREENSHOT = "screenshot"
    MINIMIZE = "minimize"
    MAXIMIZE = "maximize"
    RESTORE = "restore"


class DesktopErrorKind(str, Enum):
    UNKNOWN_ACTION = "unknown_action"
    WINDOW_NOT_FOUND = "window_not_found"
    CONTROL_NOT_FOUND = "control_not_found"
    AMBIGUOUS_TARGET = "ambiguous_target"
    STALE_STATE = "stale_state"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    PROVIDER_FAILURE = "provider_failure"


@dataclass(frozen=True)
class DesktopError(RuntimeError):
    kind: DesktopErrorKind
    message: str = "desktop action failed"

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class DesktopSession:
    id: UUID = field(default_factory=uuid4)
    platform: str = "windows"


@dataclass(frozen=True)
class DesktopWindow:
    title: str
    handle: str
    process_name: str | None = None
    pid: int | None = None
    state: str = "unknown"


@dataclass(frozen=True)
class DesktopTarget:
    window: str | None = None
    control_type: str | None = None
    name: str | None = None
    automation_id: str | None = None
    class_name: str | None = None
    coordinates: tuple[int, int] | None = None


@dataclass(frozen=True)
class DesktopElement:
    control_type: str
    name: str
    automation_id: str | None = None
    class_name: str | None = None
    enabled: bool = True
    visible: bool = True
    bounds: tuple[int, int, int, int] | None = None
    window: str | None = None


@dataclass(frozen=True)
class DesktopObservation:
    window: DesktopWindow
    title: str
    controls: tuple[DesktopElement, ...] = ()
    roles: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    automation_ids: tuple[str | None, ...] = ()
    bounds: tuple[int, int, int, int] | None = None
    enabled: bool = True
    visible: bool = True
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class DesktopScreenshot:
    mime_type: str = "image/png"
    data: bytes = b""
    url: str | None = None


@dataclass(frozen=True)
class DesktopPrecondition:
    expected_window: str | None = None
    expected_control: str | None = None
    expected_control_enabled: bool | None = None
    expected_control_visible: bool | None = None
    expected_text: str | None = None
    expected_active_window: str | None = None


@dataclass(frozen=True)
class DesktopVerificationSpec:
    kind: str
    value: str | None = None


@dataclass(frozen=True)
class DesktopAction:
    action: DesktopActionType
    session_id: UUID | None = None
    target: DesktopTarget | None = None
    value: str | None = None
    key: str | None = None
    hotkey: tuple[str, ...] = ()
    preconditions: tuple[DesktopPrecondition, ...] = ()
    verification: tuple[DesktopVerificationSpec, ...] = ()
    risk: RiskLevel = RiskLevel.MEDIUM
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if self.action in {DesktopActionType.CLICK, DesktopActionType.DOUBLE_CLICK, DesktopActionType.TYPE_TEXT, DesktopActionType.PRESS_KEY, DesktopActionType.SCROLL, DesktopActionType.HOTKEY} and self.target is None:
            raise ValueError("target is required for this desktop action")
        if self.action is DesktopActionType.TYPE_TEXT and self.value is None:
            raise ValueError("value is required for typing")


__all__ = [
    "DesktopAction",
    "DesktopActionType",
    "DesktopElement",
    "DesktopError",
    "DesktopErrorKind",
    "DesktopObservation",
    "DesktopPrecondition",
    "DesktopScreenshot",
    "DesktopSession",
    "DesktopTarget",
    "DesktopVerificationSpec",
    "DesktopWindow",
]

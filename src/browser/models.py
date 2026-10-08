"""Project-owned browser data types with explicit external-content labeling."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID, uuid4

from agent_core.models import ActionKind, ActionRequest, RiskLevel, UntrustedContent
from agent_core.secrets import Secret, sanitize_text


class TrustBoundary(str, Enum):
    TRUSTED_SYSTEM = "trusted_system"
    TRUSTED_USER = "trusted_user"
    UNTRUSTED_WEB = "untrusted_web"
    UNTRUSTED_DOCUMENT = "untrusted_document"
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool_output"


class BrowserActionType(str, Enum):
    NAVIGATE = "navigate"
    GO_BACK = "go_back"
    GO_FORWARD = "go_forward"
    RELOAD = "reload"
    OBSERVE = "observe"
    CLICK = "click"
    FILL = "fill"
    SELECT_OPTION = "select_option"
    PRESS_KEY = "press_key"
    SUBMIT = "submit"
    EXTRACT_TEXT = "extract_text"
    EXTRACT_LINKS = "extract_links"
    SCREENSHOT = "screenshot"
    NEW_TAB = "new_tab"
    CLOSE_TAB = "close_tab"
    WAIT = "wait"
    DOWNLOAD = "download"


class BrowserErrorKind(str, Enum):
    ELEMENT_NOT_FOUND = "element_not_found"
    STALE_ELEMENT = "stale_element"
    NAVIGATION_TIMEOUT = "navigation_timeout"
    PAGE_LOAD_FAILURE = "page_load_failure"
    UNEXPECTED_REDIRECT = "unexpected_redirect"
    POPUP = "popup"
    TRANSIENT = "transient"
    INVALID_ACTION = "invalid_action"
    SESSION = "session"
    UNKNOWN = "unknown"


class BrowserError(RuntimeError):
    def __init__(self, kind: BrowserErrorKind, message: str = "browser operation failed") -> None:
        safe_message = sanitize_text(message)
        super().__init__(safe_message)
        self.kind = kind
        self.safe_message = safe_message


@dataclass(frozen=True)
class BrowserSession:
    id: UUID = field(default_factory=uuid4)
    persistent: bool = False
    state_location: str | None = None


@dataclass(frozen=True)
class BrowserTab:
    id: UUID
    session_id: UUID
    url: str
    title: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", sanitize_text(self.url))
        object.__setattr__(self, "title", sanitize_text(self.title))


@dataclass(frozen=True)
class BrowserElement:
    id: str
    role: str
    accessible_name: UntrustedContent
    text: UntrustedContent
    tag_name: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    trust_boundary: TrustBoundary = TrustBoundary.UNTRUSTED_WEB

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attributes",
            {str(key): sanitize_text(str(value)) for key, value in self.attributes.items()},
        )


@dataclass(frozen=True)
class FormField:
    id: str
    name: str
    field_type: str
    label: UntrustedContent
    value: str | None = field(default=None, repr=False)
    required: bool = False
    sensitive: bool = False
    trust_boundary: TrustBoundary = TrustBoundary.UNTRUSTED_WEB


@dataclass(frozen=True)
class BrowserObservation:
    tab: BrowserTab
    visible_text: UntrustedContent
    elements: tuple[BrowserElement, ...] = ()
    forms: tuple[FormField, ...] = ()
    links: tuple[BrowserElement, ...] = ()
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    trust_boundary: TrustBoundary = TrustBoundary.UNTRUSTED_WEB


@dataclass(frozen=True)
class Screenshot:
    tab_id: UUID
    mime_type: str
    data: Secret[bytes] = field(repr=False)
    url: str
    trust_boundary: TrustBoundary = TrustBoundary.UNTRUSTED_WEB

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", sanitize_text(self.url))


@dataclass(frozen=True)
class NavigationResult:
    tab: BrowserTab
    succeeded: bool
    error: str | None = None


@dataclass(frozen=True)
class BrowserPrecondition:
    expected_role: str | None = None
    expected_name: str | None = None
    expected_label: str | None = None
    expected_url_domain: str | None = None
    expected_text: str | None = None
    expected_type: str | None = None
    required: bool = True

    def matches(self, observation: BrowserObservation | None) -> bool:
        if observation is None:
            return not self.required
        if self.expected_url_domain is not None and self.expected_url_domain not in observation.tab.url:
            return False
        if self.expected_text is not None and self.expected_text not in observation.visible_text.text:
            return False
        if self.expected_name is not None:
            candidate = False
            for element in observation.elements:
                if element.accessible_name.text == self.expected_name:
                    candidate = True
                    break
            if not candidate:
                return False
        return True


class BrowserVerificationSpec:
    def evaluate(self, result: object) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class ExpectedURL(BrowserVerificationSpec):
    url: str
    exact: bool = True

    def evaluate(self, result: object) -> bool:
        candidate = result
        if isinstance(candidate, (BrowserObservation, NavigationResult)):
            current = candidate.tab.url
        elif isinstance(candidate, BrowserTab):
            current = candidate.url
        else:
            current = str(result)
        return current == self.url if self.exact else self.url in current


@dataclass(frozen=True)
class ExpectedText(BrowserVerificationSpec):
    text: str

    def evaluate(self, result: object) -> bool:
        if not isinstance(result, BrowserObservation):
            return False
        return self.text in result.visible_text.text


@dataclass(frozen=True)
class ExpectedElement(BrowserVerificationSpec):
    role: str | None = None
    name: str | None = None
    tag_name: str | None = None

    def evaluate(self, result: object) -> bool:
        if not isinstance(result, BrowserObservation):
            return False
        for element in result.elements:
            if self.role is not None and element.role != self.role:
                continue
            if self.name is not None and element.accessible_name.text != self.name:
                continue
            if self.tag_name is not None and element.tag_name != self.tag_name:
                continue
            return True
        return False


@dataclass(frozen=True)
class ExpectedElementAbsent(BrowserVerificationSpec):
    role: str | None = None
    name: str | None = None

    def evaluate(self, result: object) -> bool:
        if not isinstance(result, BrowserObservation):
            return False
        for element in result.elements:
            if self.role is not None and element.role != self.role:
                continue
            if self.name is not None and element.accessible_name.text != self.name:
                continue
            return False
        return True


@dataclass(frozen=True)
class ExpectedFormValue(BrowserVerificationSpec):
    field_name: str
    value: str

    def evaluate(self, result: object) -> bool:
        if not isinstance(result, BrowserObservation):
            return False
        for form_field in result.forms:
            if form_field.name == self.field_name:
                return form_field.value == self.value
        return False


@dataclass(frozen=True)
class ExpectedDownload(BrowserVerificationSpec):
    filename: str | None = None
    source_url: str | None = None
    destination: str | None = None
    min_size: int | None = None

    def evaluate(self, result: object) -> bool:
        if not isinstance(result, BrowserDownload):
            return False
        if self.filename is not None and result.filename != self.filename:
            return False
        if self.source_url is not None and result.source_url != self.source_url:
            return False
        if self.destination is not None and result.destination != self.destination:
            return False
        if self.min_size is not None:
            return result.size is not None and result.size >= self.min_size
        return True


@dataclass(frozen=True)
class ExpectedStateChange(BrowserVerificationSpec):
    description: str = "state changed"

    def evaluate(self, result: object) -> bool:
        return result is not None


@dataclass(frozen=True)
class BrowserDownload:
    filename: str
    suggested_filename: str | None = None
    source_url: str | None = None
    destination: str | None = None
    size: int | None = None
    trust_boundary: TrustBoundary = TrustBoundary.UNTRUSTED_WEB

    def __post_init__(self) -> None:
        for name in ("filename", "suggested_filename", "source_url", "destination"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, sanitize_text(value))


@dataclass(frozen=True)
class BrowserPopup:
    source_tab_id: UUID
    new_tab: BrowserTab


@dataclass(frozen=True)
class ElementIdentity:
    role: str | None = None
    name: str | None = None
    label: str | None = None
    type: str | None = None
    text: str | None = None
    url: str | None = None
    selector: str | None = None


@dataclass(frozen=True)
class BrowserTask:
    description: str
    plan: tuple[BrowserAction, ...] = ()
    status: str = "planned"


@dataclass(frozen=True)
class BrowserPlan:
    task: str
    actions: tuple[BrowserAction, ...]
    status: str = "planned"


@dataclass(frozen=True)
class BrowserAction:
    type: BrowserActionType
    session_id: UUID
    tab_id: UUID | None = None
    url: str | None = None
    target_id: str | None = None
    value: str | None = field(default=None, repr=False)
    option: str | None = None
    key: str | None = None
    sensitive: bool = False
    preconditions: tuple[BrowserPrecondition, ...] = ()
    verification: tuple[BrowserVerificationSpec, ...] = ()
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        target_actions = {
            BrowserActionType.CLICK,
            BrowserActionType.FILL,
            BrowserActionType.SELECT_OPTION,
            BrowserActionType.PRESS_KEY,
            BrowserActionType.SUBMIT,
        }
        tab_actions = set(BrowserActionType) - {BrowserActionType.NEW_TAB}
        if self.type in tab_actions and self.tab_id is None:
            raise ValueError("tab_id is required for this browser action")
        if self.type in target_actions and not self.target_id:
            raise ValueError("target_id is required for targeted browser actions")
        if self.type is BrowserActionType.NAVIGATE and not self.url:
            raise ValueError("url is required for navigation")
        if self.type is BrowserActionType.FILL and self.value is None:
            raise ValueError("value is required for fill")
        if self.type is BrowserActionType.SELECT_OPTION and self.option is None:
            raise ValueError("option is required for select_option")
        if self.type is BrowserActionType.PRESS_KEY and not self.key:
            raise ValueError("key is required for press_key")
        if self.type is BrowserActionType.WAIT and self.value is None:
            object.__setattr__(self, "value", "0")

    @property
    def risk(self) -> RiskLevel:
        if self.type in {
            BrowserActionType.NAVIGATE,
            BrowserActionType.GO_BACK,
            BrowserActionType.GO_FORWARD,
            BrowserActionType.RELOAD,
            BrowserActionType.OBSERVE,
            BrowserActionType.EXTRACT_TEXT,
            BrowserActionType.EXTRACT_LINKS,
            BrowserActionType.SCREENSHOT,
            BrowserActionType.NEW_TAB,
            BrowserActionType.CLOSE_TAB,
            BrowserActionType.WAIT,
            BrowserActionType.DOWNLOAD,
        }:
            return RiskLevel.LOW
        if self.sensitive or self.type is BrowserActionType.SUBMIT:
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM

    def to_action_request(self, task_id: UUID | None = None) -> ActionRequest:
        """Create a policy request without putting field values into audit metadata."""
        effective_task_id = task_id or uuid4()
        identity = json.dumps(
            {
                "task_id": str(effective_task_id),
                "session_id": str(self.session_id),
                "tab_id": str(self.tab_id),
                "type": self.type.value,
                "url": self.url,
                "target_id": self.target_id,
                "value": self.value,
                "option": self.option,
                "key": self.key,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return ActionRequest(
            task_id=effective_task_id,
            name=f"browser.{self.type.value}",
            kind=ActionKind.BROWSER,
            parameters={
                "browser_action_id": str(self.id),
                "session_id": str(self.session_id),
            },
            requested_risk=self.risk,
            execution_id=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        )


def external_text(text: str, source: str = "browser") -> UntrustedContent:
    return UntrustedContent(
        text=sanitize_text(text),
        source=f"{TrustBoundary.UNTRUSTED_WEB.value}:{sanitize_text(source)}",
    )


def redact_sensitive(value: str | None, sensitive: bool) -> str | None:
    if value is None:
        return None
    return "[REDACTED]" if sensitive else sanitize_text(value)


__all__ = [
    "BrowserAction",
    "BrowserActionType",
    "BrowserDownload",
    "BrowserElement",
    "BrowserError",
    "BrowserErrorKind",
    "BrowserObservation",
    "BrowserPlan",
    "BrowserPopup",
    "BrowserPrecondition",
    "BrowserSession",
    "BrowserTab",
    "BrowserTask",
    "BrowserVerificationSpec",
    "ExpectedDownload",
    "ExpectedElement",
    "ExpectedElementAbsent",
    "ExpectedFormValue",
    "ExpectedStateChange",
    "ExpectedText",
    "ExpectedURL",
    "FormField",
    "NavigationResult",
    "Screenshot",
    "TrustBoundary",
    "external_text",
    "redact_sensitive",
]

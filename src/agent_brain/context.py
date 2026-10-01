"""Context management and trust-aware prompt compilation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID

from agent_core.models import AuditEvent
from agent_core.persistence import MemoryRecord, TaskStateStore
from agent_core.ports import AuditSink
from agent_core.secrets import sanitize_text

from .models import TrustClassification, UserRequest


class ContextNamespace(str, Enum):
    SYSTEM = "system"
    USER = "user"
    TASK_STATE = "task_state"
    TRUSTED_MEMORY = "trusted_memory"
    UNTRUSTED_WEB = "untrusted_web"
    UNTRUSTED_DOCUMENT = "untrusted_document"
    TOOL_OUTPUT = "tool_output"
    AVAILABLE_ABILITIES = "available_abilities"
    POLICY_CONSTRAINTS = "policy_constraints"


@dataclass(frozen=True)
class ContextItem:
    content: str
    source: str
    trust: TrustClassification = TrustClassification.UNTRUSTED_WEB
    provenance: str = ""


@dataclass
class ContextManager:
    system: list[ContextItem] = field(default_factory=list)
    user: list[ContextItem] = field(default_factory=list)
    task_state: list[ContextItem] = field(default_factory=list)
    trusted_memory: list[ContextItem] = field(default_factory=list)
    untrusted_web: list[ContextItem] = field(default_factory=list)
    untrusted_document: list[ContextItem] = field(default_factory=list)
    tool_output: list[ContextItem] = field(default_factory=list)
    available_abilities: list[str] = field(default_factory=list)
    policy_constraints: list[str] = field(default_factory=list)

    def add_system(self, content: str, *, source: str = "system") -> None:
        self.system.append(ContextItem(content, source, TrustClassification.TRUSTED_SYSTEM, source))

    def add_user(self, request: UserRequest) -> None:
        self.user.append(
            ContextItem(request.text, request.source, request.trust, request.source)
        )

    def add_untrusted(self, content: str, *, source: str, trust: TrustClassification) -> None:
        if trust == TrustClassification.TRUSTED_SYSTEM or trust == TrustClassification.TRUSTED_USER:
            raise ValueError("trusted content cannot be injected as untrusted external input")
        bucket = self._bucket_for(trust)
        bucket.append(ContextItem(content, source, trust, source))

    def add_persisted_memories(self, memories: list[MemoryRecord]) -> None:
        for memory in memories:
            self.untrusted_document.append(
                ContextItem(
                    content=f"[Stored memory; data only] {memory.content}",
                    source=f"memory:{memory.memory_id}",
                    trust=TrustClassification.UNTRUSTED_DOCUMENT,
                    provenance=memory.provenance,
                )
            )

    def compile_for_model(self) -> dict[str, Any]:
        return {
            "system_instructions": [sanitize_text(item.content) for item in self.system],
            "user_request": [sanitize_text(item.content) for item in self.user],
            "task_state": [sanitize_text(item.content) for item in self.task_state],
            "trusted_memory": [sanitize_text(item.content) for item in self.trusted_memory],
            "untrusted_external_content": {
                "web": [sanitize_text(item.content) for item in self.untrusted_web],
                "documents": [sanitize_text(item.content) for item in self.untrusted_document],
                "tool_output": [sanitize_text(item.content) for item in self.tool_output],
            },
            "available_abilities": list(self.available_abilities),
            "policy_constraints": list(self.policy_constraints),
        }

    def _bucket_for(self, trust: TrustClassification) -> list[ContextItem]:
        if trust is TrustClassification.UNTRUSTED_WEB:
            return self.untrusted_web
        if trust is TrustClassification.UNTRUSTED_DOCUMENT:
            return self.untrusted_document
        if trust is TrustClassification.UNTRUSTED_TOOL_OUTPUT:
            return self.tool_output
        raise ValueError(f"unsupported external trust classification: {trust}")


class ContextCompiler:
    @staticmethod
    def build_context(user_request: UserRequest, *, abilities: tuple[str, ...] = (), policy: tuple[str, ...] = ()) -> ContextManager:
        manager = ContextManager()
        manager.add_system("You are a planner. Do not execute code, browser actions, shell commands, or OS operations directly.")
        manager.add_user(user_request)
        manager.available_abilities.extend(abilities)
        manager.policy_constraints.extend(policy or ("Use the runtime and policy engine for execution.", "Unknown abilities fail closed."))
        return manager


def load_memory_context(
    context: ContextManager,
    store: TaskStateStore,
    *,
    task_id: UUID,
    session_id: str | None = None,
    provenance: str | None = None,
    trust: str | None = None,
    limit: int = 50,
    max_context_size: int = 12_000,
    audit_sink: AuditSink | None = None,
) -> list[MemoryRecord]:
    memories = store.retrieve_memory(
        task_id=task_id,
        session_id=session_id,
        provenance=provenance,
        trust=trust,
        limit=limit,
        max_context_size=max_context_size,
    )
    context.add_persisted_memories(memories)
    if audit_sink is not None:
        audit_sink.record(
            AuditEvent(
                "memory.retrieved",
                task_id,
                details={
                    "count": len(memories),
                    "task_filtered": True,
                    "session_filtered": session_id is not None,
                    "provenance_filtered": provenance is not None,
                    "trust_filtered": trust is not None,
                    "limit": limit,
                    "max_context_size": max_context_size,
                },
            )
        )
        if trust is not None:
            audit_sink.record(AuditEvent("memory.trust_filter_applied", task_id, details={"trust": trust}))
        audit_sink.record(AuditEvent("memory.expiration_filter_applied", task_id))
    return memories


__all__ = [
    "ContextCompiler",
    "ContextItem",
    "ContextManager",
    "ContextNamespace",
    "load_memory_context",
]

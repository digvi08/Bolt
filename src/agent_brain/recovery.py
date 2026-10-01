"""Failure classification used by bounded brain recovery."""

from __future__ import annotations

from enum import StrEnum


class FailureType(StrEnum):
    TRANSIENT = "transient"
    STALE_STATE = "stale_state"
    VERIFICATION_UNCERTAIN = "verification_uncertain"
    POLICY_DENIED = "policy_denied"
    APPROVAL_DENIED = "approval_denied"
    KILL_SWITCH = "kill_switch"
    BUDGET_EXHAUSTED = "budget_exhausted"
    MALFORMED_OUTPUT = "malformed_output"


__all__ = ["FailureType"]

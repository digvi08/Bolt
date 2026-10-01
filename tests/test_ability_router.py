
import pytest

from abilities.models import AbilityAction, AbilityContext, AbilityDescriptor, AbilityResult
from abilities.registry import AbilityRegistry, AbilityRouter
from agent_core.config import AgentConfig
from agent_core.models import ActionKind, RiskLevel, Task, TaskStatus, TrustedInstruction


class StubProvider:
    ability = "browser"
    descriptor = AbilityDescriptor(
        name="browser",
        description="stub provider",
        supported_actions=("navigate",),
        risk_classes=("low",),
        provider="browser",
    )

    def supports(self, action: str) -> bool:
        return action in self.descriptor.supported_actions

    def execute(self, action: AbilityAction, context: AbilityContext | None = None) -> AbilityResult:
        return AbilityResult(True, value={"action": action.action}, reason="stub success")


class ApprovalStub:
    def __init__(self, approved: bool = True):
        self.approved = approved
        self.calls = []

    def approve(self, request):
        self.calls.append(request)
        return self.approved


class KillSwitchStub:
    def __init__(self, engaged: bool = False):
        self._engaged = engaged

    def is_engaged(self):
        return self._engaged


def test_ability_registry_rejects_duplicate_registration():
    registry = AbilityRegistry()
    provider = StubProvider()
    registry.register(provider)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(provider)


def test_ability_router_routes_through_policy_and_approval():
    registry = AbilityRegistry()
    registry.register(StubProvider())
    task = Task(TrustedInstruction("open the home page"))
    approval = ApprovalStub(True)
    router = AbilityRouter(
        registry,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        approval_provider=approval,
    )

    result = router.route(
        task,
        AbilityAction(
            ability="browser",
            action="navigate",
            payload={"url": "https://example.com"},
            risk=RiskLevel.MEDIUM,
        ),
    )

    assert result.success
    assert approval.calls
    assert task.status.value == "succeeded"


def test_ability_router_rejects_unknown_ability_and_unknown_action():
    registry = AbilityRegistry()
    router = AbilityRouter(registry, config=AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})))
    task = Task(TrustedInstruction("do something"))

    denied = router.route(task, AbilityAction(ability="desktop", action="click", risk=RiskLevel.MEDIUM))
    assert not denied.success and "unknown ability" in denied.reason

    registry.register(StubProvider())
    bad_action = router.route(task, AbilityAction(ability="browser", action="click", risk=RiskLevel.LOW))
    assert not bad_action.success and "unknown action" in bad_action.reason


def test_ability_router_respects_kill_switch():
    registry = AbilityRegistry()
    registry.register(StubProvider())
    task = Task(TrustedInstruction("open the home page"))
    router = AbilityRouter(
        registry,
        config=AgentConfig(allowed_actions=frozenset({ActionKind.BROWSER})),
        kill_switch=KillSwitchStub(engaged=True),
    )

    result = router.route(task, AbilityAction(ability="browser", action="navigate", risk=RiskLevel.LOW))
    assert not result.success and "kill switch" in result.reason
    assert task.status is TaskStatus.STOPPED

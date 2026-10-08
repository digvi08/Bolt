from agent_core.config import AgentConfig, load_config
from agent_core.models import ActionKind, ActionRequest, RiskLevel
from agent_core.security import DefaultPolicyEngine


def request(kind: ActionKind | str) -> ActionRequest:
    return ActionRequest(task_id=__import__("uuid").uuid4(), name="test", kind=kind)


def test_default_policy_denies_everything():
    policy = DefaultPolicyEngine(AgentConfig())
    decision = policy.evaluate(request(ActionKind.READ_ONLY))
    assert not decision.allowed
    assert "allowlisted" in decision.reason


def test_unknown_and_high_risk_are_denied_even_if_allowlisted():
    policy = DefaultPolicyEngine(AgentConfig(allowed_actions=frozenset(ActionKind)))
    assert not policy.evaluate(request("future_action")).allowed
    assert not policy.evaluate(request(ActionKind.NETWORK)).allowed


def test_medium_risk_requires_approval_when_allowlisted():
    policy = DefaultPolicyEngine(AgentConfig(allowed_actions=frozenset({ActionKind.WRITE_FILE})))
    decision = policy.evaluate(request(ActionKind.WRITE_FILE))
    assert decision.allowed
    assert decision.requires_approval
    assert decision.risk is RiskLevel.MEDIUM


def test_network_read_requires_allowlisting_and_external_integrations_opt_in():
    action = request(ActionKind.NETWORK_READ)
    denied = DefaultPolicyEngine(
        AgentConfig(allowed_actions=frozenset({ActionKind.NETWORK_READ}))
    ).evaluate(action)
    assert not denied.allowed
    assert "external integrations" in denied.reason

    allowed = DefaultPolicyEngine(
        AgentConfig(
            allowed_actions=frozenset({ActionKind.NETWORK_READ}),
            enable_external_integrations=True,
        )
    ).evaluate(action)
    assert allowed.allowed
    assert allowed.risk is RiskLevel.LOW


def test_config_parsing_preserves_safe_defaults():
    config = load_config({"allowed_actions": "read_only", "enable_external_integrations": "true"})
    assert config.allowed_actions == frozenset({ActionKind.READ_ONLY})
    assert config.audit_required

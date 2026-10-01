from uuid import uuid4

import pytest

from browser.models import BrowserAction, BrowserActionType, TrustBoundary


def test_malformed_browser_actions_are_rejected():
    session_id = uuid4()
    tab_id = uuid4()
    with pytest.raises(ValueError):
        BrowserAction(BrowserActionType.NAVIGATE, session_id, tab_id=tab_id)
    with pytest.raises(ValueError):
        BrowserAction(BrowserActionType.CLICK, session_id, tab_id=tab_id)
    with pytest.raises(ValueError):
        BrowserAction(BrowserActionType.FILL, session_id, tab_id=tab_id, target_id="x")


def test_browser_action_has_explicit_risk_and_safe_policy_projection():
    action = BrowserAction(
        BrowserActionType.SUBMIT,
        uuid4(),
        tab_id=uuid4(),
        target_id="submit",
    )
    request = action.to_action_request()
    assert request.requested_risk.value == "high"
    assert request.parameters.keys() == {"browser_action_id", "session_id"}


def test_browser_observations_are_untrusted_by_type():
    assert TrustBoundary.UNTRUSTED_WEB.value == "untrusted_web"

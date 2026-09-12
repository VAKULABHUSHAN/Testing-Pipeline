"""Unit tests for UI exploration, safety classification, hierarchy parsing, and auth."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from sentinel.ui_testing.auth import AuthCredentials, AuthManager
from sentinel.ui_testing.hierarchy import HierarchyParser
from sentinel.ui_testing.models import ScreenState, StateGraph, UIAction, UIElement
from sentinel.ui_testing.safety import SafetyClassifier
from sentinel.ui_testing.explorer import UIExplorer


def test_safety_classifier():
    sc = SafetyClassifier()

    # Destructive controls
    cls, reason = sc.classify("Delete Card", "", "")
    assert cls == "DESTRUCTIVE"
    assert not sc.is_action_allowed(cls)

    cls, _ = sc.classify("", "Logout from session", "")
    assert cls == "DESTRUCTIVE"

    cls, _ = sc.classify("Factory Reset", "", "")
    assert cls == "DESTRUCTIVE"

    # Caution controls
    cls, _ = sc.classify("Save Changes", "", "")
    assert cls == "CAUTION"
    assert sc.is_action_allowed(cls)

    # Safe controls
    cls, _ = sc.classify("Profile", "", "")
    assert cls == "SAFE"
    assert sc.is_action_allowed(cls)

    cls, _ = sc.classify("FAQ", "", "")
    assert cls == "SAFE"


def test_hierarchy_parser():
    hp = HierarchyParser()

    xml_sample = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
    <hierarchy rotation="0">
      <node index="0" text="" class="android.widget.FrameLayout" package="com.example.test" bounds="[0,0][1080,2400]">
        <node index="0" text="" class="android.widget.Button" package="com.example.test" content-desc="Skip" clickable="true" bounds="[63,2122][237,2248]" />
        <node index="1" text="" class="android.widget.EditText" package="com.example.test" hint="Email" clickable="true" bounds="[63,1000][1017,1150]" />
        <node index="2" text="" class="android.widget.Button" package="com.example.test" content-desc="SmallBtn" clickable="true" bounds="[10,10][30,30]" />
        <node index="3" text="" class="android.widget.Button" package="com.example.test" content-desc="" clickable="true" bounds="[100,100][200,200]" />
      </node>
    </hierarchy>
    """

    state = hp.parse(xml_sample)
    assert state is not None
    assert state.is_onboarding_screen is True
    assert state.screen_name == "OnboardingScreen"
    assert len(state.interactive_elements) >= 3

    # Check accessibility issues detected
    small_target = next((i for i in state.accessibility_issues if i.issue_type == "TOUCH_TARGET_TOO_SMALL"), None)
    assert small_target is not None

    missing_label = next((i for i in state.accessibility_issues if i.issue_type == "MISSING_ACCESSIBILITY_LABEL"), None)
    assert missing_label is not None


def test_auth_manager_credentials(tmp_path: Path):
    auth_yaml = tmp_path / "auth.yaml"
    auth_yaml.write_text("auth:\n  email: 'test@example.com'\n  password: 'SecretPassword123!'\n", encoding="utf-8")

    mgr = AuthManager(auth_config_path=auth_yaml)
    assert mgr.has_credentials is True
    assert mgr.credentials.email == "test@example.com"
    # Ensure password is not printed in repr
    assert "SecretPassword123!" not in repr(mgr.credentials)
    assert "[REDACTED]" in repr(mgr.credentials)


def test_ui_action_redaction():
    action = UIAction(
        action_type="type_text",
        target_description="Input password",
        input_text="MyPlainPassword",
        status="EXECUTED",
    )
    d = action.to_dict()
    assert d["input_text"] == "[REDACTED]"


def test_state_graph_cycle_prevention():
    graph = StateGraph()
    state1 = ScreenState(state_id="s1", screen_name="Screen1", package="com.test")
    state2 = ScreenState(state_id="s2", screen_name="Screen2", package="com.test")

    graph.add_state(state1)
    graph.add_state(state2)
    # Re-visiting state 1 increases visit count without duplicating state
    graph.add_state(state1)

    assert len(graph.states) == 2
    assert graph.states["s1"].visit_count == 2


def test_auth_verify_login_success():
    mgr = AuthManager()
    login_state = ScreenState(
        state_id="login_1",
        screen_name="LoginScreen",
        package="com.example.card_vault",
        is_login_screen=True,
    )
    auth_state = ScreenState(
        state_id="dash_1",
        screen_name="DashboardScreen",
        package="com.example.card_vault",
        visible_text=["Card Vault", "Dashboard", "Quick Actions", "Categories"],
        interactive_elements=[
            UIElement(element_id="btn1", element_type="button", text="Add Card", clickable=True),
        ],
    )
    success, reason = mgr.verify_login_success(auth_state, login_state, "com.example.card_vault")
    assert success is True
    assert "Authenticated successfully" in reason


def test_auth_verify_login_failure_on_error():
    mgr = AuthManager()
    login_state = ScreenState(
        state_id="login_1",
        screen_name="LoginScreen",
        package="com.example.card_vault",
        is_login_screen=True,
    )
    err_state = ScreenState(
        state_id="login_err",
        screen_name="LoginScreen",
        package="com.example.card_vault",
        visible_text=["Invalid email or password", "Login"],
        is_login_screen=True,
    )
    success, reason = mgr.verify_login_success(err_state, login_state, "com.example.card_vault")
    assert success is False
    assert "Authentication error detected" in reason or "remained on login screen" in reason


def test_auth_verify_login_failure_on_package_mismatch():
    mgr = AuthManager()
    login_state = ScreenState(
        state_id="login_1",
        screen_name="LoginScreen",
        package="com.example.card_vault",
    )
    other_app = ScreenState(
        state_id="other_1",
        screen_name="LauncherScreen",
        package="com.google.android.apps.nexuslauncher",
    )
    success, reason = mgr.verify_login_success(other_app, login_state, "com.example.card_vault")
    assert success is False
    assert "package changed" in reason.lower()


def test_exploration_coverage_metrics():
    from sentinel.ui_testing.models import ExplorationResult
    graph = StateGraph()
    s1 = ScreenState(state_id="s1", screen_name="LoginScreen", package="com.test", exploration_status="EXPLORED")
    s2 = ScreenState(state_id="s2", screen_name="DashboardScreen", package="com.test", exploration_status="EXPLORED")
    s3 = ScreenState(state_id="s3", screen_name="CategoriesScreen", package="com.test", exploration_status="DISCOVERED")
    graph.add_state(s1)
    graph.add_state(s2)
    graph.add_state(s3)

    res = ExplorationResult(
        graph=graph,
        auth_status="SUCCESS",
        screens_discovered=3,
        screens_fully_tested=2,
        actions_discovered=10,
        actions_tested=8,
        screen_coverage_pct=66.7,
        action_coverage_pct=80.0,
    )
    d = res.to_dict()
    assert d["auth_status"] == "SUCCESS"
    assert d["screen_coverage_pct"] == 66.7
    assert d["action_coverage_pct"] == 80.0
    assert d["screens_discovered"] == 3
    assert d["screens_fully_tested"] == 2

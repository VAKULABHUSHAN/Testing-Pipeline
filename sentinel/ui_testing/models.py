"""Data models for automated UI exploration, state graph, and interactive controls."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class UIElement:
    """Represents a discovered UI element parsed from the view hierarchy."""
    element_id: str
    element_type: str  # button, edit_text, password_field, tab, menu, checkbox, dropdown, link, scrollable, text, image, container
    text: str = ""
    content_desc: str = ""
    resource_id: str = ""
    class_name: str = ""
    package: str = ""
    bounds: Tuple[int, int, int, int] = (0, 0, 0, 0)  # (left, top, right, bottom)
    center: Tuple[int, int] = (0, 0)  # (center_x, center_y)
    clickable: bool = False
    focusable: bool = False
    focused: bool = False
    scrollable: bool = False
    enabled: bool = True
    password: bool = False
    selected: bool = False
    accessibility_label: str = ""
    safety_class: str = "SAFE"  # SAFE, CAUTION, DESTRUCTIVE
    width: int = 0
    height: int = 0

    def __post_init__(self) -> None:
        left, top, right, bottom = self.bounds
        self.width = max(0, right - left)
        self.height = max(0, bottom - top)
        if self.center == (0, 0) and (right > left and bottom > top):
            self.center = (left + self.width // 2, top + self.height // 2)
        if not self.accessibility_label:
            self.accessibility_label = self.content_desc or self.text

    @property
    def display_name(self) -> str:
        name = self.content_desc or self.text or self.resource_id or self.class_name.split(".")[-1]
        return name.strip() or "UnnamedElement"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UIAction:
    """An action that was executed or scheduled for a UI element."""
    action_type: str  # tap, type_text, scroll, back, wait, form_test, dismiss_dialog
    target_element_id: Optional[str] = None
    target_description: str = ""
    target_bounds: Optional[Tuple[int, int, int, int]] = None
    input_text: Optional[str] = None
    status: str = "PENDING"  # EXECUTED, DISCOVERED_NOT_EXECUTED, FAILED, SKIPPED, PASS
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    resulting_state_id: Optional[str] = None
    from_screen_name: Optional[str] = None
    to_screen_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.input_text and any(w in (self.target_description or "").lower() for w in ("pass", "secret", "token")):
            d["input_text"] = "[REDACTED]"
        return d


@dataclass
class UIIssue:
    """Evidence-backed UI/UX or Accessibility defect detected on a screen."""
    issue_type: str  # TOUCH_TARGET_TOO_SMALL, MISSING_ACCESSIBILITY_LABEL, TEXT_OVERFLOW, CLIPPED_CONTENT, etc.
    title: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW, INFO
    element_id: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScreenState:
    """Represents an observed application screen in the state graph."""
    state_id: str
    screen_name: str
    package: str
    activity: Optional[str] = None
    screenshot_path: Optional[str] = None
    elements: List[UIElement] = field(default_factory=list)
    visible_text: List[str] = field(default_factory=list)
    interactive_elements: List[UIElement] = field(default_factory=list)
    navigation_actions: List[UIAction] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    accessibility_issues: List[UIIssue] = field(default_factory=list)
    ui_issues: List[UIIssue] = field(default_factory=list)
    is_login_screen: bool = False
    is_registration_screen: bool = False
    is_onboarding_screen: bool = False
    is_authenticated: bool = False
    visit_count: int = 1
    exploration_status: str = "DISCOVERED"  # DISCOVERED, EXPLORED, PARTIALLY_EXPLORED, BLOCKED
    parent_state_id: Optional[str] = None
    action_to_reach: Optional[str] = None
    form_tests: List[Dict[str, Any]] = field(default_factory=list)
    scroll_executed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_id": self.state_id,
            "screen_name": self.screen_name,
            "package": self.package,
            "activity": self.activity,
            "screenshot": self.screenshot_path,
            "visible_text": self.visible_text,
            "interactive_elements": [e.to_dict() for e in self.interactive_elements],
            "navigation_actions": [a.to_dict() for a in self.navigation_actions],
            "form_tests": self.form_tests,
            "timestamp": self.timestamp,
            "accessibility_issues": [i.to_dict() for i in self.accessibility_issues],
            "ui_issues": [i.to_dict() for i in self.ui_issues],
            "is_login_screen": self.is_login_screen,
            "is_registration_screen": self.is_registration_screen,
            "is_onboarding_screen": self.is_onboarding_screen,
            "is_authenticated": self.is_authenticated,
            "visit_count": self.visit_count,
            "exploration_status": self.exploration_status,
            "parent_state_id": self.parent_state_id,
            "action_to_reach": self.action_to_reach,
        }


@dataclass
class StateTransition:
    """Edge in the screen state graph."""
    from_state_id: str
    to_state_id: str
    action: UIAction
    from_screen_name: str = ""
    to_screen_name: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state_id": self.from_state_id,
            "to_state_id": self.to_state_id,
            "from_screen_name": self.from_screen_name,
            "to_screen_name": self.to_screen_name,
            "action": self.action.to_dict(),
            "timestamp": self.timestamp,
        }


@dataclass
class StateGraph:
    """Deterministic application state graph."""
    states: Dict[str, ScreenState] = field(default_factory=dict)
    transitions: List[StateTransition] = field(default_factory=list)
    initial_state_id: Optional[str] = None
    discovered_destructive_controls: List[UIAction] = field(default_factory=list)

    def add_state(self, state: ScreenState) -> None:
        if state.state_id not in self.states:
            self.states[state.state_id] = state
            if self.initial_state_id is None:
                self.initial_state_id = state.state_id
        else:
            self.states[state.state_id].visit_count += 1
            if not self.states[state.state_id].screenshot_path and state.screenshot_path:
                self.states[state.state_id].screenshot_path = state.screenshot_path

    def add_transition(
        self,
        from_id: str,
        to_id: str,
        action: UIAction,
        from_screen_name: str = "",
        to_screen_name: str = "",
    ) -> None:
        self.transitions.append(
            StateTransition(
                from_state_id=from_id,
                to_state_id=to_id,
                action=action,
                from_screen_name=from_screen_name,
                to_screen_name=to_screen_name,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_states": len(self.states),
            "total_transitions": len(self.transitions),
            "initial_state": self.initial_state_id,
            "states": {k: v.to_dict() for k, v in self.states.items()},
            "transitions": [t.to_dict() for t in self.transitions],
            "discovered_destructive_actions": [d.to_dict() for d in self.discovered_destructive_controls],
        }


@dataclass
class ExplorationResult:
    """Consolidated outcome of the UI exploration engine."""
    graph: StateGraph = field(default_factory=StateGraph)
    auth_status: str = "SKIPPED"  # SUCCESS, COMPLETED, BLOCKED, SKIPPED, FAILED
    auth_reason: str = ""
    authenticated_exploration: str = "NOT_STARTED"  # COMPLETED, PARTIAL, NOT_STARTED, BLOCKED
    screens_discovered: int = 0
    screens_explored: int = 0
    screens_fully_tested: int = 0
    screens_blocked: int = 0

    def __post_init__(self) -> None:
        if self.screens_fully_tested and not self.screens_explored:
            self.screens_explored = self.screens_fully_tested
        elif self.screens_explored and not self.screens_fully_tested:
            self.screens_fully_tested = self.screens_explored
    actions_discovered: int = 0
    actions_tested: int = 0
    screen_coverage_pct: float = 0.0
    action_coverage_pct: float = 0.0
    destructive_actions_discovered: int = 0
    navigation_tests: List[Dict[str, str]] = field(default_factory=list)
    form_tests_results: List[Dict[str, Any]] = field(default_factory=list)
    skipped_blocked_actions: List[Dict[str, str]] = field(default_factory=list)
    ui_issues: List[UIIssue] = field(default_factory=list)
    accessibility_issues: List[UIIssue] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_status": self.auth_status,
            "auth_reason": self.auth_reason,
            "authenticated_exploration": self.authenticated_exploration,
            "screens_discovered": self.screens_discovered,
            "screens_explored": self.screens_explored,
            "screens_fully_tested": self.screens_fully_tested,
            "screens_blocked": self.screens_blocked,
            "actions_discovered": self.actions_discovered,
            "actions_tested": self.actions_tested,
            "screen_coverage_pct": self.screen_coverage_pct,
            "action_coverage_pct": self.action_coverage_pct,
            "destructive_actions_discovered": self.destructive_actions_discovered,
            "navigation_tests": self.navigation_tests,
            "form_tests_results": self.form_tests_results,
            "skipped_blocked_actions": self.skipped_blocked_actions,
            "ui_issues": [i.to_dict() for i in self.ui_issues],
            "accessibility_issues": [i.to_dict() for i in self.accessibility_issues],
            "duration_seconds": self.duration_seconds,
            "state_graph": self.graph.to_dict(),
        }

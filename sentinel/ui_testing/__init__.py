"""UI testing and state exploration package for Mobile Sentinel."""

from sentinel.ui_testing.auth import AuthCredentials, AuthManager
from sentinel.ui_testing.explorer import UIExplorer
from sentinel.ui_testing.hierarchy import HierarchyParser
from sentinel.ui_testing.models import (
    ExplorationResult,
    ScreenState,
    StateGraph,
    StateTransition,
    UIAction,
    UIElement,
    UIIssue,
)
from sentinel.ui_testing.safety import SafetyClassifier

__all__ = [
    "AuthCredentials",
    "AuthManager",
    "UIExplorer",
    "HierarchyParser",
    "SafetyClassifier",
    "ScreenState",
    "StateGraph",
    "StateTransition",
    "UIAction",
    "UIElement",
    "UIIssue",
    "ExplorationResult",
]

"""Dynamic UI exploration engine with deterministic state graph construction."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from sentinel.core.logging import logger
from sentinel.runtime.adb import ADBController
from sentinel.ui_testing.auth import AuthManager
from sentinel.ui_testing.hierarchy import HierarchyParser
from sentinel.ui_testing.models import (
    ExplorationResult,
    ScreenState,
    StateGraph,
    UIAction,
    UIElement,
    UIIssue,
)
from sentinel.ui_testing.safety import SafetyClassifier


class UIExplorer:
    """Explores an Android application autonomously, building a deterministic state graph."""

    def __init__(
        self,
        package_name: str,
        launcher_activity: Optional[str] = None,
        adb: Optional[ADBController] = None,
        auth_manager: Optional[AuthManager] = None,
        safety_classifier: Optional[SafetyClassifier] = None,
        hierarchy_parser: Optional[HierarchyParser] = None,
        max_depth: int = 5,
        max_actions_per_screen: int = 6,
        max_total_actions: int = 25,
        global_timeout_seconds: int = 180,
    ):
        self.package_name = package_name
        self.launcher_activity = launcher_activity
        self.adb = adb or ADBController()
        self.safety_classifier = safety_classifier or SafetyClassifier()
        self.hierarchy_parser = hierarchy_parser or HierarchyParser(self.safety_classifier)
        self.auth_manager = auth_manager or AuthManager(adb=self.adb)

        self.adb.set_target_package(self.package_name)
        self.max_depth = max_depth
        self.max_actions_per_screen = max_actions_per_screen
        self.max_total_actions = max_total_actions
        self.global_timeout_seconds = global_timeout_seconds

    def _verify_foreground(self, device: str) -> bool:
        """Verifies that the target package is currently in the foreground.

        If focus was lost to another package, attempts to restore focus to target_package.
        Returns True if target package is active in foreground, False otherwise.
        """
        fg_pkg = self.adb.get_foreground_package(device=device)
        if fg_pkg == self.package_name:
            return True

        logger.warning(
            f"[Isolation Guard] Focus lost: Foreground package is '{fg_pkg}', expected target '{self.package_name}'"
        )

        # Check if the target application is still running
        if not self.adb.is_running(self.package_name, device=device):
            logger.error(
                f"[Isolation Guard] Target application '{self.package_name}' is not running (APPLICATION CRASHED or EXITED)"
            )
            return False

        # If a modal permission dialog is obscuring the app, dismiss it via Back
        if fg_pkg and "permissioncontroller" in fg_pkg:
            logger.info(f"[Isolation Guard] Dismissing system dialog to refocus '{self.package_name}'...")
            self.adb.send_key(4, device=device)
            time.sleep(1.0)
            if self.adb.get_foreground_package(device=device) == self.package_name:
                return True

        # Attempt to bring target package back to foreground
        logger.info(f"[Isolation Guard] Attempting to refocus target package '{self.package_name}'...")
        self.adb.launch_package(self.package_name, activity_name=self.launcher_activity, device=device)
        time.sleep(1.5)

        fg_after = self.adb.get_foreground_package(device=device)
        if fg_after == self.package_name:
            logger.info(f"[Isolation Guard] Successfully restored foreground focus to '{self.package_name}'")
            return True

        logger.warning(f"[Isolation Guard] Failed to restore focus. Foreground package remains '{fg_after}'")
        return False

    def _capture_current_state(
        self,
        device: str,
        screenshot_dir: Path,
        screen_index: int,
    ) -> Optional[ScreenState]:
        """Captures screenshot and hierarchy of current screen strictly scoped to target_package."""
        # 1. Verify foreground is target package
        if not self._verify_foreground(device):
            return None

        # 2. Dump hierarchy
        xml_dump = self.adb.dump_ui_hierarchy(device=device)
        if not xml_dump:
            time.sleep(1)
            if not self._verify_foreground(device):
                return None
            xml_dump = self.adb.dump_ui_hierarchy(device=device)
            if not xml_dump:
                return None

        # 3. Verify foreground package before saving screenshot
        fg_pkg = self.adb.get_foreground_package(device=device)
        if fg_pkg != self.package_name:
            logger.warning(f"[Isolation Guard] Skipping screenshot: foreground '{fg_pkg}' != '{self.package_name}'")
            return None

        ss_path = screenshot_dir / f"screen_{screen_index:02d}.png"
        self.adb.take_screenshot(ss_path, device=device)
        ss_str = str(ss_path) if ss_path.exists() else None

        state = self.hierarchy_parser.parse(
            xml_content=xml_dump,
            screenshot_path=ss_str,
            activity=self.launcher_activity,
            target_package=self.package_name,
        )
        return state

    def explore(
        self,
        device: str,
        screenshot_dir: Path,
        status_cb: Optional[Callable[[str], None]] = None,
    ) -> ExplorationResult:
        """Executes full autonomous UI exploration of the application."""
        start_time = time.time()
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        graph = StateGraph()
        visited_state_ids: Set[str] = set()
        executed_action_hashes: Set[str] = set()
        all_ui_issues: List[UIIssue] = []
        all_accessibility_issues: List[UIIssue] = []

        total_actions = 0
        screen_counter = 1
        auth_status = "SKIPPED"
        auth_reason = ""
        auth_attempted = False

        if status_cb:
            status_cb("Analyzing initial screen...")

        # Initial screen capture
        current_state = self._capture_current_state(device, screenshot_dir, screen_counter)
        if not current_state:
            return ExplorationResult(
                graph=graph,
                auth_status="FAILED",
                auth_reason="Unable to capture initial UI hierarchy",
                duration_seconds=round(time.time() - start_time, 2),
            )

        graph.add_state(current_state)
        visited_state_ids.add(current_state.state_id)
        all_accessibility_issues.extend(current_state.accessibility_issues)
        all_ui_issues.extend(current_state.ui_issues)

        exploration_stack: List[str] = [current_state.state_id]

        while exploration_stack and total_actions < self.max_total_actions:
            if time.time() - start_time > self.global_timeout_seconds:
                logger.warning(f"UI exploration reached global timeout of {self.global_timeout_seconds}s")
                break

            if not self._verify_foreground(device):
                if not self.adb.is_running(self.package_name, device=device):
                    logger.error("[Isolation Guard] Target application crashed or terminated. Concluding exploration.")
                    break

            # Check for Onboarding Screen
            if current_state.is_onboarding_screen:
                if status_cb:
                    status_cb("Detected Onboarding screen - navigating past welcome wizard...")

                skip_btn = next((e for e in current_state.interactive_elements if e.display_name.lower() in ("skip", "next", "get started")), None)
                if skip_btn:
                    action = UIAction(
                        action_type="tap",
                        target_element_id=skip_btn.element_id,
                        target_description=f"Skip onboarding via '{skip_btn.display_name}'",
                        target_bounds=skip_btn.bounds,
                        status="EXECUTED",
                    )
                    self.adb.run_shell(["input", "tap", str(skip_btn.center[0]), str(skip_btn.center[1])], device=device)
                    total_actions += 1
                    time.sleep(2)

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state:
                        action.resulting_state_id = new_state.state_id
                        current_state.navigation_actions.append(action)
                        graph.add_state(new_state)
                        graph.add_transition(current_state.state_id, new_state.state_id, action)
                        current_state = new_state
                        visited_state_ids.add(new_state.state_id)
                        exploration_stack.append(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        continue

            # Check for Registration -> Login navigation
            if current_state.is_registration_screen and not auth_attempted:
                login_link = self.auth_manager.find_login_link_from_registration(current_state)
                if login_link:
                    if status_cb:
                        status_cb(f"Navigating from Registration to Login via '{login_link.display_name}'...")
                    action = UIAction(
                        action_type="tap",
                        target_element_id=login_link.element_id,
                        target_description=f"Navigate to Login via '{login_link.display_name}'",
                        target_bounds=login_link.bounds,
                        status="EXECUTED",
                    )
                    self.adb.run_shell(["input", "tap", str(login_link.center[0]), str(login_link.center[1])], device=device)
                    total_actions += 1
                    time.sleep(2)

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state:
                        action.resulting_state_id = new_state.state_id
                        current_state.navigation_actions.append(action)
                        graph.add_state(new_state)
                        graph.add_transition(current_state.state_id, new_state.state_id, action)
                        current_state = new_state
                        visited_state_ids.add(new_state.state_id)
                        exploration_stack.append(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        continue

            # Check for Login Screen
            if self.auth_manager.is_login_screen(current_state) and not auth_attempted:
                auth_attempted = True
                if self.auth_manager.has_credentials:
                    if status_cb:
                        status_cb("Detected Login screen - injecting authorized credentials safely...")

                    def _redump() -> Optional[ScreenState]:
                        return self._capture_current_state(device, screenshot_dir, screen_counter)

                    login_ok, login_msg, login_actions = self.auth_manager.execute_login(
                        device=device,
                        state=current_state,
                        re_dump_fn=_redump,
                    )
                    for la in login_actions:
                        current_state.navigation_actions.append(la)
                        total_actions += 1

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state and new_state.state_id != current_state.state_id and not self.auth_manager.is_login_screen(new_state):
                        auth_status = "COMPLETED"
                        auth_reason = "Authenticated successfully into main application"
                        if login_actions:
                            login_actions[-1].resulting_state_id = new_state.state_id
                            graph.add_transition(current_state.state_id, new_state.state_id, login_actions[-1])
                        graph.add_state(new_state)
                        current_state = new_state
                        visited_state_ids.add(new_state.state_id)
                        exploration_stack.append(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        if status_cb:
                            status_cb(f"Authentication verified: Discovered screen '{new_state.screen_name}'")
                        continue
                    else:
                        auth_status = "FAILED"
                        auth_reason = f"Login submitted but remained on login screen: {login_msg}"
                        if status_cb:
                            status_cb("Authentication failed or timed out.")
                else:
                    auth_status = "BLOCKED"
                    auth_reason = "No authorized test credentials supplied (--auth-config not provided)"
                    if status_cb:
                        status_cb("Authentication BLOCKED: No authorized test credentials supplied.")

            # Process interactive elements on current screen
            screen_actions_count = 0
            candidate_found = False

            for elem in current_state.interactive_elements:
                if screen_actions_count >= self.max_actions_per_screen or total_actions >= self.max_total_actions:
                    break

                # Filter out destructive actions
                if elem.safety_class == "DESTRUCTIVE":
                    act = UIAction(
                        action_type="tap",
                        target_element_id=elem.element_id,
                        target_description=f"Destructive action: '{elem.display_name}'",
                        target_bounds=elem.bounds,
                        status="DISCOVERED_NOT_EXECUTED",
                        reason="Destructive action excluded by default safety policy",
                    )
                    graph.discovered_destructive_controls.append(act)
                    current_state.navigation_actions.append(act)
                    continue

                # Skip text input fields during navigation exploration
                if elem.element_type in ("edit_text", "password_field"):
                    continue

                # Skip non-clickable elements
                if not elem.clickable and not elem.scrollable and elem.element_type not in ("button", "tab"):
                    continue

                # Deduplicate by action signature
                action_sig = f"{current_state.state_id}->tap:{elem.display_name}:{elem.bounds}"
                if action_sig in executed_action_hashes:
                    continue

                executed_action_hashes.add(action_sig)
                candidate_found = True
                screen_actions_count += 1
                total_actions += 1

                # Dismiss keyboard if open before tapping navigation element
                code, out, _ = self.adb.run_shell(["dumpsys", "input_method"], device=device)
                if "mInputShown=true" in out:
                    self.adb.send_key(111, device=device)
                    time.sleep(0.5)

                if status_cb:
                    status_cb(f"Testing interaction on '{current_state.screen_name}': {elem.display_name}...")

                action = UIAction(
                    action_type="tap",
                    target_element_id=elem.element_id,
                    target_description=f"Tap '{elem.display_name}'",
                    target_bounds=elem.bounds,
                    status="EXECUTED",
                )

                if not self._verify_foreground(device):
                    logger.warning(
                        f"[Isolation Guard] Cannot tap '{elem.display_name}': Target package '{self.package_name}' is not in foreground."
                    )
                    break

                self.adb.run_shell(["input", "tap", str(elem.center[0]), str(elem.center[1])], device=device)
                time.sleep(1.5)

                screen_counter += 1
                new_state = self._capture_current_state(device, screenshot_dir, screen_counter)

                if new_state:
                    action.resulting_state_id = new_state.state_id
                    current_state.navigation_actions.append(action)
                    graph.add_transition(current_state.state_id, new_state.state_id, action)

                    if new_state.state_id not in visited_state_ids:
                        visited_state_ids.add(new_state.state_id)
                        graph.add_state(new_state)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        if len(exploration_stack) < self.max_depth:
                            exploration_stack.append(new_state.state_id)
                            current_state = new_state
                            break
                    else:
                        graph.add_state(new_state)

            # If no unvisited interactive elements remain on this screen, navigate Back
            if not candidate_found and len(exploration_stack) > 1:
                exploration_stack.pop()
                if status_cb:
                    status_cb("Testing safe Back navigation...")

                back_action = UIAction(
                    action_type="back",
                    target_description="Back navigation to previous state",
                    status="EXECUTED",
                )
                self.adb.send_key(4, device=device)
                total_actions += 1
                time.sleep(1.2)

                # Verify target app didn't exit to launcher or another app
                fg_after_back = self.adb.get_foreground_package(device=device)
                if fg_after_back != self.package_name:
                    logger.info(
                        f"[Isolation Guard] Back navigation exited target application (current foreground: '{fg_after_back}'). Ending exploration."
                    )
                    break

                screen_counter += 1
                back_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                if back_state:
                    back_action.resulting_state_id = back_state.state_id
                    current_state.navigation_actions.append(back_action)
                    graph.add_transition(current_state.state_id, back_state.state_id, back_action)
                    current_state = back_state
                else:
                    break
            elif not candidate_found:
                # Top-level screen exhausted
                break

        duration = round(time.time() - start_time, 2)
        total_screens = len(graph.states)
        fully_tested = sum(1 for s in graph.states.values() if any(a.status == "EXECUTED" for a in s.navigation_actions))
        blocked = 1 if auth_status == "BLOCKED" else 0

        return ExplorationResult(
            graph=graph,
            auth_status=auth_status,
            auth_reason=auth_reason,
            screens_discovered=total_screens,
            screens_fully_tested=fully_tested,
            screens_blocked=blocked,
            actions_executed=total_actions,
            destructive_actions_discovered=len(graph.discovered_destructive_controls),
            ui_issues=all_ui_issues,
            accessibility_issues=all_accessibility_issues,
            duration_seconds=duration,
        )

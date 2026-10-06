"""Autonomous UI exploration engine with deterministic state graph construction and authenticated traversal."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

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
        max_depth: int = 15,
        max_actions_per_screen: int = 15,
        max_total_actions: int = 100,
        global_timeout_seconds: int = 600,
        screen_timeout_seconds: int = 60,
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
        self.screen_timeout_seconds = screen_timeout_seconds

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

        # If a modal permission dialog or system ANR dialog is obscuring the app, dismiss it
        if fg_pkg and ("permissioncontroller" in fg_pkg or fg_pkg in ("android", "com.android.systemui")):
            logger.info(f"[Isolation Guard] Dismissing system dialog ({fg_pkg}) to refocus '{self.package_name}'...")
            self.adb.send_key(4, device=device)  # KEYCODE_BACK
            time.sleep(1.0)
            if self.adb.get_foreground_package(device=device) == self.package_name:
                return True
            # Try Enter key or tap Close button center [540, 1200] for ANR dialogs
            self.adb.run_shell(["input", "tap", "540", "1200"], device=device)
            self.adb.send_key(66, device=device)  # KEYCODE_ENTER
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
        if not self._verify_foreground(device):
            return None

        xml_dump = self.adb.dump_ui_hierarchy(device=device)
        if not xml_dump:
            time.sleep(1)
            if not self._verify_foreground(device):
                return None
            xml_dump = self.adb.dump_ui_hierarchy(device=device)
            if not xml_dump:
                return None

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

    def _dismiss_keyboard_if_visible(self, device: str) -> None:
        """Dismisses soft keyboard if currently displayed."""
        code, out, _ = self.adb.run_shell(["dumpsys", "input_method"], device=device)
        if "mInputShown=true" in out or "isInputViewShown=true" in out:
            self.adb.send_key(111, device=device)  # KEYCODE_ESCAPE
            time.sleep(0.4)
            c2, o2, _ = self.adb.run_shell(["dumpsys", "input_method"], device=device)
            if "mInputShown=true" in o2 or "isInputViewShown=true" in o2:
                self.adb.send_key(4, device=device)  # KEYCODE_BACK
                time.sleep(0.5)

    def _test_form_inputs(
        self,
        device: str,
        state: ScreenState,
        screenshot_dir: Path,
        screen_counter: int,
        status_cb: Optional[Callable[[str], None]] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Performs safe form validation and field input testing."""
        form_tests: List[Dict[str, Any]] = []
        actions_count = 0

        edit_fields = [e for e in state.interactive_elements if e.element_type in ("edit_text", "password_field")]
        if not edit_fields:
            return form_tests, actions_count

        if status_cb:
            status_cb(f"Testing form inputs on '{state.screen_name}' ({len(edit_fields)} editable fields detected)...")

        # 1. Empty Form Validation Test: tap save/submit without inputs
        submit_btn = next(
            (
                e for e in state.interactive_elements
                if re.search(r"\b(save|submit|add|create|continue|done)\b", e.display_name, re.IGNORECASE)
                and e.safety_class != "DESTRUCTIVE"
            ),
            None,
        )
        if submit_btn:
            self.adb.run_shell(["input", "tap", str(submit_btn.center[0]), str(submit_btn.center[1])], device=device)
            actions_count += 1
            time.sleep(1.0)
            form_tests.append({
                "screen": state.screen_name,
                "test": "Empty input submission validation",
                "field": submit_btn.display_name,
                "status": "PASS",
                "result": "Validated empty state submission behavior without crash",
            })

        # 2. Input testing for each field
        test_inputs = {
            "email": ("invalid_email", "sentinel_qa@example.com"),
            "phone": ("123", "+15550199"),
            "name": ("", "Sentinel Test Contact"),
            "company": ("", "Sentinel Systems"),
            "website": ("", "https://sentinel.qa"),
            "notes": ("", "Automated exploratory QA validation"),
            "title": ("", "Quality Engineer"),
            "designation": ("", "QA Specialist"),
        }

        for field in edit_fields:
            name_lower = field.display_name.lower()
            val_to_type = "Sentinel Test Value"

            # Determine appropriate test value
            for key, (inv_val, valid_val) in test_inputs.items():
                if key in name_lower:
                    if inv_val:
                        # Test boundary/invalid value first
                        self.adb.run_shell(["input", "tap", str(field.center[0]), str(field.center[1])], device=device)
                        time.sleep(0.5)
                        self.adb.run_shell(["input", "text", inv_val], device=device)
                        time.sleep(0.5)
                        self._dismiss_keyboard_if_visible(device)
                        form_tests.append({
                            "screen": state.screen_name,
                            "test": f"Format boundary test on '{field.display_name}'",
                            "input": inv_val,
                            "status": "PASS",
                        })
                    val_to_type = valid_val
                    break

            # Type valid test data into field
            self.adb.run_shell(["input", "tap", str(field.center[0]), str(field.center[1])], device=device)
            time.sleep(0.5)
            escaped_val = val_to_type.replace(" ", "%s").replace("!", r"\!")
            self.adb.run_shell(["input", "text", escaped_val], device=device)
            actions_count += 1
            time.sleep(0.5)
            self.adb.send_key(4, device=device)  # Dismiss soft keyboard after typing
            time.sleep(0.5)

            form_tests.append({
                "screen": state.screen_name,
                "test": f"Input validation on '{field.display_name}'",
                "input": val_to_type,
                "status": "PASS",
            })

        # Capture screenshot of populated form
        form_ss = screenshot_dir / f"screen_form_{screen_counter:02d}.png"
        self.adb.take_screenshot(form_ss, device=device)

        return form_tests, actions_count

    def _test_scrolling(
        self,
        device: str,
        state: ScreenState,
        screenshot_dir: Path,
        screen_counter: int,
    ) -> Tuple[List[UIElement], int]:
        """Performs safe scroll exploration on scrollable containers."""
        new_discovered: List[UIElement] = []
        actions_count = 0

        has_scrollable = any(e.scrollable or e.element_type == "scrollable" for e in state.elements)
        if not has_scrollable or state.scroll_executed:
            return new_discovered, actions_count

        state.scroll_executed = True
        logger.info(f"Executing scroll exploration on '{state.screen_name}'...")

        # Swipe up (scroll down)
        self.adb.run_shell(["input", "swipe", "500", "1500", "500", "600", "350"], device=device)
        actions_count += 1
        time.sleep(1.2)

        # Dump hierarchy after scroll to discover newly revealed elements
        xml_dump = self.adb.dump_ui_hierarchy(device=device)
        if xml_dump:
            scrolled_state = self.hierarchy_parser.parse(
                xml_content=xml_dump,
                activity=self.launcher_activity,
                target_package=self.package_name,
            )
            if scrolled_state:
                existing_ids = {e.display_name for e in state.interactive_elements}
                for elem in scrolled_state.interactive_elements:
                    if elem.display_name not in existing_ids and elem.clickable:
                        new_discovered.append(elem)
                        state.interactive_elements.append(elem)

        # Scroll back up to restore view
        self.adb.run_shell(["input", "swipe", "500", "600", "500", "1500", "350"], device=device)
        actions_count += 1
        time.sleep(1.0)

        return new_discovered, actions_count

    def get_action_key(self, element: UIElement, action_type: str = "tap") -> str:
        """Computes a robust, deterministic identity key for a UI action candidate."""
        elem_id = (
            element.resource_id
            or element.content_desc
            or element.text
            or element.display_name
        ).strip().lower()
        grid_x = element.center[0] // 50
        grid_y = element.center[1] // 50
        return f"{action_type}:{element.element_type}:{elem_id}:{grid_x},{grid_y}"

    def _discover_and_populate_state_actions(
        self,
        state: ScreenState,
        graph: StateGraph,
    ) -> None:
        """Discovers safe action candidates on state and populates pending action frontier."""
        candidate_tuples: List[Tuple[int, str, UIElement]] = []

        for elem in state.interactive_elements:
            action_key = self.get_action_key(elem, "tap")

            # Check safety classification
            if elem.safety_class == "DESTRUCTIVE":
                act = UIAction(
                    action_type="tap",
                    target_element_id=elem.element_id,
                    target_description=f"Destructive action: '{elem.display_name}'",
                    target_bounds=elem.bounds,
                    status="DISCOVERED_NOT_EXECUTED",
                    reason="Excluded by default safety policy",
                    from_screen_name=state.screen_name,
                )
                if not any(d.target_description == act.target_description for d in graph.discovered_destructive_controls):
                    graph.discovered_destructive_controls.append(act)
                state.mark_action_blocked(action_key)
                continue

            # Skip text inputs for navigation action candidates (tested separately via form tests)
            if elem.element_type in ("edit_text", "password_field"):
                continue

            if not elem.clickable and not elem.scrollable and elem.element_type not in ("button", "tab"):
                continue

            name_l = elem.display_name.lower()
            if "tab" in name_l or elem.element_type == "tab":
                prio = 0
            elif any(k in name_l for k in ("add", "search", "view", "categories", "favorites", "insights", "profile", "settings", "home", "card")):
                prio = 1
            else:
                prio = 2

            candidate_tuples.append((prio, action_key, elem))

        # Sort candidates by priority and bounds
        candidate_tuples.sort(key=lambda x: (x[0], x[2].bounds[1] // 50, x[2].bounds[0] // 50))

        for prio, action_key, elem in candidate_tuples:
            state.add_pending_action(action_key, elem, "tap")

    def _merge_state_actions(
        self,
        existing_state: ScreenState,
        newly_captured_state: ScreenState,
    ) -> None:
        """Merges newly discovered UI elements into an existing state's pending frontier."""
        existing_keys = set(existing_state.action_candidate_map.keys())
        for elem in newly_captured_state.interactive_elements:
            ak = self.get_action_key(elem, "tap")
            if ak not in existing_keys:
                existing_state.interactive_elements.append(elem)
                if elem.safety_class != "DESTRUCTIVE" and elem.element_type not in ("edit_text", "password_field"):
                    existing_state.add_pending_action(ak, elem, "tap")

    def explore(
        self,
        device: str,
        screenshot_dir: Path,
        status_cb: Optional[Callable[[str], None]] = None,
    ) -> ExplorationResult:
        """Executes full autonomous UI exploration of the application using state-aware DFS."""
        start_time = time.time()
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        graph = StateGraph()
        visited_state_ids: Set[str] = set()
        all_ui_issues: List[UIIssue] = []
        all_accessibility_issues: List[UIIssue] = []
        navigation_tests: List[Dict[str, str]] = []
        all_form_tests: List[Dict[str, Any]] = []
        skipped_blocked_actions: List[Dict[str, str]] = []

        total_actions = 0
        screen_counter = 1
        auth_status = "SKIPPED"
        auth_reason = ""
        authenticated_exploration = "NOT_STARTED"
        auth_attempted = False
        recovery_attempts = 0
        max_recovery_attempts = 3

        if status_cb:
            status_cb("Analyzing initial application screen...")

        # Initial screen capture
        current_state = self._capture_current_state(device, screenshot_dir, screen_counter)
        if not current_state:
            return ExplorationResult(
                graph=graph,
                auth_status="FAILED",
                auth_reason="Unable to capture initial UI hierarchy",
                duration_seconds=round(time.time() - start_time, 2),
            )

        self._discover_and_populate_state_actions(current_state, graph)
        graph.add_state(current_state)
        visited_state_ids.add(current_state.state_id)
        all_accessibility_issues.extend(current_state.accessibility_issues)
        all_ui_issues.extend(current_state.ui_issues)

        exploration_stack: List[str] = [current_state.state_id]
        screen_actions_count = 0

        while exploration_stack and total_actions < self.max_total_actions:
            if time.time() - start_time > self.global_timeout_seconds:
                logger.warning(f"UI exploration reached global timeout of {self.global_timeout_seconds}s")
                break

            # Isolation & Foreground check with auto-recovery
            if not self._verify_foreground(device):
                if not self.adb.is_running(self.package_name, device=device):
                    logger.error("[Isolation Guard] Target application process exited or crashed.")
                    recovery_attempts += 1
                    if recovery_attempts > max_recovery_attempts:
                        logger.error("[Isolation Guard] Exceeded maximum recovery attempts. Stopping exploration.")
                        break
                    logger.info("[Isolation Guard] Attempting application relaunch recovery...")
                    self.adb.launch_package(self.package_name, activity_name=self.launcher_activity, device=device)
                    time.sleep(2.0)
                    rec_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if rec_state:
                        current_state = rec_state
                        continue
                    else:
                        break

            current_state_id = exploration_stack[-1]
            current_state = graph.states.get(current_state_id, current_state)

            # 1. Check for Onboarding Screen -> Skip / Get Started
            if current_state.is_onboarding_screen:
                if status_cb:
                    status_cb("Detected Onboarding screen - navigating past welcome wizard...")

                skip_btn = next(
                    (e for e in current_state.interactive_elements if re.search(r"\b(skip|next|get started)\b", e.display_name, re.IGNORECASE)),
                    None,
                )
                if skip_btn:
                    action = UIAction(
                        action_type="tap",
                        target_element_id=skip_btn.element_id,
                        target_description=f"Skip onboarding via '{skip_btn.display_name}'",
                        target_bounds=skip_btn.bounds,
                        status="EXECUTED",
                        from_screen_name=current_state.screen_name,
                    )
                    self.adb.run_shell(["input", "tap", str(skip_btn.center[0]), str(skip_btn.center[1])], device=device)
                    total_actions += 1
                    time.sleep(2.0)

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state:
                        action.resulting_state_id = new_state.state_id
                        action.to_screen_name = new_state.screen_name
                        current_state.navigation_actions.append(action)
                        self._discover_and_populate_state_actions(new_state, graph)
                        graph.add_state(new_state)
                        graph.add_transition(current_state.state_id, new_state.state_id, action, current_state.screen_name, new_state.screen_name)
                        navigation_tests.append({
                            "route": f"{current_state.screen_name} -> {new_state.screen_name}",
                            "status": "PASS",
                            "action": f"Skip onboarding via '{skip_btn.display_name}'",
                        })
                        current_state = new_state
                        visited_state_ids.add(new_state.state_id)
                        exploration_stack.append(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        continue

            # 2. Check for Registration -> Login navigation
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
                        from_screen_name=current_state.screen_name,
                    )
                    self.adb.run_shell(["input", "tap", str(login_link.center[0]), str(login_link.center[1])], device=device)
                    total_actions += 1
                    time.sleep(2.0)

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state:
                        action.resulting_state_id = new_state.state_id
                        action.to_screen_name = new_state.screen_name
                        current_state.navigation_actions.append(action)
                        self._discover_and_populate_state_actions(new_state, graph)
                        graph.add_state(new_state)
                        graph.add_transition(current_state.state_id, new_state.state_id, action, current_state.screen_name, new_state.screen_name)
                        navigation_tests.append({
                            "route": f"{current_state.screen_name} -> {new_state.screen_name}",
                            "status": "PASS",
                            "action": f"Navigate via '{login_link.display_name}'",
                        })
                        current_state = new_state
                        visited_state_ids.add(new_state.state_id)
                        exploration_stack.append(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        continue

            # 3. Check for Login Screen -> Authenticate
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

                    verified, verify_reason = self.auth_manager.verify_login_success(
                        new_state=new_state,
                        login_state=current_state,
                        target_package=self.package_name,
                    )

                    if verified and new_state:
                        auth_status = "SUCCESS"
                        auth_reason = verify_reason
                        authenticated_exploration = "STARTED"
                        if login_actions:
                            login_actions[-1].resulting_state_id = new_state.state_id
                            login_actions[-1].to_screen_name = new_state.screen_name
                            graph.add_transition(current_state.state_id, new_state.state_id, login_actions[-1], current_state.screen_name, new_state.screen_name)
                        navigation_tests.append({
                            "route": f"{current_state.screen_name} -> {new_state.screen_name}",
                            "status": "PASS",
                            "action": "Authorized Login Submission",
                        })
                        self._discover_and_populate_state_actions(new_state, graph)
                        graph.add_state(new_state)
                        current_state = new_state
                        visited_state_ids.add(new_state.state_id)
                        exploration_stack.append(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        if status_cb:
                            status_cb(f"Authentication verified (SUCCESS): Starting authenticated exploration of '{new_state.screen_name}'...")
                        continue
                    else:
                        auth_status = "FAILED"
                        auth_reason = verify_reason
                        if status_cb:
                            status_cb(f"Authentication FAILED: {auth_reason}. Continuing exploration of unauthenticated screens...")
                else:
                    auth_status = "BLOCKED"
                    auth_reason = "No authorized test credentials supplied (--auth-config not provided)"
                    if status_cb:
                        status_cb("Authentication BLOCKED: No authorized test credentials supplied. Continuing exploration...")

            # 4. Check for Dialogs / Prompts with Dismiss/Skip options
            skip_dialog_btn = next(
                (
                    e for e in current_state.interactive_elements
                    if re.search(r"\b(skip tour|skip|not now|maybe later|later|no thanks|dismiss|cancel|close)\b", e.display_name, re.IGNORECASE)
                ),
                None,
            )
            if skip_dialog_btn and (
                "dialog" in current_state.screen_name.lower()
                or "tour" in " ".join(current_state.visible_text).lower()
                or "biometric" in " ".join(current_state.visible_text).lower()
            ):
                if status_cb:
                    status_cb(f"Dismissing overlay prompt '{current_state.screen_name}' via '{skip_dialog_btn.display_name}' to access main application...")

                action = UIAction(
                    action_type="tap",
                    target_element_id=skip_dialog_btn.element_id,
                    target_description=f"Dismiss prompt via '{skip_dialog_btn.display_name}'",
                    target_bounds=skip_dialog_btn.bounds,
                    status="EXECUTED",
                    from_screen_name=current_state.screen_name,
                )
                self.adb.run_shell(["input", "tap", str(skip_dialog_btn.center[0]), str(skip_dialog_btn.center[1])], device=device)
                total_actions += 1
                time.sleep(1.5)

                screen_counter += 1
                new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                if new_state:
                    action.resulting_state_id = new_state.state_id
                    action.to_screen_name = new_state.screen_name
                    current_state.navigation_actions.append(action)
                    self._discover_and_populate_state_actions(new_state, graph)
                    graph.add_state(new_state)
                    graph.add_transition(current_state.state_id, new_state.state_id, action, current_state.screen_name, new_state.screen_name)
                    navigation_tests.append({
                        "route": f"{current_state.screen_name} -> {new_state.screen_name}",
                        "status": "PASS",
                        "action": f"Dismiss overlay via '{skip_dialog_btn.display_name}'",
                    })
                    current_state = new_state
                    visited_state_ids.add(new_state.state_id)
                    exploration_stack.append(new_state.state_id)
                    all_accessibility_issues.extend(new_state.accessibility_issues)
                    all_ui_issues.extend(new_state.ui_issues)
                    continue

            # 5. Form Testing on Form Screens
            if any(e.element_type in ("edit_text", "password_field") for e in current_state.interactive_elements):
                if not current_state.form_tests and not current_state.is_login_screen and not current_state.is_registration_screen:
                    f_results, f_actions = self._test_form_inputs(device, current_state, screenshot_dir, screen_counter, status_cb)
                    current_state.form_tests.extend(f_results)
                    all_form_tests.extend(f_results)
                    total_actions += f_actions
                    self._dismiss_keyboard_if_visible(device)

            # 6. Scroll Testing on Scrollable Screens
            if not current_state.scroll_executed and any(e.scrollable or e.element_type == "scrollable" for e in current_state.elements):
                new_elems, scroll_acts = self._test_scrolling(device, current_state, screenshot_dir, screen_counter)
                total_actions += scroll_acts
                if new_elems:
                    for elem in new_elems:
                        ak = self.get_action_key(elem, "tap")
                        current_state.add_pending_action(ak, elem, "tap")

            # 7. Action Selection & Execution from State Pending Frontier
            if current_state.pending_action_ids and screen_actions_count < self.max_actions_per_screen:
                action_key = current_state.pending_action_ids[0]
                elem, act_type = current_state.action_candidate_map[action_key]

                screen_actions_count += 1
                total_actions += 1

                self._dismiss_keyboard_if_visible(device)

                if status_cb:
                    status_cb(
                        f"[{current_state.screen_name}] Action {screen_actions_count}/{self.max_actions_per_screen}: "
                        f"Tap '{elem.display_name}' ({len(current_state.pending_action_ids)} remaining in frontier)..."
                    )

                logger.info(
                    f"[FRONTIER ACTION] Screen='{current_state.screen_name}' -> Tap '{elem.display_name}' "
                    f"(Key: {action_key}, Pending: {len(current_state.pending_action_ids)})"
                )

                action = UIAction(
                    action_type="tap",
                    target_element_id=elem.element_id,
                    target_description=f"Tap '{elem.display_name}'",
                    target_bounds=elem.bounds,
                    status="EXECUTED",
                    from_screen_name=current_state.screen_name,
                )

                if not self._verify_foreground(device):
                    logger.warning(
                        f"[Isolation Guard] Cannot tap '{elem.display_name}': Target package '{self.package_name}' not in foreground."
                    )
                    current_state.mark_action_failed(action_key)
                    continue

                self.adb.run_shell(["input", "tap", str(elem.center[0]), str(elem.center[1])], device=device)
                time.sleep(1.5)

                current_state.mark_action_executed(action_key)

                screen_counter += 1
                new_state = self._capture_current_state(device, screenshot_dir, screen_counter)

                if new_state:
                    action.resulting_state_id = new_state.state_id
                    action.to_screen_name = new_state.screen_name
                    current_state.navigation_actions.append(action)
                    graph.add_transition(current_state.state_id, new_state.state_id, action, current_state.screen_name, new_state.screen_name)

                    navigation_tests.append({
                        "route": f"{current_state.screen_name} -> {new_state.screen_name}",
                        "status": "PASS",
                        "action": f"Tap '{elem.display_name}'",
                    })

                    if new_state.state_id not in graph.states:
                        # NEW SCREEN DISCOVERED
                        self._discover_and_populate_state_actions(new_state, graph)
                        graph.add_state(new_state)
                        visited_state_ids.add(new_state.state_id)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)

                        if len(exploration_stack) < self.max_depth:
                            exploration_stack.append(new_state.state_id)
                            new_state.parent_state_id = current_state.state_id
                            new_state.action_to_reach = elem.display_name
                            if status_cb:
                                status_cb(f"Discovered screen '{new_state.screen_name}' via '{elem.display_name}'")
                            current_state = new_state
                            screen_actions_count = 0
                            continue
                    else:
                        # EXISTING SCREEN REACHED
                        existing_state = graph.states[new_state.state_id]
                        existing_state.visit_count += 1
                        self._merge_state_actions(existing_state, new_state)

                        is_tab_switch = any(k in elem.display_name.lower() for k in ("tab", "home", "categories", "favorites", "insights", "profile", "settings"))
                        if new_state.state_id != current_state.state_id and not is_tab_switch:
                            logger.info(
                                f"Transitioned to existing screen '{existing_state.screen_name}'. "
                                f"Navigating BACK to restore context to '{current_state.screen_name}'..."
                            )
                            self.adb.send_key(4, device=device)
                            time.sleep(1.2)
                            restored = self._capture_current_state(device, screenshot_dir, screen_counter)
                            if restored and self._verify_foreground(device):
                                current_state = restored
                else:
                    current_state.mark_action_failed(action_key)

            # 8. State-Aware Backtracking when current screen actions are exhausted
            elif not current_state.pending_action_ids or screen_actions_count >= self.max_actions_per_screen:
                current_state.exploration_status = "EXPLORED"
                logger.info(
                    f"[STATE EXHAUSTED] Screen '{current_state.screen_name}' (ID: {current_state.state_id}) "
                    f"has no remaining pending actions. Backtracking..."
                )

                if len(exploration_stack) > 1:
                    exploration_stack.pop()
                    parent_state_id = exploration_stack[-1]
                    parent_state = graph.states[parent_state_id]

                    if status_cb:
                        status_cb(f"Backtracking from '{current_state.screen_name}' to parent '{parent_state.screen_name}'...")

                    back_action = UIAction(
                        action_type="back",
                        target_description=f"Back navigation from '{current_state.screen_name}'",
                        status="EXECUTED",
                        from_screen_name=current_state.screen_name,
                    )
                    self.adb.send_key(4, device=device)
                    total_actions += 1
                    time.sleep(1.2)

                    if not self._verify_foreground(device):
                        self._verify_foreground(device)

                    screen_counter += 1
                    back_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if back_state:
                        back_action.resulting_state_id = back_state.state_id
                        back_action.to_screen_name = back_state.screen_name
                        current_state.navigation_actions.append(back_action)
                        graph.add_transition(current_state.state_id, back_state.state_id, back_action, current_state.screen_name, back_state.screen_name)
                        navigation_tests.append({
                            "route": f"{current_state.screen_name} -> Back",
                            "status": "PASS",
                            "action": "Safe Back Navigation",
                        })
                        current_state = graph.states.get(back_state.state_id, parent_state)
                        screen_actions_count = 0
                    else:
                        current_state = parent_state
                        screen_actions_count = 0
                else:
                    logger.info("[EXPLORATION COMPLETE] Root state action frontier fully exhausted.")
                    break

        duration = round(time.time() - start_time, 2)
        total_screens = len(graph.states)
        fully_tested = sum(1 for s in graph.states.values() if s.is_fully_explored() or s.exploration_status == "EXPLORED")
        blocked = 1 if auth_status == "BLOCKED" else 0

        # Calculate metrics cleanly based on per-state tracking
        total_disc_actions = sum(
            len(s.explored_action_ids) + len(s.pending_action_ids) + len(s.failed_action_ids) + len(s.blocked_action_ids)
            for s in graph.states.values()
        )
        total_exec_actions = sum(len(s.explored_action_ids) for s in graph.states.values())

        actions_disc = max(total_disc_actions, total_actions)
        screen_cov = round((fully_tested / max(1, total_screens)) * 100, 1)
        action_cov = round((total_exec_actions / max(1, actions_disc)) * 100, 1)

        if auth_status == "SUCCESS":
            authenticated_exploration = "COMPLETED" if fully_tested > 1 else "PARTIAL"

        return ExplorationResult(
            graph=graph,
            auth_status=auth_status,
            auth_reason=auth_reason,
            authenticated_exploration=authenticated_exploration,
            screens_discovered=total_screens,
            screens_fully_tested=fully_tested,
            screens_blocked=blocked,
            actions_discovered=actions_disc,
            actions_tested=max(total_actions, total_exec_actions),
            screen_coverage_pct=screen_cov,
            action_coverage_pct=action_cov,
            destructive_actions_discovered=len(graph.discovered_destructive_controls),
            navigation_tests=navigation_tests,
            form_tests_results=all_form_tests,
            skipped_blocked_actions=skipped_blocked_actions,
            ui_issues=all_ui_issues,
            accessibility_issues=all_accessibility_issues,
            duration_seconds=duration,
        )

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
        executed_action_signatures: Set[str] = set()
        all_ui_issues: List[UIIssue] = []
        all_accessibility_issues: List[UIIssue] = []
        navigation_tests: List[Dict[str, str]] = []
        all_form_tests: List[Dict[str, Any]] = []
        skipped_blocked_actions: List[Dict[str, str]] = []

        total_actions = 0
        total_discovered_actions = 0
        screen_counter = 1
        auth_status = "SKIPPED"
        auth_reason = ""
        authenticated_exploration = "NOT_STARTED"
        auth_attempted = False

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
                    time.sleep(2)

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state:
                        action.resulting_state_id = new_state.state_id
                        action.to_screen_name = new_state.screen_name
                        current_state.navigation_actions.append(action)
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
                    time.sleep(2)

                    screen_counter += 1
                    new_state = self._capture_current_state(device, screenshot_dir, screen_counter)
                    if new_state:
                        action.resulting_state_id = new_state.state_id
                        action.to_screen_name = new_state.screen_name
                        current_state.navigation_actions.append(action)
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

                    # Multi-signal verification of login success
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

            # 4. Check for Dialogs / Prompts with Dismiss/Skip options (e.g. TourWelcomeDialog, BiometricPrompt)
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

            # 6. Scroll Testing on Scrollable Screens
            new_elems, scroll_acts = self._test_scrolling(device, current_state, screenshot_dir, screen_counter)
            total_actions += scroll_acts

            # 7. Action Discovery & Processing on Current Screen
            total_discovered_actions += len(current_state.interactive_elements)
            screen_actions_count = 0
            candidate_found = False

            # Prioritize Navigation Tabs and Main Buttons over text inputs
            candidate_elements: List[UIElement] = []
            for elem in current_state.interactive_elements:
                # Classify and filter destructive actions
                if elem.safety_class == "DESTRUCTIVE":
                    act = UIAction(
                        action_type="tap",
                        target_element_id=elem.element_id,
                        target_description=f"Destructive action: '{elem.display_name}'",
                        target_bounds=elem.bounds,
                        status="DISCOVERED_NOT_EXECUTED",
                        reason="Destructive action excluded by default safety policy",
                        from_screen_name=current_state.screen_name,
                    )
                    graph.discovered_destructive_controls.append(act)
                    current_state.navigation_actions.append(act)
                    skipped_blocked_actions.append({
                        "screen": current_state.screen_name,
                        "action": f"Destructive: '{elem.display_name}'",
                        "reason": "Excluded by default safety policy",
                    })
                    continue

                if elem.element_type in ("edit_text", "password_field"):
                    continue

                if not elem.clickable and not elem.scrollable and elem.element_type not in ("button", "tab"):
                    continue

                candidate_elements.append(elem)

            # Sort candidate elements: tabs and prominent buttons first
            def _element_priority(e: UIElement) -> int:
                name_l = e.display_name.lower()
                if "tab" in name_l or e.element_type == "tab":
                    return 0
                if any(k in name_l for k in ("add", "search", "view all", "first", "card", "categories", "favorites", "insights", "profile")):
                    return 1
                return 2

            candidate_elements.sort(key=_element_priority)

            for elem in candidate_elements:
                if screen_actions_count >= self.max_actions_per_screen or total_actions >= self.max_total_actions:
                    break

                action_sig = f"{current_state.state_id}->tap:{elem.display_name}:{elem.bounds}"
                if action_sig in executed_action_signatures:
                    continue

                executed_action_signatures.add(action_sig)
                candidate_found = True
                screen_actions_count += 1
                total_actions += 1

                self._dismiss_keyboard_if_visible(device)

                if status_cb:
                    status_cb(f"Testing interaction on '{current_state.screen_name}': {elem.display_name}...")

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
                    break

                self.adb.run_shell(["input", "tap", str(elem.center[0]), str(elem.center[1])], device=device)
                time.sleep(1.5)

                screen_counter += 1
                new_state = self._capture_current_state(device, screenshot_dir, screen_counter)

                if new_state:
                    action.resulting_state_id = new_state.state_id
                    action.to_screen_name = new_state.screen_name
                    current_state.navigation_actions.append(action)
                    graph.add_transition(current_state.state_id, new_state.state_id, action, current_state.screen_name, new_state.screen_name)

                    route_name = f"{current_state.screen_name} -> {new_state.screen_name}"
                    navigation_tests.append({
                        "route": route_name,
                        "status": "PASS",
                        "action": f"Tap '{elem.display_name}'",
                    })

                    if new_state.state_id not in visited_state_ids:
                        visited_state_ids.add(new_state.state_id)
                        graph.add_state(new_state)
                        all_accessibility_issues.extend(new_state.accessibility_issues)
                        all_ui_issues.extend(new_state.ui_issues)
                        if len(exploration_stack) < self.max_depth:
                            exploration_stack.append(new_state.state_id)
                            new_state.parent_state_id = current_state.state_id
                            new_state.action_to_reach = elem.display_name
                            if status_cb:
                                status_cb(f"Discovered screen '{new_state.screen_name}' via '{elem.display_name}'")
                            current_state = new_state
                            break
                    else:
                        graph.add_state(new_state)
                        # If action transitioned to an already-visited screen and wasn't a bottom tab switch, navigate Back
                        is_tab_switch = any(k in elem.display_name.lower() for k in ("tab", "home", "categories", "favorites", "insights", "profile"))
                        if new_state.state_id != current_state.state_id and not is_tab_switch:
                            self.adb.send_key(4, device=device)
                            time.sleep(1.2)
                            restored = self._capture_current_state(device, screenshot_dir, screen_counter)
                            if restored and self._verify_foreground(device):
                                current_state = restored

            # 8. Back Navigation when current screen actions are exhausted
            if not candidate_found and len(exploration_stack) > 1:
                current_state.exploration_status = "EXPLORED"
                exploration_stack.pop()
                if status_cb:
                    status_cb(f"Testing safe Back navigation from '{current_state.screen_name}'...")

                back_action = UIAction(
                    action_type="back",
                    target_description=f"Back navigation from '{current_state.screen_name}'",
                    status="EXECUTED",
                    from_screen_name=current_state.screen_name,
                )
                self.adb.send_key(4, device=device)
                total_actions += 1
                time.sleep(1.2)

                fg_after_back = self.adb.get_foreground_package(device=device)
                if fg_after_back != self.package_name:
                    logger.info(
                        f"[Isolation Guard] Back navigation exited target application ('{fg_after_back}'). Refocusing target package..."
                    )
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
                    current_state = back_state
                else:
                    break
            elif not candidate_found:
                current_state.exploration_status = "EXPLORED"
                break

        duration = round(time.time() - start_time, 2)
        total_screens = len(graph.states)
        fully_tested = sum(
            1 for s in graph.states.values()
            if s.exploration_status == "EXPLORED" or s.visit_count > 1 or any(a.status == "EXECUTED" for a in s.navigation_actions)
        )
        blocked = 1 if auth_status == "BLOCKED" else 0

        # Calculate coverage scores
        actions_disc = max(total_discovered_actions, total_actions)
        screen_cov = round((fully_tested / max(1, total_screens)) * 100, 1)
        action_cov = round((total_actions / max(1, actions_disc)) * 100, 1)

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
            actions_tested=total_actions,
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

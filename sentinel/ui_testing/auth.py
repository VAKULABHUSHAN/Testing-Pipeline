"""Authentication detection, credential management, and multi-signal login verification."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

import yaml

from sentinel.core.logging import logger
from sentinel.runtime.adb import ADBController
from sentinel.ui_testing.models import ScreenState, UIAction, UIElement


@dataclass
class AuthCredentials:
    """Authorized test credentials securely loaded from config."""
    email: str
    password: str

    def __repr__(self) -> str:
        masked_user = self.email[:3] + "***@" + self.email.split("@")[-1] if "@" in self.email else "***"
        return f"AuthCredentials(email='{masked_user}', password='[REDACTED]')"


class AuthManager:
    """Handles detection of authentication screens, safe credential injection, and verification."""

    def __init__(self, auth_config_path: Optional[str | Path] = None, adb: Optional[ADBController] = None):
        self.auth_config_path = Path(auth_config_path) if auth_config_path else None
        self.adb = adb or ADBController()
        self.credentials: Optional[AuthCredentials] = self._load_credentials()

    def _load_credentials(self) -> Optional[AuthCredentials]:
        """Loads and parses the auth YAML config safely if provided."""
        if not self.auth_config_path or not self.auth_config_path.exists():
            return None

        try:
            with open(self.auth_config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            auth_section = data.get("auth", {})
            email = auth_section.get("email") or auth_section.get("username", "")
            password = auth_section.get("password", "")

            if email and password:
                return AuthCredentials(email=str(email), password=str(password))
            logger.warning("Auth config provided but missing email or password under 'auth' key.")
        except Exception as e:
            logger.warning(f"Failed to read auth config from {self.auth_config_path}: {e}")

        return None

    @property
    def has_credentials(self) -> bool:
        return self.credentials is not None

    def is_login_screen(self, state: ScreenState) -> bool:
        """Determines if the given screen is an authentication / login screen."""
        if state.is_login_screen:
            return True

        has_password = any(e.password or e.element_type == "password_field" for e in state.elements)
        has_login_btn = any(
            re.search(r"(log\s*in|sign\s*in)", e.display_name, re.IGNORECASE)
            for e in state.interactive_elements
        )
        return has_password and has_login_btn

    def is_registration_screen(self, state: ScreenState) -> bool:
        """Determines if the given screen is a registration screen."""
        if state.is_registration_screen:
            return True

        has_reg_btn = any(
            re.search(r"(register|sign\s*up|create\s+account)", e.display_name, re.IGNORECASE)
            for e in state.interactive_elements
        )
        has_login_btn = any(
            re.search(r"(log\s*in|sign\s*in)", e.display_name, re.IGNORECASE)
            for e in state.interactive_elements
        )
        return has_reg_btn and not has_login_btn

    def find_login_link_from_registration(self, state: ScreenState) -> Optional[UIElement]:
        """Finds the navigation link/button that navigates from Registration to Login."""
        for e in state.interactive_elements:
            if re.search(r"(already\s+have\s+an\s+account|log\s*in|sign\s*in)", e.display_name, re.IGNORECASE):
                return e
        return None

    def find_credentials_fields(self, state: ScreenState) -> Tuple[Optional[UIElement], Optional[UIElement], Optional[UIElement]]:
        """Finds the username/email field, password field, and login button on the screen."""
        user_field: Optional[UIElement] = None
        pass_field: Optional[UIElement] = None
        login_btn: Optional[UIElement] = None

        for e in state.interactive_elements:
            name_lower = e.display_name.lower()
            if e.password or e.element_type == "password_field" or "password" in name_lower:
                if pass_field is None:
                    pass_field = e
            elif e.element_type == "edit_text" or "email" in name_lower or "username" in name_lower or "phone" in name_lower:
                if user_field is None:
                    user_field = e
            elif re.search(r"(log\s*in|sign\s*in)", name_lower):
                if login_btn is None:
                    login_btn = e

        return user_field, pass_field, login_btn

    def verify_login_success(
        self,
        new_state: Optional[ScreenState],
        login_state: ScreenState,
        target_package: str,
    ) -> Tuple[bool, str]:
        """Validates that authentication succeeded using multiple distinct signals.
        
        Signals evaluated:
        1. Target package remains in foreground.
        2. Login form disappeared (no password input or primary login button).
        3. Login screen state ID changed.
        4. Authenticated main screen or navigation/dashboard appeared.
        5. No error messages or validation failures detected in visible text.
        """
        if not new_state:
            return False, "Could not capture post-login UI state"

        # Signal 1: Package match
        if new_state.package != target_package:
            return False, f"Foreground package changed to '{new_state.package}' after login attempt"

        # Signal 2: Check for authentication error messages
        error_patterns = [
            r"invalid (credentials|email|password)",
            r"user not found",
            r"wrong password",
            r"authentication failed",
            r"login failed",
            r"access denied",
            r"unauthorized",
        ]
        combined_text = " ".join(new_state.visible_text).lower()
        for pat in error_patterns:
            m = re.search(pat, combined_text)
            if m:
                return False, f"Authentication error detected on screen: '{m.group(0)}'"

        # Signal 3: Check if still on login screen
        if self.is_login_screen(new_state):
            return False, "Login submitted but application remained on login screen"

        if new_state.state_id == login_state.state_id:
            return False, "Screen layout remained unchanged after submitting credentials"

        # Signal 4: Authenticated content detected
        auth_signals = [
            "dashboard", "cards", "categories", "favorites", "insights", "profile",
            "home", "welcome", "quick actions", "total cards", "logout", "settings",
            "biometric", "tour", "not now"
        ]
        has_auth_indicator = any(sig in combined_text for sig in auth_signals)
        has_non_login_elements = len(new_state.interactive_elements) > 0 and not any(
            e.element_type == "password_field" for e in new_state.elements
        )

        if has_auth_indicator or has_non_login_elements:
            return True, "Authenticated successfully into main application"

        return True, "Login screen dismissed successfully"

    def execute_login(
        self,
        device: str,
        state: ScreenState,
        re_dump_fn: Optional[Any] = None,
    ) -> Tuple[bool, str, List[UIAction]]:
        """Executes safe login using provided credentials without leaking passwords to logs."""
        actions: List[UIAction] = []
        if not self.credentials:
            return False, "No authorized test credentials supplied", actions

        user_field, pass_field, login_btn = self.find_credentials_fields(state)
        if not user_field or not pass_field or not login_btn:
            return False, "Could not identify all required login fields (email, password, login button)", actions

        # 1. Tap email field and type email
        self.adb.run_shell(["input", "tap", str(user_field.center[0]), str(user_field.center[1])], device=device)
        time.sleep(0.8)
        escaped_email = self.credentials.email.replace(" ", "%s").replace("!", r"\!")
        self.adb.run_shell(["input", "text", escaped_email], device=device)
        actions.append(
            UIAction(
                action_type="type_text",
                target_element_id=user_field.element_id,
                target_description=f"Input email into '{user_field.display_name}'",
                target_bounds=user_field.bounds,
                input_text=self.credentials.email[:3] + "***@" + self.credentials.email.split("@")[-1] if "@" in self.credentials.email else "***",
                status="EXECUTED",
                from_screen_name=state.screen_name,
            )
        )
        time.sleep(0.8)

        # 2. Tap password field and type password
        self.adb.run_shell(["input", "tap", str(pass_field.center[0]), str(pass_field.center[1])], device=device)
        time.sleep(0.8)
        escaped_password = self.credentials.password.replace(" ", "%s").replace("!", r"\!").replace("&", r"\&").replace("$", r"\$")
        self.adb.run_shell(["input", "text", escaped_password], device=device)
        actions.append(
            UIAction(
                action_type="type_text",
                target_element_id=pass_field.element_id,
                target_description=f"Input password into '{pass_field.display_name}'",
                target_bounds=pass_field.bounds,
                input_text="[REDACTED]",
                status="EXECUTED",
                from_screen_name=state.screen_name,
            )
        )
        time.sleep(0.8)

        # 3. Dismiss soft keyboard so login button is unobstructed and restored to viewport
        self.adb.send_key(4, device=device)  # KEYCODE_BACK dismisses soft keyboard
        time.sleep(1.0)

        # 4. Re-locate login button if re-dump callback is available
        btn_center = login_btn.center
        if re_dump_fn:
            refreshed_state = re_dump_fn()
            if refreshed_state:
                _, _, refreshed_btn = self.find_credentials_fields(refreshed_state)
                if refreshed_btn:
                    btn_center = refreshed_btn.center

        # 5. Tap login button
        self.adb.run_shell(["input", "tap", str(btn_center[0]), str(btn_center[1])], device=device)
        actions.append(
            UIAction(
                action_type="tap",
                target_element_id=login_btn.element_id,
                target_description=f"Tap '{login_btn.display_name}' button",
                target_bounds=login_btn.bounds,
                status="EXECUTED",
                from_screen_name=state.screen_name,
            )
        )

        # Wait for network authentication transition
        time.sleep(3.5)
        return True, "Login submitted", actions

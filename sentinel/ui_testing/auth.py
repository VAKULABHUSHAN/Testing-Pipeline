"""Authentication management, credential handling, and safe login execution."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import yaml

from sentinel.core.logging import logger
from sentinel.runtime.adb import ADBController
from sentinel.ui_testing.models import ScreenState, UIAction, UIElement


@dataclass
class AuthCredentials:
    """Safely encapsulates authorized test credentials."""
    email: str
    password: str

    def __repr__(self) -> str:
        masked_user = self.email[:3] + "***@" + self.email.split("@")[-1] if "@" in self.email else "***"
        return f"AuthCredentials(email='{masked_user}', password='[REDACTED]')"


class AuthManager:
    """Handles detection of authentication screens and safe credential injection."""

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
            re.search(r"\b(log\s*in|sign\s*in)\b", e.display_name, re.IGNORECASE)
            for e in state.interactive_elements
        )
        return has_password and has_login_btn

    def is_registration_screen(self, state: ScreenState) -> bool:
        """Determines if the given screen is a registration screen."""
        if state.is_registration_screen:
            return True

        has_reg_btn = any(
            re.search(r"\b(register|sign\s*up|create\s+account)\b", e.display_name, re.IGNORECASE)
            for e in state.interactive_elements
        )
        has_login_btn = any(
            re.search(r"\b(log\s*in|sign\s*in)\b", e.display_name, re.IGNORECASE)
            for e in state.interactive_elements
        )
        return has_reg_btn and not has_login_btn

    def find_login_link_from_registration(self, state: ScreenState) -> Optional[UIElement]:
        """Finds the navigation link/button that navigates from Registration to Login."""
        for e in state.interactive_elements:
            if re.search(r"\b(already\s+have\s+an\s+account|log\s*in|sign\s*in)\b", e.display_name, re.IGNORECASE):
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
            elif re.search(r"\b(log\s*in|sign\s*in)\b", name_lower):
                if login_btn is None:
                    login_btn = e

        return user_field, pass_field, login_btn

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
        escaped_email = self.credentials.email.replace(" ", "%s").replace("!", "\\!")
        self.adb.run_shell(["input", "text", escaped_email], device=device)
        actions.append(
            UIAction(
                action_type="type_text",
                target_element_id=user_field.element_id,
                target_description=f"Input email into '{user_field.display_name}'",
                target_bounds=user_field.bounds,
                input_text=self.credentials.email[:3] + "***@" + self.credentials.email.split("@")[-1],
                status="EXECUTED",
            )
        )
        time.sleep(0.8)

        # 2. Tap password field and type password
        self.adb.run_shell(["input", "tap", str(pass_field.center[0]), str(pass_field.center[1])], device=device)
        time.sleep(0.8)
        # Escape characters for adb shell input text
        escaped_password = self.credentials.password.replace(" ", "%s").replace("!", "\\!").replace("&", "\\&").replace("$", "\\$")
        self.adb.run_shell(["input", "text", escaped_password], device=device)
        actions.append(
            UIAction(
                action_type="type_text",
                target_element_id=pass_field.element_id,
                target_description=f"Input password into '{pass_field.display_name}'",
                target_bounds=pass_field.bounds,
                input_text="[REDACTED]",
                status="EXECUTED",
            )
        )
        time.sleep(0.8)

        # 3. Dismiss soft keyboard if visible so login button is accessible in original viewport
        code, out, _ = self.adb.run_shell(["dumpsys", "input_method"], device=device)
        if "mInputShown=true" in out:
            self.adb.send_key(111, device=device)  # KEYCODE_ESCAPE
            time.sleep(0.5)
            # Recheck and send back key only if keyboard still shown
            c2, o2, _ = self.adb.run_shell(["dumpsys", "input_method"], device=device)
            if "mInputShown=true" in o2:
                self.adb.send_key(4, device=device)  # KEYCODE_BACK
                time.sleep(0.8)

        # 4. Re-locate login button if re-dump callback is available to ensure accurate bounds
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
            )
        )

        # Wait for network and screen transition
        time.sleep(3.5)
        return True, "Login submitted", actions

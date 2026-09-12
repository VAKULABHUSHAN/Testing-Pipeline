"""UI hierarchy XML parser and screen element extractor."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from sentinel.ui_testing.models import ScreenState, UIElement, UIIssue
from sentinel.ui_testing.safety import SafetyClassifier


class HierarchyParser:
    """Parses Android uiautomator XML dumps into structured screen representations."""

    def __init__(self, safety_classifier: Optional[SafetyClassifier] = None):
        self.safety_classifier = safety_classifier or SafetyClassifier()

    def parse_bounds(self, bounds_str: str) -> Tuple[int, int, int, int]:
        """Parses bounds string of format '[left,top][right,bottom]' into a 4-tuple."""
        match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)))
        return (0, 0, 0, 0)

    def classify_element_type(self, node: ET.Element) -> str:
        """Determines semantic type of a UI node."""
        cls_name = (node.get("class") or "").lower()
        content_desc = (node.get("content-desc") or "").lower()
        text = (node.get("text") or "").lower()
        password = (node.get("password") or "false").lower() == "true"
        clickable = (node.get("clickable") or "false").lower() == "true"
        scrollable = (node.get("scrollable") or "false").lower() == "true"

        if password:
            return "password_field"
        if "edittext" in cls_name or (clickable and ("enter" in content_desc or "email" in content_desc or "password" in content_desc)):
            return "edit_text"
        if "button" in cls_name:
            return "button"
        if "checkbox" in cls_name:
            return "checkbox"
        if scrollable or "scrollview" in cls_name or "recyclerview" in cls_name or "listview" in cls_name:
            return "scrollable"
        if "tab" in cls_name or "tab" in content_desc:
            return "tab"
        if "menu" in cls_name or "menu" in content_desc:
            return "menu"
        if "imageview" in cls_name:
            return "image"
        if clickable:
            if "sign" in content_desc or "log" in content_desc or "next" in content_desc or "skip" in content_desc:
                return "button"
            return "button"
        if text or content_desc:
            return "text"
        return "container"

    def parse(
        self,
        xml_content: str,
        screenshot_path: Optional[str] = None,
        activity: Optional[str] = None,
        target_package: Optional[str] = None,
    ) -> Optional[ScreenState]:
        """Parses UI XML into a complete ScreenState, strictly filtered to target_package if specified."""
        if not xml_content or "<hierarchy" not in xml_content:
            return None

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            # Handle possible invalid trailing characters
            try:
                clean_xml = xml_content[xml_content.find("<hierarchy"):xml_content.rfind("</hierarchy>") + 12]
                root = ET.fromstring(clean_xml)
            except Exception:
                return None

        # If target_package is specified, verify target package nodes exist in hierarchy
        if target_package:
            has_target = any((node.get("package") or "") == target_package for node in root.iter("node"))
            if not has_target:
                # Target application is not in the foreground
                return None

        elements: List[UIElement] = []
        visible_text: List[str] = []
        interactive_elements: List[UIElement] = []
        accessibility_issues: List[UIIssue] = []
        ui_issues: List[UIIssue] = []

        package_name = target_package or ""
        elem_counter = 0

        # Traverse all nodes
        for node in root.iter("node"):
            pkg = node.get("package") or ""
            # Exclude elements belonging to other packages (launchers, other apps, system UI)
            if target_package and pkg != target_package:
                continue

            if pkg and not package_name:
                package_name = pkg

            text = (node.get("text") or "").strip()
            content_desc = (node.get("content-desc") or "").strip()
            resource_id = (node.get("resource-id") or "").strip()
            cls_name = node.get("class") or ""
            bounds_str = node.get("bounds") or "[0,0][0,0]"
            bounds = self.parse_bounds(bounds_str)

            clickable = (node.get("clickable") or "false").lower() == "true"
            focusable = (node.get("focusable") or "false").lower() == "true"
            focused = (node.get("focused") or "false").lower() == "true"
            scrollable = (node.get("scrollable") or "false").lower() == "true"
            enabled = (node.get("enabled") or "true").lower() == "true"
            password = (node.get("password") or "false").lower() == "true"
            selected = (node.get("selected") or "false").lower() == "true"

            elem_type = self.classify_element_type(node)

            if text:
                visible_text.append(text)
            if content_desc and content_desc not in visible_text:
                visible_text.append(content_desc)

            # Classify safety
            safety_class, _ = self.safety_classifier.classify(text, content_desc, resource_id)

            elem_id = f"elem_{elem_counter}_{elem_type}"
            elem_counter += 1

            element = UIElement(
                element_id=elem_id,
                element_type=elem_type,
                text=text,
                content_desc=content_desc,
                resource_id=resource_id,
                class_name=cls_name,
                package=pkg,
                bounds=bounds,
                clickable=clickable,
                focusable=focusable,
                focused=focused,
                scrollable=scrollable,
                enabled=enabled,
                password=password,
                selected=selected,
                safety_class=safety_class,
            )
            elements.append(element)

            # Check for interactive element
            if clickable or scrollable or elem_type in ("edit_text", "password_field", "button", "tab"):
                interactive_elements.append(element)

                # Check accessibility: Touch target size
                # Android recommendation is at least 48dp x 48dp (approximately 48px at base scale)
                if clickable and (element.width < 48 or element.height < 48) and element.width > 0 and element.height > 0:
                    accessibility_issues.append(
                        UIIssue(
                            issue_type="TOUCH_TARGET_TOO_SMALL",
                            title=f"Touch target below 48dp: '{element.display_name}'",
                            description=(
                                f"Interactive control '{element.display_name}' has physical dimensions of "
                                f"{element.width}x{element.height}px, which is below the recommended 48x48dp touch target standard."
                            ),
                            severity="LOW",
                            element_id=element.element_id,
                            evidence={"bounds": list(bounds), "width": element.width, "height": element.height},
                            recommendation="Increase the touch target area to at least 48x48dp to ensure accessibility.",
                        )
                    )

                # Check accessibility: Missing content description
                if clickable and not element.text and not element.content_desc:
                    accessibility_issues.append(
                        UIIssue(
                            issue_type="MISSING_ACCESSIBILITY_LABEL",
                            title=f"Clickable element missing semantic label: {element.class_name.split('.')[-1]}",
                            description=(
                                f"Clickable control of type '{element.class_name}' at bounds {bounds_str} has neither visible "
                                "text nor contentDescription, making it inaccessible to screen readers."
                            ),
                            severity="MEDIUM",
                            element_id=element.element_id,
                            evidence={"bounds": list(bounds), "class": element.class_name},
                            recommendation="Provide a meaningful contentDescription or label for all interactive components.",
                        )
                    )

        # Detect screen characteristics
        combined_text = " ".join(visible_text).lower()
        is_onboarding = any(w in combined_text for w in ("welcome", "get started", "skip", "intro")) and any(e.content_desc.lower() == "skip" or e.text.lower() == "skip" for e in interactive_elements)
        is_login = any(w in combined_text for w in ("login", "sign in", "welcome back")) and any(e.element_type in ("password_field", "edit_text") for e in interactive_elements)
        is_registration = any(w in combined_text for w in ("register", "sign up", "create account")) and any(e.element_type in ("password_field", "edit_text") for e in interactive_elements) and not is_login

        # Determine Screen Name heuristic
        screen_name = self._infer_screen_name(visible_text, is_onboarding, is_login, is_registration, activity)

        # Compute deterministic state ID
        state_id = self._compute_state_id(screen_name, interactive_elements)

        return ScreenState(
            state_id=state_id,
            screen_name=screen_name,
            package=package_name,
            activity=activity,
            screenshot_path=screenshot_path,
            elements=elements,
            visible_text=visible_text,
            interactive_elements=interactive_elements,
            accessibility_issues=accessibility_issues,
            ui_issues=ui_issues,
            is_login_screen=is_login,
            is_registration_screen=is_registration,
            is_onboarding_screen=is_onboarding,
            is_authenticated=not (is_onboarding or is_login or is_registration),
        )

    def _infer_screen_name(
        self,
        visible_text: List[str],
        is_onboarding: bool,
        is_login: bool,
        is_registration: bool,
        activity: Optional[str],
    ) -> str:
        """Infers a human-readable screen name based on prominent headings and content."""
        if is_onboarding:
            return "OnboardingScreen"
        if is_login:
            return "LoginScreen"
        if is_registration:
            return "RegistrationScreen"

        # Check for prominent known section titles in text
        text_lower = [t.lower() for t in visible_text]
        for t, orig in zip(text_lower, visible_text):
            for candidate in ("dashboard", "home", "profile", "settings", "cards", "categories", "faq", "guidelines", "about", "search", "details"):
                if candidate == t or (candidate in t and len(t) < 25):
                    return f"{candidate.capitalize()}Screen"

        if visible_text:
            first_clean = re.sub(r"[^a-zA-Z0-9]", "", visible_text[0])
            if first_clean and len(first_clean) < 20:
                return f"{first_clean.capitalize()}Screen"

        if activity:
            clean_act = activity.split(".")[-1].replace("Activity", "")
            if clean_act:
                return f"{clean_act}Screen"

        return "MainAppScreen"

    def _compute_state_id(self, screen_name: str, interactive_elements: List[UIElement]) -> str:
        """Computes a deterministic hash fingerprint representing this unique screen layout."""
        sig_elements = []
        for e in sorted(interactive_elements, key=lambda x: (x.bounds[1], x.bounds[0])):
            sig = f"{e.element_type}:{e.display_name}:{e.bounds[0]},{e.bounds[1]}"
            sig_elements.append(sig)
        raw_key = f"{screen_name}|" + "|".join(sig_elements)
        h = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
        return f"{screen_name}_{h}"

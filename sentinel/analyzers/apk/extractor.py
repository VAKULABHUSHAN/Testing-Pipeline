"""APK validation, metadata extraction, and structure analysis."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sentinel.core.exceptions import APKValidationError
from sentinel.core.logging import logger


@dataclass
class APKMetadata:
    """Structured metadata extracted from an Android APK."""
    file_path: str
    file_size_bytes: int
    file_size_mb: float
    sha256: str
    package_name: str
    version_name: str
    version_code: int
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    app_label: str
    launcher_activity: Optional[str]
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: List[Dict[str, Any]] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    is_flutter: bool = False
    abis: List[str] = field(default_factory=list)
    raw_badging: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "file_size_mb": self.file_size_mb,
            "sha256": self.sha256,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "app_label": self.app_label,
            "launcher_activity": self.launcher_activity,
            "activities_count": len(self.activities),
            "services_count": len(self.services),
            "receivers_count": len(self.receivers),
            "providers_count": len(self.providers),
            "exported_count": len(self.exported_components),
            "permissions_count": len(self.permissions),
            "is_flutter": self.is_flutter,
            "abis": self.abis,
        }


class APKExtractor:
    """Validates APKs, extracts metadata, and analyzes zip package structure."""

    def __init__(self, aapt_path: Optional[str] = None):
        self.aapt_path = aapt_path or self._resolve_aapt_path()

    def _resolve_aapt_path(self) -> Optional[str]:
        found = shutil.which("aapt")
        if found:
            return found

        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk_root and sys.platform == "win32":
            default_win = Path.home() / "AppData" / "Local" / "Android" / "Sdk"
            if default_win.exists():
                sdk_root = str(default_win)

        if sdk_root:
            build_tools = Path(sdk_root) / "build-tools"
            if build_tools.exists():
                # Pick the latest build-tools version available
                versions = sorted(list(build_tools.glob("*")), reverse=True)
                for v in versions:
                    ext = ".exe" if sys.platform == "win32" else ""
                    candidate = v / f"aapt{ext}"
                    if candidate.exists():
                        return str(candidate)
        return None

    def validate_apk_file(self, apk_path: str | Path) -> Path:
        """Validates that the file exists, has .apk extension, is readable, and non-empty."""
        path = Path(apk_path).resolve()
        if not path.exists():
            raise APKValidationError(f"APK file does not exist: {path}")
        if not path.is_file():
            raise APKValidationError(f"Target path is not a file: {path}")
        if path.suffix.lower() != ".apk":
            raise APKValidationError(f"File is not an Android APK (expected .apk extension): {path}")

        try:
            size = path.stat().st_size
            if size == 0:
                raise APKValidationError(f"APK file is empty (0 bytes): {path}")
        except OSError as e:
            raise APKValidationError(f"Cannot read APK file attributes: {e}") from e

        # Validate that it is a readable zip file
        if not zipfile.is_zipfile(path):
            raise APKValidationError(f"APK is not a valid ZIP archive: {path}")

        return path

    def calculate_sha256(self, path: Path) -> str:
        """Calculates SHA-256 hash of APK file."""
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def extract_metadata(self, apk_path: str | Path) -> APKMetadata:
        """Extracts complete APK metadata using aapt and zip inspection."""
        path = self.validate_apk_file(apk_path)
        sha256 = self.calculate_sha256(path)
        size_bytes = path.stat().st_size
        size_mb = round(size_bytes / (1024 * 1024), 2)

        raw_badging = ""
        package_name = "unknown"
        version_code = 1
        version_name = "1.0.0"
        min_sdk = None
        target_sdk = None
        app_label = path.stem
        launcher_activity = None
        permissions: List[str] = []
        abis: List[str] = []
        is_flutter = False

        # First probe via aapt badging if aapt is available
        if self.aapt_path:
            try:
                res = subprocess.run(
                    [self.aapt_path, "dump", "badging", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                    shell=False,
                )
                if res.returncode == 0 and res.stdout:
                    raw_badging = res.stdout
                    package_name, version_code, version_name = self._parse_badging_package(raw_badging)
                    min_sdk, target_sdk = self._parse_badging_sdk(raw_badging)
                    app_label = self._parse_badging_label(raw_badging) or app_label
                    launcher_activity = self._parse_badging_launcher(raw_badging)
                    permissions = self._parse_badging_permissions(raw_badging)
            except Exception as e:
                logger.warning(f"Failed to extract badging with aapt: {e}")

        # Structure analysis via zipfile
        activities: List[str] = []
        services: List[str] = []
        receivers: List[str] = []
        providers: List[str] = []
        exported_components: List[Dict[str, Any]] = []

        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                # Check Flutter presence
                if any("flutter_assets" in n or "libflutter.so" in n for n in names):
                    is_flutter = True

                # Check ABIs
                detected_abis = set()
                for n in names:
                    if n.startswith("lib/") and n.count("/") == 2:
                        parts = n.split("/")
                        detected_abis.add(parts[1])
                abis = sorted(list(detected_abis))
        except Exception as e:
            logger.warning(f"Error inspecting zip contents: {e}")

        # Inspect Manifest XML tree via aapt if available
        if self.aapt_path:
            manifest_tree = self._dump_xmltree(path, "AndroidManifest.xml")
            if manifest_tree:
                comp_info = self._parse_manifest_tree(manifest_tree, package_name)
                activities = comp_info.get("activities", [])
                services = comp_info.get("services", [])
                receivers = comp_info.get("receivers", [])
                providers = comp_info.get("providers", [])
                exported_components = comp_info.get("exported", [])
                if not launcher_activity and comp_info.get("launcher"):
                    launcher_activity = comp_info.get("launcher")

        return APKMetadata(
            file_path=str(path),
            file_size_bytes=size_bytes,
            file_size_mb=size_mb,
            sha256=sha256,
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            app_label=app_label,
            launcher_activity=launcher_activity,
            activities=activities,
            services=services,
            receivers=receivers,
            providers=providers,
            exported_components=exported_components,
            permissions=permissions,
            is_flutter=is_flutter,
            abis=abis,
            raw_badging=raw_badging,
        )

    def _dump_xmltree(self, apk_path: Path, xml_file: str) -> str:
        """Dumps formatted XML tree from APK."""
        if not self.aapt_path:
            return ""
        try:
            res = subprocess.run(
                [self.aapt_path, "dump", "xmltree", str(apk_path), xml_file],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                shell=False,
            )
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

    @staticmethod
    def _parse_badging_package(badging: str) -> Tuple[str, int, str]:
        pkg = "unknown"
        code = 1
        name = "1.0.0"
        m = re.search(r"package:\s*name='([^']+)'(?:\s+versionCode='(\d+)')?(?:\s+versionName='([^']+)')?", badging)
        if m:
            pkg = m.group(1) or pkg
            code = int(m.group(2)) if m.group(2) else code
            name = m.group(3) or name
        return pkg, code, name

    @staticmethod
    def _parse_badging_sdk(badging: str) -> Tuple[Optional[int], Optional[int]]:
        min_sdk = None
        target_sdk = None
        m_min = re.search(r"sdkVersion:'(\d+)'", badging)
        if m_min:
            min_sdk = int(m_min.group(1))
        m_target = re.search(r"targetSdkVersion:'(\d+)'", badging)
        if m_target:
            target_sdk = int(m_target.group(1))
        return min_sdk, target_sdk

    @staticmethod
    def _parse_badging_label(badging: str) -> Optional[str]:
        m = re.search(r"application-label:'([^']+)'", badging)
        return m.group(1) if m else None

    @staticmethod
    def _parse_badging_launcher(badging: str) -> Optional[str]:
        m = re.search(r"launchable-activity:\s*name='([^']+)'", badging)
        return m.group(1) if m else None

    @staticmethod
    def _parse_badging_permissions(badging: str) -> List[str]:
        perms = []
        for line in badging.splitlines():
            m = re.search(r"uses-permission:\s*name='([^']+)'", line)
            if m:
                perms.append(m.group(1))
        return perms

    @staticmethod
    def _parse_manifest_tree(tree: str, package_name: str) -> Dict[str, Any]:
        """Parses aapt xmltree output for components and exported status."""
        activities = []
        services = []
        receivers = []
        providers = []
        exported_list = []
        launcher = None

        current_elem: Optional[str] = None
        current_name: Optional[str] = None
        current_exported: Optional[bool] = None
        current_permission: Optional[str] = None
        has_intent_filter = False
        is_launcher_filter = False

        def _add_exported(exp_item: Dict[str, Any]) -> None:
            for existing in exported_list:
                if existing["name"] == exp_item["name"] and existing["type"] == exp_item["type"]:
                    return
            exported_list.append(exp_item)

        for line in tree.splitlines():
            line_str = line.strip()
            # Detect Element
            if line_str.startswith("E: "):
                elem = line_str.split()[1]
                if elem in ("activity", "service", "receiver", "provider"):
                    # Save previous component if exists
                    if current_elem and current_name:
                        exp = current_exported if current_exported is not None else has_intent_filter
                        if exp:
                            _add_exported({
                                "type": current_elem,
                                "name": current_name,
                                "permission": current_permission,
                                "has_filter": has_intent_filter,
                            })
                        if is_launcher_filter and not launcher:
                            launcher = current_name

                    current_elem = elem
                    current_name = None
                    current_exported = None
                    current_permission = None
                    has_intent_filter = False
                    is_launcher_filter = False
                elif elem not in ("intent-filter", "action", "category", "meta-data", "data", "layout"):
                    if current_elem and current_name:
                        exp = current_exported if current_exported is not None else has_intent_filter
                        if exp:
                            _add_exported({
                                "type": current_elem,
                                "name": current_name,
                                "permission": current_permission,
                                "has_filter": has_intent_filter,
                            })
                        if is_launcher_filter and not launcher:
                            launcher = current_name
                    current_elem = None

            # Detect Attributes
            elif "A: android:name(" in line_str and current_elem:
                m = re.search(r'="([^"]+)"', line_str)
                if m and not current_name:
                    cname = m.group(1)
                    if cname.startswith("."):
                        cname = package_name + cname
                    current_name = cname
                    if current_elem == "activity" and cname not in activities:
                        activities.append(cname)
                    elif current_elem == "service" and cname not in services:
                        services.append(cname)
                    elif current_elem == "receiver" and cname not in receivers:
                        receivers.append(cname)
                    elif current_elem == "provider" and cname not in providers:
                        providers.append(cname)

            elif "A: android:exported(" in line_str and current_elem:
                if "0xffffffff" in line_str or "true" in line_str:
                    current_exported = True
                elif "0x0" in line_str or "false" in line_str:
                    current_exported = False

            elif "A: android:permission(" in line_str and current_elem:
                m = re.search(r'="([^"]+)"', line_str)
                if m:
                    current_permission = m.group(1)

            elif "E: intent-filter" in line_str and current_elem:
                has_intent_filter = True

            elif 'android.intent.action.MAIN' in line_str or 'android.intent.category.LAUNCHER' in line_str:
                is_launcher_filter = True

        # Process trailing element
        if current_elem and current_name:
            exp = current_exported if current_exported is not None else has_intent_filter
            if exp:
                _add_exported({
                    "type": current_elem,
                    "name": current_name,
                    "permission": current_permission,
                    "has_filter": has_intent_filter,
                })
            if is_launcher_filter and not launcher:
                launcher = current_name

        return {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "exported": exported_list,
            "launcher": launcher,
        }

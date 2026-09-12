"""Android Debug Bridge (ADB) controller and device manager."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sentinel.core.exceptions import RuntimeDeviceError, TargetPackageViolation
from sentinel.core.logging import logger


class ADBController:
    """Manages low-level ADB operations safely and deterministically."""

    def __init__(
        self,
        adb_path: Optional[str] = None,
        timeout_seconds: int = 45,
        target_package: Optional[str] = None,
    ):
        self.adb_path = adb_path or self._resolve_adb_path()
        self.timeout_seconds = timeout_seconds
        self.target_package = target_package

    def set_target_package(self, package_name: str) -> None:
        """Permanently locks operations to the specified target application package."""
        self.target_package = package_name

    def validate_target_package(self, package_name: str) -> None:
        """Guards against any ADB operation targeting unauthorized packages."""
        if self.target_package and package_name != self.target_package:
            raise TargetPackageViolation(
                f"Attempted operation on package '{package_name}'. "
                f"Allowed package: '{self.target_package}'"
            )

    def _resolve_adb_path(self) -> str:
        found = shutil.which("adb")
        if found:
            return found

        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk_root and sys.platform == "win32":
            default_win = Path.home() / "AppData" / "Local" / "Android" / "Sdk"
            if default_win.exists():
                sdk_root = str(default_win)

        if sdk_root:
            ext = ".exe" if sys.platform == "win32" else ""
            candidate = Path(sdk_root) / "platform-tools" / f"adb{ext}"
            if candidate.exists():
                return str(candidate)

        return "adb"

    def _execute(
        self,
        args: List[str],
        device: Optional[str] = None,
        timeout: Optional[int] = None,
        check: bool = False,
    ) -> Tuple[int, str, str]:
        """Safely executes an ADB command with timeout."""
        cmd = [self.adb_path]
        if device:
            cmd.extend(["-s", device])
        cmd.extend(args)

        t = timeout or self.timeout_seconds
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=t,
                check=check,
                shell=False,
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except subprocess.TimeoutExpired:
            logger.warning(f"ADB command timed out after {t}s: {' '.join(cmd)}")
            return -2, "", f"Command timed out after {t} seconds"
        except FileNotFoundError:
            return -1, "", f"ADB binary not found at {self.adb_path}"
        except Exception as e:
            return -3, "", str(e)

    def start_server(self) -> bool:
        """Starts the ADB daemon server."""
        code, _, _ = self._execute(["start-server"], timeout=15)
        return code == 0

    def list_devices(self) -> List[str]:
        """Returns a list of connected authorized devices/emulators."""
        self.start_server()
        code, out, _ = self._execute(["devices"], timeout=10)
        if code != 0 or not out:
            return []

        devices = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    def get_default_device(self) -> Optional[str]:
        """Returns the first available online device, or None."""
        devs = self.list_devices()
        return devs[0] if devs else None

    def run_shell(
        self,
        args: List[str],
        device: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Tuple[int, str, str]:
        """Runs a command via adb shell."""
        cmd = ["shell"] + args
        return self._execute(cmd, device=device, timeout=timeout)

    def install_apk(
        self,
        apk_path: str,
        device: Optional[str] = None,
        replace: bool = True,
    ) -> Tuple[bool, str]:
        """Installs an APK on the target device."""
        if not Path(apk_path).exists():
            return False, f"APK file not found: {apk_path}"

        args = ["install"]
        if replace:
            args.append("-r")
        args.append(str(Path(apk_path).resolve()))

        code, out, err = self._execute(args, device=device, timeout=120)
        output = f"{out}\n{err}".strip()
        if code == 0 and "Success" in output:
            return True, "Success"
        return False, output or "Installation failed with non-zero exit code"

    def uninstall_package(
        self,
        package_name: str,
        device: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Uninstalls a package from the target device."""
        self.validate_target_package(package_name)
        code, out, err = self._execute(["uninstall", package_name], device=device, timeout=30)
        output = f"{out}\n{err}".strip()
        if code == 0 and "Success" in output:
            return True, "Success"
        return False, output

    def is_package_installed(
        self,
        package_name: str,
        device: Optional[str] = None,
    ) -> bool:
        """Verifies if the specified package is installed on the target device."""
        self.validate_target_package(package_name)
        code, out, _ = self.run_shell(["pm", "path", package_name], device=device, timeout=10)
        return code == 0 and "package:" in out

    def get_foreground_package(self, device: Optional[str] = None) -> Optional[str]:
        """Identifies the application package currently active in the foreground."""
        import re

        # 1. Try dumpsys activity activities (fast and accurate for top resumed activity)
        code, out, _ = self.run_shell(["dumpsys", "activity", "activities"], device=device, timeout=5)
        if code == 0 and out:
            m = re.search(r"(?:topResumedActivity|mResumedActivity)=ActivityRecord\{[0-9a-fA-F]+\s+u\d+\s+([a-zA-Z0-9._]+)/", out)
            if m:
                return m.group(1)
            m = re.search(r"(?:topResumedActivity|mResumedActivity).*?\s+([a-zA-Z0-9._]+)/", out)
            if m:
                return m.group(1)

        # 2. Fallback to dumpsys window
        code, out, _ = self.run_shell(["dumpsys", "window"], device=device, timeout=5)
        if code == 0 and out:
            m = re.search(r"mCurrentFocus=Window\{[0-9a-fA-F]+\s+u\d+\s+([a-zA-Z0-9._]+)/", out)
            if m:
                return m.group(1)
            m = re.search(r"mFocusedApp=ActivityRecord\{[0-9a-fA-F]+\s+u\d+\s+([a-zA-Z0-9._]+)/", out)
            if m:
                return m.group(1)

        return None

    def launch_package(
        self,
        package_name: str,
        activity_name: Optional[str] = None,
        device: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Launches an application by activity or monkey dispatch."""
        self.validate_target_package(package_name)
        if activity_name:
            target = f"{package_name}/{activity_name}"
            code, out, err = self.run_shell(["am", "start", "-n", target], device=device, timeout=20)
            if code == 0 and "Error" not in out:
                return True, out
            logger.warning(f"am start failed for {target}, falling back to monkey: {out}")

        # Fallback to monkey launcher
        code, out, err = self.run_shell(
            ["monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            device=device,
            timeout=20,
        )
        if code == 0 and "Events injected: 1" in out:
            return True, "Launched via category.LAUNCHER"
        return False, f"{out}\n{err}".strip()

    def force_stop(self, package_name: str, device: Optional[str] = None) -> bool:
        """Force-stops the target package."""
        self.validate_target_package(package_name)
        code, _, _ = self.run_shell(["am", "force-stop", package_name], device=device, timeout=10)
        return code == 0

    def get_pid(self, package_name: str, device: Optional[str] = None) -> Optional[int]:
        """Retrieves process ID for the target package if running."""
        self.validate_target_package(package_name)
        code, out, _ = self.run_shell(["pidof", package_name], device=device, timeout=5)
        if code == 0 and out.strip():
            first = out.strip().split()[0]
            if first.isdigit():
                return int(first)

        # Fallback to ps -A
        code, out, _ = self.run_shell(["ps", "-A"], device=device, timeout=10)
        if code == 0 and out:
            for line in out.splitlines():
                if package_name in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
        return None

    def is_running(self, package_name: str, device: Optional[str] = None) -> bool:
        """Checks whether the application process is alive."""
        self.validate_target_package(package_name)
        return self.get_pid(package_name, device=device) is not None

    def clear_logcat(self, device: Optional[str] = None) -> bool:
        """Clears existing logcat buffer."""
        code, _, _ = self._execute(["logcat", "-c"], device=device, timeout=10)
        return code == 0

    def capture_logcat(
        self,
        device: Optional[str] = None,
        max_lines: int = 5000,
    ) -> str:
        """Dumps current logcat contents safely."""
        code, out, _ = self._execute(["logcat", "-d", "-t", str(max_lines), "-v", "time"], device=device, timeout=20)
        return out if code == 0 else ""

    def take_screenshot(self, output_path: Path | str, device: Optional[str] = None) -> bool:
        """Captures a screenshot from device and saves it to local disk."""
        target_path = Path(output_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        remote_tmp = f"/data/local/tmp/sentinel_ss_{int(time.time())}.png"

        try:
            # Capture remotely
            code, _, _ = self.run_shell(["screencap", "-p", remote_tmp], device=device, timeout=15)
            if code != 0:
                return False

            # Pull to host
            code, _, _ = self._execute(["pull", remote_tmp, str(target_path.resolve())], device=device, timeout=20)
            # Remove remote temp
            self.run_shell(["rm", "-f", remote_tmp], device=device, timeout=5)
            return code == 0 and target_path.exists() and target_path.stat().st_size > 0
        except Exception as e:
            logger.warning(f"Screenshot capture failed: {e}")
            return False

    def get_device_properties(self, device: Optional[str] = None) -> Dict[str, str]:
        """Fetches basic Android OS and hardware properties."""
        code, out, _ = self.run_shell(["getprop"], device=device, timeout=10)
        props: Dict[str, str] = {}
        if code == 0 and out:
            for line in out.splitlines():
                if ":" in line and "[" in line:
                    try:
                        k = line.split("]: [")[0].strip("[] \t")
                        v = line.split("]: [")[1].rstrip("]")
                        props[k] = v
                    except Exception:
                        continue
        return {
            "model": props.get("ro.product.model", "Unknown Model"),
            "manufacturer": props.get("ro.product.manufacturer", "Android"),
            "android_version": props.get("ro.build.version.release", "Unknown"),
            "sdk_version": props.get("ro.build.version.sdk", "Unknown"),
            "abi": props.get("ro.product.cpu.abi", "Unknown"),
        }

    def send_key(self, keycode: int | str, device: Optional[str] = None) -> bool:
        """Sends an input keyevent (e.g. 3 for HOME, 4 for BACK)."""
        code, _, _ = self.run_shell(["input", "keyevent", str(keycode)], device=device, timeout=5)
        return code == 0

    def set_network_state(self, enabled: bool, device: Optional[str] = None) -> bool:
        """Safely toggles network connectivity on device (Wi-Fi / Data)."""
        cmd_state = "enable" if enabled else "disable"
        c1, _, _ = self.run_shell(["svc", "wifi", cmd_state], device=device, timeout=10)
        c2, _, _ = self.run_shell(["svc", "data", cmd_state], device=device, timeout=10)
        return c1 == 0 or c2 == 0

    def set_rotation(self, landscape: bool, device: Optional[str] = None) -> bool:
        """Changes user rotation setting (0 = portrait, 1 = landscape)."""
        val = "1" if landscape else "0"
        code, _, _ = self.run_shell(["settings", "put", "system", "user_rotation", val], device=device, timeout=10)
        return code == 0

    def dump_ui_hierarchy(self, device: Optional[str] = None) -> Optional[str]:
        """Dumps UI XML hierarchy from device."""
        remote_xml = f"/data/local/tmp/uidump_{int(time.time())}.xml"
        c1, _, _ = self.run_shell(["uiautomator", "dump", remote_xml], device=device, timeout=15)
        if c1 != 0:
            return None

        c2, out, _ = self.run_shell(["cat", remote_xml], device=device, timeout=15)
        self.run_shell(["rm", "-f", remote_xml], device=device, timeout=5)
        return out if c2 == 0 else None

    def get_memory_info(self, package_name: str, device: Optional[str] = None) -> Dict[str, str]:
        """Captures process memory statistics via dumpsys meminfo."""
        self.validate_target_package(package_name)
        code, out, _ = self.run_shell(["dumpsys", "meminfo", package_name], device=device, timeout=15)
        info = {}
        if code == 0 and out:
            for line in out.splitlines():
                if "TOTAL PSS:" in line or "TOTAL:" in line or "Native Heap:" in line or "Dalvik Heap:" in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        info[parts[0]] = parts[1]
        return info

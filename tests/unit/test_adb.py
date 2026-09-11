"""Unit tests for ADB abstraction and device management."""

from unittest.mock import MagicMock, patch
from sentinel.runtime.adb import ADBController


def test_adb_list_devices_empty() -> None:
    adb = ADBController()
    with patch.object(adb, "_execute", return_value=(0, "List of devices attached\n", "")):
        devs = adb.list_devices()
        assert devs == []


def test_adb_list_devices_detected() -> None:
    adb = ADBController()
    with patch.object(adb, "_execute", return_value=(0, "List of devices attached\nemulator-5554\tdevice\n", "")):
        devs = adb.list_devices()
        assert devs == ["emulator-5554"]
        assert adb.get_default_device() == "emulator-5554"


def test_adb_install_apk_success() -> None:
    adb = ADBController()
    with patch("pathlib.Path.exists", return_value=True), \
         patch.object(adb, "_execute", return_value=(0, "Success", "")):
        ok, msg = adb.install_apk("test.apk")
        assert ok is True
        assert msg == "Success"


def test_adb_install_apk_failure() -> None:
    adb = ADBController()
    with patch("pathlib.Path.exists", return_value=True), \
         patch.object(adb, "_execute", return_value=(1, "Failure [INSTALL_FAILED_ALREADY_EXISTS]", "")):
        ok, msg = adb.install_apk("test.apk")
        assert ok is False
        assert "INSTALL_FAILED_ALREADY_EXISTS" in msg


def test_adb_get_pid_via_pidof() -> None:
    adb = ADBController()
    with patch.object(adb, "run_shell", return_value=(0, "12345", "")):
        pid = adb.get_pid("com.example.app")
        assert pid == 12345
        assert adb.is_running("com.example.app") is True


def test_adb_device_properties() -> None:
    adb = ADBController()
    sample_getprop = (
        "[ro.product.model]: [Pixel 7]\n"
        "[ro.product.manufacturer]: [Google]\n"
        "[ro.build.version.release]: [14]\n"
        "[ro.build.version.sdk]: [34]\n"
        "[ro.product.cpu.abi]: [arm64-v8a]\n"
    )
    with patch.object(adb, "run_shell", return_value=(0, sample_getprop, "")):
        props = adb.get_device_properties("emulator-5554")
        assert props["model"] == "Pixel 7"
        assert props["android_version"] == "14"
        assert props["sdk_version"] == "34"

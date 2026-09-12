"""Unit tests for Single Application Test Isolation."""

import pytest
from unittest.mock import MagicMock, patch

from sentinel.core.exceptions import TargetPackageViolation
from sentinel.runtime.adb import ADBController
from sentinel.runtime.monitor import RuntimeMonitor
from sentinel.ui_testing.hierarchy import HierarchyParser
from sentinel.ui_testing.explorer import UIExplorer


SAMPLE_LAUNCHER_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.google.android.apps.nexuslauncher" bounds="[0,0][1080,2400]">
    <node index="0" text="Predicted app: aurum" resource-id="com.google.android.apps.nexuslauncher:id/icon" class="android.widget.TextView" package="com.google.android.apps.nexuslauncher" content-desc="Predicted app: aurum" clickable="true" bounds="[54,2040][258,2280]" />
    <node index="1" text="Card Vault" resource-id="com.google.android.apps.nexuslauncher:id/icon" class="android.widget.TextView" package="com.google.android.apps.nexuslauncher" content-desc="Card Vault" clickable="true" bounds="[300,2040][504,2280]" />
  </node>
</hierarchy>"""

SAMPLE_APP_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.card_vault" bounds="[0,0][1080,2400]">
    <node index="0" text="Card Vault" resource-id="" class="android.view.View" package="com.example.card_vault" content-desc="Card Vault" clickable="false" bounds="[48,120][300,180]" />
    <node index="1" text="Login" resource-id="" class="android.widget.Button" package="com.example.card_vault" content-desc="Login" clickable="true" bounds="[100,500][400,600]" />
    <node index="2" text="" resource-id="" class="android.view.View" package="com.android.systemui" bounds="[0,0][1080,63]" />
  </node>
</hierarchy>"""


def test_adb_target_package_lock_violation():
    adb = ADBController()
    adb.set_target_package("com.example.card_vault")

    # Allowed operations
    adb.validate_target_package("com.example.card_vault")

    # Guard violation
    with pytest.raises(TargetPackageViolation) as exc_info:
        adb.validate_target_package("com.example.aurum")

    assert "Attempted operation on package 'com.example.aurum'" in str(exc_info.value)
    assert "Allowed package: 'com.example.card_vault'" in str(exc_info.value)


def test_adb_package_methods_enforce_guard():
    adb = ADBController()
    adb.set_target_package("com.example.card_vault")

    with pytest.raises(TargetPackageViolation):
        adb.launch_package("com.example.aurum")

    with pytest.raises(TargetPackageViolation):
        adb.force_stop("com.example.aurum")

    with pytest.raises(TargetPackageViolation):
        adb.get_pid("com.example.aurum")

    with pytest.raises(TargetPackageViolation):
        adb.is_running("com.example.aurum")

    with pytest.raises(TargetPackageViolation):
        adb.uninstall_package("com.example.aurum")

    with pytest.raises(TargetPackageViolation):
        adb.get_memory_info("com.example.aurum")

    with pytest.raises(TargetPackageViolation):
        adb.is_package_installed("com.example.aurum")


def test_adb_get_foreground_package_activity_dump():
    adb = ADBController()
    dumpsys_output = (
        "  topResumedActivity=ActivityRecord{1214110 u0 com.example.card_vault/.MainActivity t6}\n"
    )
    with patch.object(adb, "run_shell", return_value=(0, dumpsys_output, "")):
        fg = adb.get_foreground_package()
        assert fg == "com.example.card_vault"


def test_adb_get_foreground_package_window_dump():
    adb = ADBController()
    # Mock activity dump failing, falling back to window dump
    def mock_run_shell(cmd, **kwargs):
        if "activities" in cmd:
            return (0, "", "")
        return (0, "  mCurrentFocus=Window{349bfc7 u0 com.example.aurum/com.example.aurum.MainActivity}", "")

    with patch.object(adb, "run_shell", side_effect=mock_run_shell):
        fg = adb.get_foreground_package()
        assert fg == "com.example.aurum"


def test_hierarchy_parser_rejects_foreign_screens():
    parser = HierarchyParser()

    # When parsing launcher screen with target_package="com.example.card_vault",
    # since no card_vault package nodes exist, it returns None.
    state = parser.parse(SAMPLE_LAUNCHER_XML, target_package="com.example.card_vault")
    assert state is None


def test_hierarchy_parser_filters_foreign_nodes():
    parser = HierarchyParser()

    # When parsing app screen, system UI nodes (com.android.systemui) should be excluded
    state = parser.parse(SAMPLE_APP_XML, target_package="com.example.card_vault")
    assert state is not None
    assert state.package == "com.example.card_vault"
    assert len(state.elements) == 3  # Root container + 2 card_vault child nodes, excluding systemui
    for elem in state.elements:
        assert elem.package == "com.example.card_vault"


def test_runtime_monitor_crash_isolation():
    monitor = RuntimeMonitor(package_name="com.example.card_vault")

    foreign_crash_log = """
09-11 12:00:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main
09-11 12:00:00.000 1234 1234 E AndroidRuntime: Process: com.example.aurum, PID: 12345
09-11 12:00:00.000 1234 1234 E AndroidRuntime: java.lang.RuntimeException: Test Aurum crash
"""
    res_foreign = monitor.analyze_logcat(foreign_crash_log)
    assert not res_foreign.has_crash
    assert len(res_foreign.findings) == 0

    target_crash_log = """
09-11 12:00:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main
09-11 12:00:00.000 1234 1234 E AndroidRuntime: Process: com.example.card_vault, PID: 54321
09-11 12:00:00.000 1234 1234 E AndroidRuntime: java.lang.RuntimeException: Target app crash
"""
    res_target = monitor.analyze_logcat(target_crash_log)
    assert res_target.has_crash
    assert len(res_target.findings) == 1
    assert res_target.findings[0].id == "RUNTIME_APP_CRASH"

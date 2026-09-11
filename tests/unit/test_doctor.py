"""Unit tests for Environment Doctor tooling detection."""

from unittest.mock import patch, MagicMock
from sentinel.environment.doctor import EnvironmentDoctor
from sentinel.core.enums import ToolStatus


def test_doctor_python_detection() -> None:
    doctor = EnvironmentDoctor()
    res = doctor.check_python()
    assert res.found is True
    assert res.name == "Python"
    assert res.version is not None
    assert res.status in (ToolStatus.AVAILABLE, ToolStatus.DEGRADED)


def test_doctor_adb_mocked_missing() -> None:
    doctor = EnvironmentDoctor()
    with patch("shutil.which", return_value=None), \
         patch.object(doctor, "_find_sdk_tool", return_value=None):
        res = doctor.check_adb()
        assert res.found is False
        assert res.status == ToolStatus.MISSING
        assert res.remediation is not None


def test_doctor_adb_mocked_present() -> None:
    doctor = EnvironmentDoctor()
    with patch("shutil.which", return_value="/mock/path/adb"), \
         patch.object(doctor, "_run_command", return_value=(0, "Android Debug Bridge version 1.0.41", "")):
        res = doctor.check_adb()
        assert res.found is True
        assert res.status == ToolStatus.AVAILABLE
        assert res.version == "1.0.41"
        assert res.path == "/mock/path/adb"


def test_doctor_diagnose_aggregates_all() -> None:
    doctor = EnvironmentDoctor()
    report = doctor.diagnose()
    assert "python" in report.tools
    assert "adb" in report.tools
    assert "android_sdk" in report.tools
    assert "java" in report.tools
    assert "flutter" in report.tools
    assert isinstance(report.ready_for_scan, bool)
    assert report.summary != ""


def test_doctor_render_console_report() -> None:
    doctor = EnvironmentDoctor()
    report = doctor.diagnose()
    rendered = doctor.render_console_report(report)
    assert "MOBILE SENTINEL - ENVIRONMENT DOCTOR" in rendered
    assert "Static Scan Readiness" in rendered

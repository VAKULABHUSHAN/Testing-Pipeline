"""Unit tests for Runtime logcat analysis and performance jank detection."""

from sentinel.runtime.monitor import RuntimeMonitor
from sentinel.core.enums import FindingCategory, Severity


def test_monitor_skipped_frames_thresholds() -> None:
    monitor = RuntimeMonitor(package_name="com.example.aurum")

    # Aurum test case: 356 frames skipped -> HIGH severity PERFORMANCE finding
    logcat_text = (
        "09-11 10:00:01.123 1234 1234 I Choreographer: Skipped 356 frames! The application may be doing too much work on its main thread.\n"
        "09-11 10:00:02.123 1234 1234 I System: Normal log line"
    )

    result = monitor.analyze_logcat(logcat_text)
    assert result.has_crash is False
    assert result.skipped_frames_max == 356
    assert len(result.findings) == 1

    perf_finding = result.findings[0]
    assert perf_finding.category == FindingCategory.PERFORMANCE
    assert perf_finding.severity == Severity.HIGH
    assert "356 frames" in perf_finding.description


def test_monitor_crash_detection() -> None:
    monitor = RuntimeMonitor(package_name="com.example.app")

    logcat_text = (
        "09-11 10:00:05.100 2345 2345 E AndroidRuntime: FATAL EXCEPTION: main\n"
        "Process: com.example.app, PID: 2345\n"
        "java.lang.NullPointerException: Attempt to invoke virtual method on a null object reference\n"
        "    at com.example.app.MainActivity.onCreate(MainActivity.java:42)"
    )

    result = monitor.analyze_logcat(logcat_text)
    assert result.has_crash is True
    assert len(result.findings) == 1
    assert result.findings[0].id == "RUNTIME_APP_CRASH"
    assert result.findings[0].severity == Severity.HIGH


def test_monitor_ignores_system_noise() -> None:
    monitor = RuntimeMonitor(package_name="com.example.app")

    logcat_text = (
        "W/SELinux: max_map_count denial in emulator\n"
        "W/System: Unexpected CPU variant detected\n"
        "W/HWUI: HWUI warnings encountered during render\n"
        "W/ANGLE: ANGLE configuration warning\n"
        "W/ashmem: ashmem is deprecated"
    )

    result = monitor.analyze_logcat(logcat_text)
    assert result.has_crash is False
    assert result.has_anr is False
    assert len(result.findings) == 0

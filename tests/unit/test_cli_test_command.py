"""Unit tests for sentinel test CLI command handling."""

from unittest.mock import MagicMock, patch
from click.testing import CliRunner
from sentinel.cli.main import cli
from sentinel.orchestrator.pipeline import ScanExecutionResult
from sentinel.core.models import ScanMetadata, RiskScoreSummary


def test_cli_test_apk_not_found() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["test", "non_existent_path.apk"])
    assert result.exit_code == 1
    assert "[ERROR] APK not found:" in result.output
    # Ensure no traceback
    assert "Traceback" not in result.output


def test_cli_test_no_device_detected(tmp_path) -> None:
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()

    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=[]):
        result = runner.invoke(cli, ["test", str(fake_apk)])
        assert result.exit_code == 1
        assert "[ERROR] No Android device or emulator detected." in result.output
        assert "Traceback" not in result.output


def test_cli_test_success_mocked(tmp_path) -> None:
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()

    mock_result = ScanExecutionResult(
        scan_id="MS-TEST-001",
        metadata=ScanMetadata(
            scan_id="MS-TEST-001",
            app_path=str(fake_apk),
            app_hash_sha256="abc12345",
            app_name="Mock App",
            package_name="com.example.mock",
        ),
        apk_meta=None,
        device_name="emulator-5554",
        risk_summary=RiskScoreSummary(overall_score=90.0, risk_level="LOW"),
    )

    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_result), \
         patch("sentinel.reporting.text_report.TextReportGenerator.generate", return_value="report text"), \
         patch("sentinel.reporting.json_report.JsonReportGenerator.generate", return_value="{}"):
        result = runner.invoke(cli, ["test", str(fake_apk), "--output", str(tmp_path / "out")])
        assert result.exit_code == 0
        assert "Mobile Sentinel" in result.output
        assert "Scan completed." in result.output
        assert "Report:" in result.output
        assert "Traceback" not in result.output

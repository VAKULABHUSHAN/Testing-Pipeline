"""Unit tests for Report generation (Text and JSON)."""

import json
from pathlib import Path
from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding, RiskScoreSummary, ScanMetadata, TestScenarioResult
from sentinel.orchestrator.pipeline import ScanExecutionResult
from sentinel.reporting.json_report import JsonReportGenerator
from sentinel.reporting.text_report import TextReportGenerator


def test_text_report_generation(tmp_path: Path) -> None:
    res = ScanExecutionResult(
        scan_id="MS-20260911-001",
        metadata=ScanMetadata(
            scan_id="MS-20260911-001",
            app_path="D:/Aurum/app.apk",
            app_hash_sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            app_name="Aurum",
            package_name="com.example.aurum",
            target_sdk=36,
        ),
        apk_meta=None,
        device_name="emulator-5554",
        findings=[
            Finding(
                id="PERF_MAIN_THREAD_JANK",
                title="Startup main-thread jank",
                category=FindingCategory.PERFORMANCE,
                severity=Severity.HIGH,
                confidence=0.95,
                description="Application skipped 356 frames during startup.",
                impact="Application may appear frozen.",
                recommendation="Move expensive startup work away from main thread.",
                evidence={"max_skipped_frames": 356},
            )
        ],
        risk_summary=RiskScoreSummary(
            overall_score=85.0,
            security_score=90.0,
            stability_score=95.0,
            performance_score=70.0,
            risk_level="MEDIUM",
            high_count=1,
        ),
        test_results=[
            TestScenarioResult(test_id="01", name="Fresh Launch", status="PASS", details="OK"),
            TestScenarioResult(test_id="02", name="Startup Stability", status="PASS", details="OK"),
        ],
        runtime_summary={"Launch": "PASS", "Crash": "PASS"},
        duration_seconds=12.5,
    )

    txt_file = tmp_path / "report.txt"
    gen = TextReportGenerator()
    content = gen.generate(res, txt_file)

    assert "MOBILE SENTINEL SECURITY & QA AUDIT" in content
    assert "Scan ID: MS-20260911-001" in content
    assert "Application: Aurum" in content
    assert "Package: com.example.aurum" in content
    assert "Overall Risk: MEDIUM" in content
    assert "Startup main-thread jank" in content
    assert "FINAL VERDICT" in content


def test_json_report_generation(tmp_path: Path) -> None:
    res = ScanExecutionResult(
        scan_id="MS-20260911-001",
        metadata=ScanMetadata(
            scan_id="MS-20260911-001",
            app_path="D:/Aurum/app.apk",
            app_hash_sha256="abcdef",
        ),
        apk_meta=None,
        device_name="emulator-5554",
    )

    json_file = tmp_path / "report.json"
    gen = JsonReportGenerator()
    content = gen.generate(res, json_file)

    data = json.loads(content)
    assert data["scan_id"] == "MS-20260911-001"
    assert "metadata" in data
    assert "findings" in data

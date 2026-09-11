"""Unit tests for Manifest and permission analyzer."""

from sentinel.analyzers.android.manifest import ManifestAnalyzer
from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import ScanMetadata


def test_manifest_analyzer_permissions_and_exported() -> None:
    meta = APKMetadata(
        file_path="dummy.apk",
        file_size_bytes=1000,
        file_size_mb=0.01,
        sha256="abcdef123456",
        package_name="com.example.test",
        version_name="1.0.0",
        version_code=1,
        min_sdk=24,
        target_sdk=30,  # Below modern 34
        app_label="Test App",
        launcher_activity="com.example.test.MainActivity",
        permissions=[
            "android.permission.INTERNET",
            "android.permission.CAMERA",  # Dangerous
            "android.permission.SYSTEM_ALERT_WINDOW",  # Special
        ],
        exported_components=[
            {"type": "activity", "name": "com.example.test.MainActivity"},
            {"type": "service", "name": "com.example.test.UnprotectedService", "permission": None},
            {"type": "receiver", "name": "com.example.test.ProtectedReceiver", "permission": "android.permission.DUMP"},
        ],
    )

    scan_meta = ScanMetadata(
        scan_id="MS-TEST-001",
        app_path="dummy.apk",
        app_hash_sha256="abcdef123456",
    )

    analyzer = ManifestAnalyzer()
    findings = analyzer.analyze(meta, scan_meta)

    # Verify target SDK finding
    sdk_findings = [f for f in findings if f.id == "ANDROID_OUTDATED_TARGET_SDK"]
    assert len(sdk_findings) == 1

    # Verify dangerous permission
    cam_findings = [f for f in findings if f.id == "ANDROID_DANGEROUS_PERMISSION"]
    assert len(cam_findings) == 1
    assert "CAMERA" in cam_findings[0].title

    # Verify special permission
    special_findings = [f for f in findings if f.id == "ANDROID_SPECIAL_PERMISSION"]
    assert len(special_findings) == 1

    # Verify unprotected exported component
    unprot_findings = [f for f in findings if f.id == "ANDROID_EXPORTED_COMPONENT"]
    assert len(unprot_findings) == 1
    assert "UnprotectedService" in unprot_findings[0].title

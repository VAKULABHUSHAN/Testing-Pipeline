"""Unit tests for core models, enums, configuration, and logging."""

import json
from sentinel.core.enums import FindingCategory, Severity, FindingCertainty
from sentinel.core.models import Finding, ScanMetadata, RiskScoreSummary
from sentinel.core.config import SentinelConfig
from sentinel.core.logging import RedactingFormatter


def test_finding_creation_and_fingerprint() -> None:
    finding1 = Finding(
        id="ANDROID_EXPORTED_ACTIVITY",
        title="Exported Activity without permission",
        category=FindingCategory.ATTACK_SURFACE,
        severity=Severity.HIGH,
        confidence=0.95,
        description="Activity is exported to external apps",
        impact="Unauthorized component invocation",
        recommendation="Set android:exported=false or apply permission",
        evidence={"activity": "com.example.MainActivity", "exported": True},
        source="android_manifest",
        location="AndroidManifest.xml:42",
    )

    assert finding1.fingerprint != ""
    assert finding1.category == FindingCategory.ATTACK_SURFACE
    assert finding1.severity == Severity.HIGH

    # Same data must yield deterministic fingerprint
    finding2 = Finding(
        id="ANDROID_EXPORTED_ACTIVITY",
        title="Exported Activity without permission",
        category=FindingCategory.ATTACK_SURFACE,
        severity=Severity.HIGH,
        confidence=0.95,
        description="Activity is exported to external apps",
        impact="Unauthorized component invocation",
        recommendation="Set android:exported=false or apply permission",
        evidence={"activity": "com.example.MainActivity", "exported": True},
        source="android_manifest",
        location="AndroidManifest.xml:42",
    )
    assert finding1.fingerprint == finding2.fingerprint


def test_finding_serialization_roundtrip() -> None:
    f = Finding(
        id="SECRETS_AWS_KEY",
        title="Hardcoded AWS Access Key",
        category=FindingCategory.SECRETS,
        severity=Severity.CRITICAL,
        confidence=1.0,
        description="AWS access key exposed in strings",
        impact="Cloud compromise",
        recommendation="Revoke and rotate key immediately",
        evidence={"key_id": "AKIA***"},
        source="secret_scanner",
    )
    d = f.to_dict()
    assert d["severity"] == "CRITICAL"
    assert d["category"] == "SECRETS"

    # Ensure JSON serializable
    json_str = json.dumps(d)
    parsed = json.loads(json_str)
    reconstructed = Finding.from_dict(parsed)
    assert reconstructed.id == f.id
    assert reconstructed.severity == Severity.CRITICAL
    assert reconstructed.category == FindingCategory.SECRETS


def test_sentinel_config_defaults() -> None:
    cfg = SentinelConfig.default()
    assert cfg.scan.static is True
    assert cfg.scan.runtime is False
    assert cfg.safety.destructive_actions is False
    assert cfg.report.html is True
    assert cfg.report.json is True


def test_log_secret_redaction() -> None:
    text_with_secret = "Failed authentication token: bearer=ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    redacted = RedactingFormatter.redact(text_with_secret)
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "bearer=" in redacted

    text_aws = "Detected key AKIAIOSFODNN7EXAMPLE in config"
    redacted_aws = RedactingFormatter.redact(text_aws)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted_aws

"""Unit tests for secret scanning and redaction."""

from sentinel.analyzers.secrets.scanner import SecretScanner
from sentinel.core.enums import Severity


def test_secret_scanner_regex_matches_and_redaction() -> None:
    scanner = SecretScanner()
    text = (
        "Here is an AWS key AKIAIOSFODNN7EXAMPLE for tests.\n"
        "And a google key AIzaSyD_87g_fakeGoogleKeyTest1234567abcd.\n"
        "And a DB connection: postgres://admin:superSecretPassword123@db.prod.internal:5432/app"
    )

    findings = scanner._scan_text(text, "test_file.dex")

    # AWS
    aws_findings = [f for f in findings if f.id == "SECRETS_AWS_ACCESS_KEY"]
    assert len(aws_findings) == 1
    assert aws_findings[0].severity == Severity.CRITICAL
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_findings[0].evidence["matched"]
    assert aws_findings[0].evidence["matched"] == "AKIAIO...PLE"

    # Google API Key
    google_findings = [f for f in findings if f.id == "SECRETS_GOOGLE_API_KEY"]
    assert len(google_findings) == 1
    assert "AIzaSy" in google_findings[0].evidence["matched"]
    assert "..." in google_findings[0].evidence["matched"]

    # Database
    db_findings = [f for f in findings if f.id == "SECRETS_DATABASE_URL"]
    assert len(db_findings) == 1
    assert db_findings[0].severity == Severity.HIGH


def test_shannon_entropy() -> None:
    scanner = SecretScanner()
    assert scanner._shannon_entropy("aaaaaaa") == 0.0
    # High entropy random string
    assert scanner._shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > 3.5

"""Automated secret, API key, and credential scanner."""

from __future__ import annotations

import math
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.analyzers.base import BaseAnalyzer
from sentinel.core.enums import FindingCategory, FindingCertainty, Severity
from sentinel.core.models import Finding, ScanMetadata

SECRET_PATTERNS = [
    (
        "SECRETS_GOOGLE_API_KEY",
        "Google Cloud / Maps API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        Severity.MEDIUM,
        "Google API key found embedded in application resources or binaries.",
    ),
    (
        "SECRETS_AWS_ACCESS_KEY",
        "AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "AWS Access Key ID exposed in APK.",
    ),
    (
        "SECRETS_GITHUB_TOKEN",
        "GitHub Personal Access Token",
        re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
        Severity.CRITICAL,
        "GitHub personal access token detected in APK.",
    ),
    (
        "SECRETS_FIREBASE_DB",
        "Firebase Realtime Database URL",
        re.compile(r"https://[a-zA-Z0-9\-]+\.firebaseio\.com"),
        Severity.LOW,
        "Firebase Realtime Database endpoint discovered.",
    ),
    (
        "SECRETS_PRIVATE_KEY",
        "Embedded Private Key Block",
        re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PRIVATE)\s+KEY-----"),
        Severity.CRITICAL,
        "Cryptographic private key header detected inside package.",
    ),
    (
        "SECRETS_DATABASE_URL",
        "Database Connection String with Credentials",
        re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_\-\.]+"),
        Severity.HIGH,
        "Database connection URI containing hardcoded credentials.",
    ),
]


class SecretScanner(BaseAnalyzer):
    """Scans APK package contents for sensitive keys, credentials, and tokens."""

    @property
    def name(self) -> str:
        return "secret_scanner"

    @property
    def description(self) -> str:
        return "Detects embedded API keys, credentials, and sensitive tokens with entropy analysis"

    def analyze(self, target: Any, metadata: ScanMetadata) -> List[Finding]:
        if not isinstance(target, APKMetadata):
            return []

        findings: List[Finding] = []
        apk_path = Path(target.file_path)

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for entry in zf.namelist():
                    # Scan relevant file extensions
                    if (
                        entry.endswith(".dex")
                        or entry.endswith(".xml")
                        or entry.endswith(".json")
                        or entry.endswith(".properties")
                        or entry.startswith("assets/")
                        or entry.endswith(".so")
                    ):
                        try:
                            # Read up to 2MB per file to maintain safety and responsiveness
                            data = zf.read(entry)[: 2 * 1024 * 1024]
                            text = data.decode("utf-8", errors="ignore")
                            file_findings = self._scan_text(text, entry)
                            findings.extend(file_findings)
                        except Exception:
                            continue
        except Exception:
            pass

        # Deduplicate findings by fingerprint
        unique_findings: List[Finding] = []
        seen_fingerprints: Set[str] = set()
        for f in findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                unique_findings.append(f)

        return unique_findings

    def _scan_text(self, text: str, file_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule_id, title, pattern, severity, desc in SECRET_PATTERNS:
            matches = pattern.finditer(text)
            for m in matches:
                secret_raw = m.group(0)
                # Redact secret for evidence
                redacted = self._redact(secret_raw)
                entropy = self._shannon_entropy(secret_raw)

                findings.append(
                    Finding(
                        id=rule_id,
                        title=title,
                        category=FindingCategory.SECRETS,
                        severity=severity,
                        confidence=0.92 if entropy > 3.0 else 0.75,
                        description=desc,
                        impact="Hardcoded credentials in client applications can be extracted and abused by attackers.",
                        recommendation="Store sensitive secrets on a backend server or use secret management vaults. Rotate exposed keys.",
                        evidence={
                            "matched": redacted,
                            "location": file_path,
                            "entropy": round(entropy, 2),
                        },
                        source=self.name,
                        location=file_path,
                        certainty=FindingCertainty.POTENTIAL if severity != Severity.CRITICAL else FindingCertainty.CONFIRMED,
                    )
                )

        return findings

    @staticmethod
    def _redact(secret: str) -> str:
        """Redacts secret to prevent report exposure, e.g. AIzaSy...9X2."""
        if len(secret) <= 8:
            return "***"
        prefix = secret[:6]
        suffix = secret[-3:]
        return f"{prefix}...{suffix}"

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

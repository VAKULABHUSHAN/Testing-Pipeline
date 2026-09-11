"""Network configuration and endpoint analyzer."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set

from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.analyzers.base import BaseAnalyzer
from sentinel.core.enums import FindingCategory, FindingCertainty, Severity
from sentinel.core.models import Finding, ScanMetadata

# Match common URLs
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]{5,120}")


class NetworkAnalyzer(BaseAnalyzer):
    """Inspects APK for network configuration, cleartext endpoints, and backend URLs."""

    @property
    def name(self) -> str:
        return "network_analyzer"

    @property
    def description(self) -> str:
        return "Discovers embedded network endpoints, HTTP usage, and development hosts"

    def analyze(self, target: Any, metadata: ScanMetadata) -> List[Finding]:
        if not isinstance(target, APKMetadata):
            return []

        findings: List[Finding] = []
        apk_path = Path(target.file_path)

        discovered_urls: Set[str] = set()
        http_insecure_urls: Set[str] = set()
        localhost_urls: Set[str] = set()

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for entry in zf.namelist():
                    if entry.endswith(".dex") or entry.endswith(".xml") or entry.startswith("assets/"):
                        try:
                            content = zf.read(entry)[: 1024 * 1024].decode("utf-8", errors="ignore")
                            for match in URL_PATTERN.finditer(content):
                                url = match.group(0).rstrip(").,'\";")
                                # Skip schema and android system urls
                                if "schemas.android.com" in url or "w3.org" in url or "apache.org" in url:
                                    continue
                                discovered_urls.add(url)
                                if url.startswith("http://"):
                                    http_insecure_urls.add(url)
                                if "localhost" in url or "127.0.0.1" in url or "10.0.2.2" in url:
                                    localhost_urls.add(url)
                        except Exception:
                            continue
        except Exception:
            pass

        # Insecure HTTP endpoints finding
        if http_insecure_urls:
            sample_urls = list(http_insecure_urls)[:5]
            findings.append(
                Finding(
                    id="NETWORK_CLEARTEXT_HTTP_ENDPOINTS",
                    title="Insecure Cleartext HTTP URLs Discovered in Binary",
                    category=FindingCategory.NETWORK,
                    severity=Severity.MEDIUM,
                    confidence=0.88,
                    description=f"Found {len(http_insecure_urls)} plain unencrypted HTTP endpoint(s) embedded in package.",
                    impact="Cleartext network traffic is subject to eavesdropping and man-in-the-middle (MitM) manipulation.",
                    recommendation="Enforce HTTPS for all backend endpoints and configure network security config to prohibit cleartext traffic.",
                    evidence={"count": len(http_insecure_urls), "samples": sample_urls},
                    source=self.name,
                    location="Embedded strings",
                    certainty=FindingCertainty.POTENTIAL,
                )
            )

        # Localhost / staging references
        if localhost_urls:
            findings.append(
                Finding(
                    id="NETWORK_DEVELOPMENT_ENDPOINTS",
                    title="Development / Loopback Hostnames Detected",
                    category=FindingCategory.CONFIGURATION,
                    severity=Severity.LOW,
                    confidence=0.90,
                    description=f"Identified references to local development addresses ({', '.join(list(localhost_urls)[:3])}).",
                    impact="Development endpoints may expose debugging APIs or fail when deployed in production.",
                    recommendation="Verify that local host endpoints are disabled in release configuration.",
                    evidence={"endpoints": list(localhost_urls)[:5]},
                    source=self.name,
                    location="Embedded strings",
                    certainty=FindingCertainty.OBSERVATION,
                )
            )

        return findings

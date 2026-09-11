"""Flutter framework and asset detector."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.analyzers.base import BaseAnalyzer
from sentinel.core.enums import FindingCategory, FindingCertainty, Severity
from sentinel.core.models import Finding, ScanMetadata


class FlutterAnalyzer(BaseAnalyzer):
    """Inspects APK for Flutter runtime indicators, assets, and build modes."""

    @property
    def name(self) -> str:
        return "flutter_detector"

    @property
    def description(self) -> str:
        return "Detects Flutter engine, compilation mode, and packaged asset manifest"

    def analyze(self, target: Any, metadata: ScanMetadata) -> List[Finding]:
        if not isinstance(target, APKMetadata):
            return []

        findings: List[Finding] = []
        apk_path = Path(target.file_path)

        has_libflutter = False
        has_libapp = False
        has_kernel_blob = False
        asset_count = 0
        asset_manifest_found = False

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                names = zf.namelist()
                for name in names:
                    if "libflutter.so" in name:
                        has_libflutter = True
                    if "libapp.so" in name:
                        has_libapp = True
                    if "kernel_blob.bin" in name:
                        has_kernel_blob = True
                    if name.startswith("assets/flutter_assets/"):
                        asset_count += 1
                        if "AssetManifest" in name:
                            asset_manifest_found = True
        except Exception:
            pass

        is_flutter = has_libflutter or target.is_flutter or (asset_count > 0)
        metadata.is_flutter = is_flutter

        if is_flutter:
            build_mode = "AOT Release" if has_libapp and not has_kernel_blob else "Debug / JIT" if has_kernel_blob else "Unknown"

            findings.append(
                Finding(
                    id="FLUTTER_FRAMEWORK_DETECTED",
                    title="Flutter Application Runtime Detected",
                    category=FindingCategory.FLUTTER,
                    severity=Severity.INFO,
                    confidence=1.0,
                    description=f"APK was built using Google Flutter framework (Build Mode: {build_mode}).",
                    impact="Application utilizes Dart VM and Flutter rendering engine.",
                    recommendation="Ensure code obfuscation (--obfuscate --split-debug-info) is enabled for production builds.",
                    evidence={
                        "build_mode": build_mode,
                        "has_libflutter": has_libflutter,
                        "has_libapp": has_libapp,
                        "asset_count": asset_count,
                    },
                    source=self.name,
                    location="lib/ and assets/flutter_assets/",
                    certainty=FindingCertainty.CONFIRMED,
                )
            )

            if has_kernel_blob:
                findings.append(
                    Finding(
                        id="FLUTTER_DEBUG_BUILD",
                        title="Flutter Debug Kernel Blob Present in Package",
                        category=FindingCategory.CONFIGURATION,
                        severity=Severity.MEDIUM,
                        confidence=0.95,
                        description="Application contains uncompiled Dart kernel bytecode (kernel_blob.bin) characteristic of debug builds.",
                        impact="Debug builds include debugging symbols and developer capabilities unsuitable for production release.",
                        recommendation="Build release APK using 'flutter build apk --release'.",
                        evidence={"artifact": "kernel_blob.bin"},
                        source=self.name,
                        location="assets/flutter_assets/kernel_blob.bin",
                        certainty=FindingCertainty.CONFIRMED,
                    )
                )

        return findings

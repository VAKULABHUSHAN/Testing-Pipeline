"""Android manifest and permission analyzer."""

from __future__ import annotations

from typing import Any, Dict, List

from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.analyzers.base import BaseAnalyzer
from sentinel.core.enums import FindingCategory, FindingCertainty, PermissionClassification, Severity
from sentinel.core.models import Finding, ScanMetadata

# Well-known Android permissions classification
DANGEROUS_PERMISSIONS = {
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.BODY_SENSORS",
    "android.permission.POST_NOTIFICATIONS",
}

SPECIAL_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
}


class ManifestAnalyzer(BaseAnalyzer):
    """Analyzes AndroidManifest components, permissions, and security posture."""

    @property
    def name(self) -> str:
        return "android_manifest"

    @property
    def description(self) -> str:
        return "Evaluates manifest flags, exported components, and permissions"

    def analyze(self, target: Any, metadata: ScanMetadata) -> List[Finding]:
        if not isinstance(target, APKMetadata):
            return []

        findings: List[Finding] = []
        apk_meta: APKMetadata = target

        # 1. Analyze Permissions
        findings.extend(self._analyze_permissions(apk_meta))

        # 2. Analyze Exported Components
        findings.extend(self._analyze_exported_components(apk_meta))

        # 3. Analyze Target SDK
        if apk_meta.target_sdk and apk_meta.target_sdk < 34:
            findings.append(
                Finding(
                    id="ANDROID_OUTDATED_TARGET_SDK",
                    title="Target SDK is below current Google Play requirement",
                    category=FindingCategory.CONFIGURATION,
                    severity=Severity.LOW,
                    confidence=0.95,
                    description=f"Application targets Android SDK {apk_meta.target_sdk}, which is older than modern security baseline (SDK 34+).",
                    impact="Application might not benefit from latest platform security mitigations and privacy protections.",
                    recommendation="Update compileSdkVersion and targetSdkVersion in build.gradle to 34 or higher.",
                    evidence={"targetSdkVersion": apk_meta.target_sdk},
                    source=self.name,
                    location="AndroidManifest.xml:targetSdkVersion",
                    certainty=FindingCertainty.CONFIRMED,
                )
            )

        return findings

    def _analyze_permissions(self, apk_meta: APKMetadata) -> List[Finding]:
        findings: List[Finding] = []
        dangerous_found = []
        special_found = []

        for perm in apk_meta.permissions:
            clean_perm = perm.strip()
            if clean_perm in DANGEROUS_PERMISSIONS:
                dangerous_found.append(clean_perm)
            elif clean_perm in SPECIAL_PERMISSIONS:
                special_found.append(clean_perm)

        # Report dangerous permissions contextually
        for perm in dangerous_found:
            findings.append(
                Finding(
                    id="ANDROID_DANGEROUS_PERMISSION",
                    title=f"Dangerous Permission Requested: {perm.split('.')[-1]}",
                    category=FindingCategory.SECURITY,
                    severity=Severity.LOW,
                    confidence=0.90,
                    description=f"The application requests the runtime-permission '{perm}'.",
                    impact="Grants application access to sensitive user data or device capabilities when approved by user.",
                    recommendation="Ensure this permission is strictly necessary for core functionality and gracefully handled at runtime.",
                    evidence={"permission": perm, "classification": PermissionClassification.DANGEROUS.value},
                    source=self.name,
                    location="AndroidManifest.xml:uses-permission",
                    certainty=FindingCertainty.OBSERVATION,
                )
            )

        # Report special permissions
        for perm in special_found:
            findings.append(
                Finding(
                    id="ANDROID_SPECIAL_PERMISSION",
                    title=f"Special/Privileged Permission: {perm.split('.')[-1]}",
                    category=FindingCategory.SECURITY,
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    description=f"The application requests elevated system permission '{perm}'.",
                    impact="Special permissions provide powerful system capabilities that could broaden attack surface.",
                    recommendation="Review if alternative APIs can achieve the desired feature without special permissions.",
                    evidence={"permission": perm, "classification": PermissionClassification.SPECIAL.value},
                    source=self.name,
                    location="AndroidManifest.xml:uses-permission",
                    certainty=FindingCertainty.POTENTIAL,
                )
            )

        return findings

    def _analyze_exported_components(self, apk_meta: APKMetadata) -> List[Finding]:
        findings: List[Finding] = []

        for comp in apk_meta.exported_components:
            comp_name = comp.get("name", "unknown")
            comp_type = comp.get("type", "component")
            permission = comp.get("permission")
            has_filter = comp.get("has_filter", False)

            # Skip launcher activity (it is expected to be exported so system launcher can start it)
            if comp_name == apk_meta.launcher_activity or "MainActivity" in comp_name:
                findings.append(
                    Finding(
                        id="ANDROID_LAUNCHER_EXPORTED",
                        title=f"Main Launcher Activity Exported: {comp_name.split('.')[-1]}",
                        category=FindingCategory.ATTACK_SURFACE,
                        severity=Severity.INFO,
                        confidence=1.0,
                        description=f"Main entry activity '{comp_name}' is exported to allow launching from Android home.",
                        impact="Normal expected behavior for primary application launcher.",
                        recommendation="Ensure input intent parameters are sanitized upon launch.",
                        evidence={"component": comp_name, "type": comp_type},
                        source=self.name,
                        location="AndroidManifest.xml",
                        certainty=FindingCertainty.OBSERVATION,
                    )
                )
                continue

            # Check if protected by signature/system permission
            is_protected = permission in (
                "android.permission.BIND_JOB_SERVICE",
                "android.permission.BIND_REMOTEVIEWS",
                "android.permission.DUMP",
            ) or (permission and "signature" in permission.lower())

            if is_protected:
                findings.append(
                    Finding(
                        id="ANDROID_PROTECTED_EXPORTED_COMPONENT",
                        title=f"Exported {comp_type.capitalize()} Protected by Permission: {comp_name.split('.')[-1]}",
                        category=FindingCategory.ATTACK_SURFACE,
                        severity=Severity.INFO,
                        confidence=0.90,
                        description=f"{comp_type.capitalize()} '{comp_name}' is exported but guarded by permission '{permission}'.",
                        impact="Only callers possessing the required permission can invoke this component.",
                        recommendation="Verify that the protecting permission has appropriate protectionLevel.",
                        evidence={"component": comp_name, "type": comp_type, "permission": permission},
                        source=self.name,
                        location="AndroidManifest.xml",
                        certainty=FindingCertainty.OBSERVATION,
                    )
                )
            else:
                findings.append(
                    Finding(
                        id="ANDROID_EXPORTED_COMPONENT",
                        title=f"Unprotected Exported {comp_type.capitalize()}: {comp_name.split('.')[-1]}",
                        category=FindingCategory.ATTACK_SURFACE,
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        description=f"Exported {comp_type} '{comp_name}' does not require any permission for external invocation.",
                        impact="Third-party apps installed on the device may directly invoke this component.",
                        recommendation="Set android:exported='false' if this component is internal, or protect with a signature permission.",
                        evidence={"component": comp_name, "type": comp_type, "permission": None, "has_filter": has_filter},
                        source=self.name,
                        location="AndroidManifest.xml",
                        certainty=FindingCertainty.POTENTIAL,
                    )
                )

        return findings

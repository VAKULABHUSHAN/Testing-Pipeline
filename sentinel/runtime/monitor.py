"""Runtime logcat analysis, crash detection, and performance monitoring."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from sentinel.core.enums import FindingCategory, FindingCertainty, Severity
from sentinel.core.models import Finding

# Patterns for genuine crashes and exceptions
CRASH_PATTERNS = [
    re.compile(r"FATAL EXCEPTION:\s*(.*)"),
    re.compile(r"AndroidRuntime:\s*FATAL EXCEPTION"),
    re.compile(r"signal\s+\d+\s+\(SIG[A-Z0-9]+\)"),
    re.compile(r"\bbacktrace:\s*#00"),
]

ANR_PATTERNS = [
    re.compile(r"ANR in\s+([a-zA-Z0-9_\.]+)"),
    re.compile(r"Input dispatching timed out"),
]

FLUTTER_ERROR_PATTERNS = [
    re.compile(r"Unhandled Exception:\s*(.*)"),
    re.compile(r"════════ Exception caught by"),
    re.compile(r"FlutterError:\s*(.*)"),
    re.compile(r"Dart Error:\s*(.*)"),
]

SKIPPED_FRAMES_PATTERN = re.compile(
    r"Skipped\s+(\d+)\s+frames!\s+The application may be doing too much work on its main thread\."
)

# System and environment messages that should NOT trigger findings
SYSTEM_NOISE_PATTERNS = [
    re.compile(r"(?i)unexpected cpu variant"),
    re.compile(r"(?i)ashmem .* deprecated"),
    re.compile(r"(?i)hwui"),
    re.compile(r"(?i)angle.*configuration"),
    re.compile(r"(?i)selinux.*max_map_count"),
    re.compile(r"(?i)userfaultfd"),
    re.compile(r"(?i)gralloc"),
    re.compile(r"(?i)OpenGLRenderer"),
]


@dataclass
class RuntimeAnalysisResult:
    """Summary of runtime observations."""
    has_crash: bool = False
    has_anr: bool = False
    crash_details: List[str] = field(default_factory=list)
    anr_details: List[str] = field(default_factory=list)
    flutter_errors: List[str] = field(default_factory=list)
    skipped_frames_max: int = 0
    total_skipped_frames: int = 0
    findings: List[Finding] = field(default_factory=list)


class RuntimeMonitor:
    """Parses runtime logcat streams for crashes, stability issues, and performance."""

    def __init__(self, package_name: str):
        self.package_name = package_name

    def analyze_logcat(self, logcat_text: str) -> RuntimeAnalysisResult:
        result = RuntimeAnalysisResult()
        if not logcat_text:
            return result

        lines = logcat_text.splitlines()
        filtered_lines: List[str] = []

        # Filter out system noise
        for line in lines:
            if any(noise.search(line) for noise in SYSTEM_NOISE_PATTERNS):
                continue
            filtered_lines.append(line)

        # 1. Skipped Frames (Performance)
        skipped_frames_found: List[int] = []
        for line in filtered_lines:
            m = SKIPPED_FRAMES_PATTERN.search(line)
            if m:
                frames = int(m.group(1))
                skipped_frames_found.append(frames)

        if skipped_frames_found:
            max_skipped = max(skipped_frames_found)
            result.skipped_frames_max = max_skipped
            result.total_skipped_frames = sum(skipped_frames_found)

            # Assign severity based on guidelines
            if max_skipped > 300:
                sev = Severity.HIGH
            elif max_skipped >= 180:
                sev = Severity.MEDIUM
            elif max_skipped >= 60:
                sev = Severity.LOW
            else:
                sev = Severity.INFO

            result.findings.append(
                Finding(
                    id="PERF_MAIN_THREAD_JANK",
                    title="Startup main-thread jank (Skipped frames)",
                    category=FindingCategory.PERFORMANCE,
                    severity=sev,
                    confidence=0.95,
                    description=f"UI thread jank detected: application skipped up to {max_skipped} frames during execution.",
                    impact="Application may appear frozen or unresponsive to touches during startup or transitions.",
                    recommendation="Move expensive startup work away from the UI/main thread and profile initialization tasks.",
                    evidence={
                        "max_skipped_frames": max_skipped,
                        "occurrences": len(skipped_frames_found),
                        "total_frames_skipped": result.total_skipped_frames,
                    },
                    source="logcat_monitor",
                    location="MainThread",
                    certainty=FindingCertainty.CONFIRMED,
                )
            )

        # 2. Crash Detection
        crash_blocks: List[str] = []
        for i, line in enumerate(filtered_lines):
            if any(p.search(line) for p in CRASH_PATTERNS):
                # Capture surrounding 5 lines for context
                context_start = max(0, i - 2)
                context_end = min(len(filtered_lines), i + 6)
                snippet = "\n".join(filtered_lines[context_start:context_end])
                crash_blocks.append(snippet)

        if crash_blocks:
            result.has_crash = True
            result.crash_details = crash_blocks[:3]
            result.findings.append(
                Finding(
                    id="RUNTIME_APP_CRASH",
                    title="Fatal Application Crash Observed",
                    category=FindingCategory.RUNTIME,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    description=f"Fatal exception or native crash detected in process logs ({len(crash_blocks)} occurrence(s)).",
                    impact="Process terminated unexpectedly, causing abrupt termination of user session.",
                    recommendation="Inspect crash stack trace in evidence logs and resolve the unhandled exception.",
                    evidence={"occurrences": len(crash_blocks), "snippet": crash_blocks[0][:300]},
                    source="logcat_monitor",
                    location="AndroidRuntime",
                    certainty=FindingCertainty.CONFIRMED,
                )
            )

        # 3. ANR Detection
        for line in filtered_lines:
            if any(p.search(line) for p in ANR_PATTERNS):
                if self.package_name in line or "Input dispatching" in line:
                    result.has_anr = True
                    result.anr_details.append(line.strip())

        if result.has_anr:
            result.findings.append(
                Finding(
                    id="RUNTIME_ANR_DETECTED",
                    title="Application Not Responding (ANR) Detected",
                    category=FindingCategory.RUNTIME,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    description="The Android system reported an Application Not Responding condition.",
                    impact="System displays 'App isn't responding' dialog, forcing user to wait or kill the app.",
                    recommendation="Ensure long-running operations (I/O, database, network) are executed off the main thread.",
                    evidence={"anr_lines": result.anr_details[:2]},
                    source="logcat_monitor",
                    location="InputDispatcher",
                    certainty=FindingCertainty.CONFIRMED,
                )
            )

        # 4. Flutter / Dart Uncaught Exceptions
        for line in filtered_lines:
            if any(p.search(line) for p in FLUTTER_ERROR_PATTERNS):
                result.flutter_errors.append(line.strip())

        if result.flutter_errors and not result.has_crash:
            result.findings.append(
                Finding(
                    id="FLUTTER_UNHANDLED_EXCEPTION",
                    title="Unhandled Flutter/Dart Exception in UI Pipeline",
                    category=FindingCategory.FLUTTER,
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    description=f"Observed {len(result.flutter_errors)} unhandled Flutter error(s) in log output.",
                    impact="May lead to grey error screen (red/grey screen of death in debug) or broken widget states.",
                    recommendation="Wrap asynchronous calls and widget builders in appropriate error handlers (FlutterError.onError).",
                    evidence={"errors": result.flutter_errors[:3]},
                    source="logcat_monitor",
                    location="FlutterFramework",
                    certainty=FindingCertainty.CONFIRMED,
                )
            )

        return result

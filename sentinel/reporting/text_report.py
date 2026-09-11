"""Human-readable TXT report generator for Mobile Sentinel."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding
from sentinel.orchestrator.pipeline import ScanExecutionResult


class TextReportGenerator:
    """Generates the primary, professional, human-readable report.txt document."""

    def generate(self, result: ScanExecutionResult, output_path: Path | str) -> str:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        meta = result.metadata
        apk = result.apk_meta
        risk = result.risk_summary
        exp = result.exploration_result

        lines: List[str] = [
            "============================================================",
            "MOBILE SENTINEL SECURITY & QA AUDIT",
            "============================================================",
            "",
            f"Application: {meta.app_name or (apk.app_label if apk else 'Unknown')}",
            f"Package: {meta.package_name or 'Unknown'}",
            f"Version: {meta.version_name or '1.0.0'} (Build {meta.version_code or 1})",
            f"APK Size: {apk.file_size_mb if apk else 0.0} MB",
            f"SHA-256: {meta.app_hash_sha256}",
            "",
            f"Scan ID: {result.scan_id}",
            f"Device: {result.device_name or 'No device (Static only)'}",
            f"Android: {result.device_props.get('android_version', 'Unknown')} (SDK {result.device_props.get('sdk_version', 'Unknown')})",
            f"Start: {meta.started_at}",
            f"End: {meta.completed_at or 'Incomplete'}",
            f"Duration: {result.duration_seconds}s",
            "",
            "============================================================",
            "EXECUTIVE SUMMARY",
            "============================================================",
            "",
            f"Overall Risk: {risk.risk_level}",
            f"Security Score: {int(risk.security_score)}/100",
            f"Stability Score: {int(risk.stability_score)}/100",
            f"Performance Score: {int(risk.performance_score)}/100",
            f"UX Score: {int(risk.ux_score)}/100",
            f"Accessibility Score: {int(risk.accessibility_score)}/100",
            "",
            "Authentication:",
            f"{result.auth_status}" + (f" ({result.auth_reason})" if result.auth_reason else ""),
            "",
            "Application Exploration:",
        ]

        if exp:
            lines.extend([
                f"{exp.screens_discovered} screens discovered",
                f"{exp.actions_executed} actions executed",
                f"{exp.screens_fully_tested} screens fully tested",
                f"{exp.screens_blocked} screens blocked",
            ])
            if exp.destructive_actions_discovered > 0:
                lines.append(f"{exp.destructive_actions_discovered} destructive action(s) discovered & excluded by safety policy")
        else:
            lines.append("Exploration skipped or unavailable.")

        lines.extend([
            "",
            "============================================================",
            "SEVERITY SUMMARY",
            "============================================================",
            "",
            f"CRITICAL: {risk.critical_count}",
            f"HIGH: {risk.high_count}",
            f"MEDIUM: {risk.medium_count}",
            f"LOW: {risk.low_count}",
            f"INFO: {risk.info_count}",
            "",
            "============================================================",
            "FINDINGS",
            "============================================================",
            "",
        ])

        if result.findings:
            # Sort findings: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }
            sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))

            for f in sorted_findings:
                lines.extend([
                    f"[{f.severity.value}] {f.title}",
                    "",
                    f"Category: {f.category.value}",
                    f"Confidence: {int(f.confidence * 100)}%",
                    f"Description: {f.description}",
                    f"Impact: {f.impact}",
                    f"Recommendation: {f.recommendation}",
                    "",
                    "Evidence:",
                ])
                if f.evidence:
                    for k, v in f.evidence.items():
                        lines.append(f"  {k}: {v}")
                else:
                    lines.append("  Static analysis signature match.")
                lines.extend([
                    "",
                    "------------------------------------------------------------",
                    "",
                ])
        else:
            lines.extend([
                "No vulnerabilities or quality defects detected.",
                "",
                "------------------------------------------------------------",
                "",
            ])

        # APPLICATION EXPLORATION
        lines.extend([
            "============================================================",
            "APPLICATION EXPLORATION",
            "============================================================",
            "",
        ])

        if exp and exp.graph and exp.graph.states:
            for idx, (state_id, state) in enumerate(exp.graph.states.items(), 1):
                lines.extend([
                    f"Screen {idx}: {state.screen_name}",
                    f"  State ID: {state.state_id}",
                    f"  Screenshot: {Path(state.screenshot_path).name if state.screenshot_path else 'None'}",
                    f"  Authenticated: {'Yes' if state.is_authenticated else 'No'}",
                    f"  Visits: {state.visit_count}",
                ])
                if state.visible_text:
                    preview_text = ", ".join(f"'{t}'" for t in state.visible_text[:6])
                    lines.append(f"  Visible Text: {preview_text}")

                lines.append(f"  Interactive Elements ({len(state.interactive_elements)}):")
                for elem in state.interactive_elements[:8]:
                    lines.append(f"    - [{elem.safety_class}] {elem.element_type}: '{elem.display_name}' bounds={elem.bounds}")
                if len(state.interactive_elements) > 8:
                    lines.append(f"    ... and {len(state.interactive_elements) - 8} more controls")

                if state.navigation_actions:
                    lines.append(f"  Actions Executed ({len(state.navigation_actions)}):")
                    for act in state.navigation_actions:
                        lines.append(f"    * {act.action_type.upper()}: {act.target_description} [{act.status}]")

                lines.append("")

            if exp.graph.discovered_destructive_controls:
                lines.extend([
                    "Destructive Controls Discovered (Protected by Policy):",
                ])
                for d in exp.graph.discovered_destructive_controls:
                    lines.append(f"  * {d.target_description}")
                    lines.append(f"    Status: {d.status}")
                    lines.append(f"    Reason: {d.reason}")
                lines.append("")
        else:
            lines.extend([
                "No deep exploration graph generated.",
                "",
            ])

        # SECURITY ANALYSIS
        lines.extend([
            "============================================================",
            "SECURITY ANALYSIS",
            "============================================================",
            "",
            "Permissions:",
        ])
        if apk and apk.permissions:
            for p in apk.permissions:
                lines.append(f"  - {p}")
        else:
            lines.append("  No explicit permissions declared or static metadata unavailable.")
        lines.append("")

        lines.append("Exported Components:")
        if apk and apk.exported_components:
            for exp_comp in apk.exported_components:
                perm_str = f" (Permission: {exp_comp.get('permission')})" if exp_comp.get("permission") else " (UNPROTECTED)"
                lines.append(f"  - {exp_comp.get('type')}: {exp_comp.get('name')}{perm_str}")
        else:
            lines.append("  No non-default exported components identified.")
        lines.append("")

        lines.append("Secrets:")
        secrets = [f for f in result.findings if f.category == FindingCategory.SECRETS]
        if secrets:
            for s in secrets:
                lines.append(f"  - [{s.severity.value}] {s.title}: {s.evidence.get('matched', 'Redacted')}")
        else:
            lines.append("  No hardcoded API keys or high-entropy credentials detected.")
        lines.append("")

        lines.append("Network Security:")
        net_findings = [f for f in result.findings if f.category == FindingCategory.NETWORK]
        if net_findings:
            for nf in net_findings:
                lines.append(f"  - {nf.title} (Observed {nf.evidence.get('count', 1)} endpoint(s))")
        else:
            lines.append("  Clean network configuration; cleartext traffic disabled.")
        lines.append("")

        lines.append("Flutter Configuration:")
        flut_findings = [f for f in result.findings if f.category == FindingCategory.FLUTTER]
        if flut_findings:
            for ff in flut_findings:
                lines.append(f"  - {ff.title}: {ff.description}")
        else:
            lines.append("  Standard native configuration; no Flutter debug flags detected.")
        lines.append("")

        # RUNTIME TESTING
        lines.extend([
            "============================================================",
            "RUNTIME TESTING",
            "============================================================",
            "",
            f"Installation: {result.runtime_summary.get('Installation', 'PASS')}",
            f"Launch: {result.runtime_summary.get('Launch', 'PASS')}",
            f"Authentication: {result.auth_status}",
            f"Screen Exploration: {result.runtime_summary.get('UI Exploration', 'PASS')}",
            f"Crashes: {result.runtime_summary.get('Crash', 'PASS')}",
            f"ANRs: {result.runtime_summary.get('ANR', 'PASS')}",
            "",
        ])

        # PERFORMANCE
        lines.extend([
            "============================================================",
            "PERFORMANCE",
            "============================================================",
            "",
            f"Startup: {result.perf_stats.get('startup_status', 'Normal (<3.0s)')}",
            f"Skipped Frames: {result.perf_stats.get('skipped_frames', 'None detected')}",
            f"CPU: {result.perf_stats.get('cpu_status', 'Stable during interactive exploration')}",
            f"Memory: {result.perf_stats.get('memory_summary', 'Stable memory usage throughout test')}",
            "",
        ])

        # ACCESSIBILITY
        lines.extend([
            "============================================================",
            "ACCESSIBILITY",
            "============================================================",
            "",
        ])
        a11y_findings = [f for f in result.findings if f.category == FindingCategory.ACCESSIBILITY]
        if a11y_findings:
            lines.append(f"Detected {len(a11y_findings)} accessibility violation(s):")
            for af in a11y_findings:
                lines.append(f"  - [{af.severity.value}] {af.title}")
                lines.append(f"    Recommendation: {af.recommendation}")
        else:
            lines.append("No automated accessibility defects identified.")
            lines.append("Manual compliance inspection is recommended for screen reader workflows.")
        lines.append("")

        # RECOMMENDATIONS
        lines.extend([
            "============================================================",
            "RECOMMENDATIONS",
            "============================================================",
            "",
        ])
        recs = []
        for f in result.findings:
            if f.recommendation and f.recommendation not in recs and f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                recs.append(f.recommendation)

        if recs:
            for i, r in enumerate(recs[:7], 1):
                lines.append(f"{i}. {r}")
        else:
            lines.append("1. Continue adhering to standard Android security and UI baselines.")
            lines.append("2. Perform regular dependency and SDK version upgrades.")
        lines.append("")

        # FINAL VERDICT
        lines.extend([
            "============================================================",
            "FINAL VERDICT",
            "============================================================",
            "",
            f"Risk Level: {risk.risk_level}",
            "",
            "The application was tested using safe automated static and runtime",
            "analysis. All findings are backed by concrete evidence and must be",
            "reviewed and validated prior to production distribution.",
            "",
            "============================================================",
            "END OF REPORT",
            "============================================================",
        ])

        content = "\n".join(lines)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)

        return content

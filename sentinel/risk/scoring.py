"""Deterministic risk scoring and assessment engine."""

from __future__ import annotations

from typing import List

from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding, RiskScoreSummary


class RiskScoringEngine:
    """Calculates transparent, multi-category scores from findings."""

    # Penalty deductions per severity level
    PENALTIES = {
        Severity.CRITICAL: 25.0,
        Severity.HIGH: 12.0,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.0,
        Severity.INFO: 0.0,
    }

    def evaluate(self, findings: List[Finding]) -> RiskScoreSummary:
        crit = 0
        high = 0
        med = 0
        low = 0
        info = 0

        # Base category scores (out of 100)
        sec_penalties = 0.0
        stab_penalties = 0.0
        perf_penalties = 0.0
        ux_penalties = 0.0
        acc_penalties = 0.0
        cfg_penalties = 0.0

        for f in findings:
            p = self.PENALTIES.get(f.severity, 0.0)

            if f.severity == Severity.CRITICAL:
                crit += 1
            elif f.severity == Severity.HIGH:
                high += 1
            elif f.severity == Severity.MEDIUM:
                med += 1
            elif f.severity == Severity.LOW:
                low += 1
            else:
                info += 1

            cat = f.category
            if cat in (FindingCategory.SECURITY, FindingCategory.SECRETS, FindingCategory.ATTACK_SURFACE, FindingCategory.NETWORK):
                sec_penalties += p
            elif cat in (FindingCategory.RUNTIME,):
                stab_penalties += p
            elif cat in (FindingCategory.PERFORMANCE,):
                perf_penalties += p
            elif cat in (FindingCategory.UI_UX,):
                ux_penalties += p
            elif cat in (FindingCategory.ACCESSIBILITY,):
                acc_penalties += p
            elif cat in (FindingCategory.CONFIGURATION, FindingCategory.DEPENDENCY, FindingCategory.FLUTTER):
                cfg_penalties += p

        # Calculate bounded scores (0-100)
        sec_score = max(0.0, min(100.0, 100.0 - sec_penalties))
        stab_score = max(0.0, min(100.0, 100.0 - stab_penalties))
        perf_score = max(0.0, min(100.0, 100.0 - perf_penalties))
        ux_score = max(0.0, min(100.0, 100.0 - ux_penalties))
        acc_score = max(0.0, min(100.0, 100.0 - acc_penalties))
        cfg_score = max(0.0, min(100.0, 100.0 - cfg_penalties))

        # Overall weighted composite score
        overall = (
            sec_score * 0.35
            + stab_score * 0.25
            + perf_score * 0.15
            + cfg_score * 0.10
            + ux_score * 0.08
            + acc_score * 0.07
        )

        # Classify overall risk level
        if crit > 0 or high >= 3:
            risk_level = "CRITICAL"
        elif high > 0 or med >= 3:
            risk_level = "HIGH"
        elif med > 0 or low >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return RiskScoreSummary(
            overall_score=round(overall, 1),
            security_score=round(sec_score, 1),
            stability_score=round(stab_score, 1),
            performance_score=round(perf_score, 1),
            ux_score=round(ux_score, 1),
            accessibility_score=round(acc_score, 1),
            configuration_score=round(cfg_score, 1),
            risk_level=risk_level,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
        )

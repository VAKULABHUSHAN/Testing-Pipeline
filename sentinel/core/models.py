"""Core standardized data models for Mobile Sentinel."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sentinel.core.enums import (
    FindingCategory,
    FindingCertainty,
    Severity,
    ToolStatus,
)


@dataclass
class Finding:
    """Standardized finding representation produced by all analyzers."""
    id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float
    description: str
    impact: str
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    location: str = ""
    references: List[str] = field(default_factory=list)
    certainty: FindingCertainty = FindingCertainty.POTENTIAL
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize category and severity if strings were passed
        if isinstance(self.category, str):
            self.category = FindingCategory(self.category)
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.certainty, str):
            self.certainty = FindingCertainty(self.certainty)

        # Generate deterministic fingerprint if not explicitly set
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """Generate a deterministic hash based on core finding identity."""
        raw_key = f"{self.id}:{self.category.value}:{self.source}:{self.location}:{sorted(self.evidence.keys())}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to serializable dictionary."""
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        data["certainty"] = self.certainty.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        """Reconstruct Finding from dictionary."""
        d = dict(data)
        if "category" in d:
            d["category"] = FindingCategory(d["category"])
        if "severity" in d:
            d["severity"] = Severity(d["severity"])
        if "certainty" in d:
            d["certainty"] = FindingCertainty(d["certainty"])
        return cls(**d)


@dataclass
class ToolCheckResult:
    """Diagnostic check result for a single system tool or dependency."""
    name: str
    status: ToolStatus
    found: bool
    version: Optional[str] = None
    path: Optional[str] = None
    details: str = ""
    required: bool = True
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class EnvironmentReport:
    """Full environment diagnostic report."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ready_for_scan: bool = False
    ready_for_runtime: bool = False
    tools: Dict[str, ToolCheckResult] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "ready_for_scan": self.ready_for_scan,
            "ready_for_runtime": self.ready_for_runtime,
            "tools": {k: v.to_dict() for k, v in self.tools.items()},
            "summary": self.summary,
        }


@dataclass
class ScanMetadata:
    """Metadata regarding a single execution scan."""
    scan_id: str
    app_path: str
    app_hash_sha256: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    is_flutter: bool = False
    tool_version: str = "0.1.0"
    analyzers_executed: List[str] = field(default_factory=list)
    failed_analyzers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TestScenarioResult:
    """Outcome of an individual automated test scenario."""
    __test__ = False
    test_id: str
    name: str
    status: str  # PASS, WARN, FAIL, SKIPPED, PARTIAL
    details: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskScoreSummary:
    """Multi-category risk score output (0-100, where 100 is best / lowest risk)."""
    overall_score: float = 100.0
    security_score: float = 100.0
    stability_score: float = 100.0
    performance_score: float = 100.0
    ux_score: float = 100.0
    accessibility_score: float = 100.0
    configuration_score: float = 100.0
    risk_level: str = "LOW"
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

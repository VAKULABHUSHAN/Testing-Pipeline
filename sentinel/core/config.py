"""Configuration loader and settings models for Mobile Sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

from sentinel.core.exceptions import ConfigError


@dataclass
class ScanConfig:
    static: bool = True
    runtime: bool = False
    network: bool = False
    ui: bool = False
    accessibility: bool = False


@dataclass
class RuntimeConfig:
    device: str = "auto"
    timeout_seconds: int = 300
    collect_logcat: bool = True
    capture_screenshots: bool = True


@dataclass
class SafetyConfig:
    destructive_actions: bool = False
    allow_network_traffic: bool = False
    allow_external_calls: bool = False


@dataclass
class ReportConfig:
    html: bool = True
    json: bool = True
    pdf: bool = False
    output_dir: str = "reports"


@dataclass
class SentinelConfig:
    project_name: str = "Mobile Sentinel Assessment"
    scan: ScanConfig = field(default_factory=ScanConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    @classmethod
    def default(cls) -> SentinelConfig:
        return cls()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SentinelConfig:
        try:
            scan_data = data.get("scan", {})
            runtime_data = data.get("runtime", {})
            safety_data = data.get("safety", {})
            report_data = data.get("report", {})

            return cls(
                project_name=data.get("project", {}).get("name", "Mobile Sentinel Assessment")
                if isinstance(data.get("project"), dict)
                else data.get("project_name", "Mobile Sentinel Assessment"),
                scan=ScanConfig(
                    static=scan_data.get("static", True),
                    runtime=scan_data.get("runtime", False),
                    network=scan_data.get("network", False),
                    ui=scan_data.get("ui", False),
                    accessibility=scan_data.get("accessibility", False),
                ),
                runtime=RuntimeConfig(
                    device=runtime_data.get("device", "auto"),
                    timeout_seconds=runtime_data.get("timeout", 300),
                    collect_logcat=runtime_data.get("collect_logcat", True),
                    capture_screenshots=runtime_data.get("capture_screenshots", True),
                ),
                safety=SafetyConfig(
                    destructive_actions=safety_data.get("destructive_actions", False),
                    allow_network_traffic=safety_data.get("allow_network_traffic", False),
                    allow_external_calls=safety_data.get("allow_external_calls", False),
                ),
                report=ReportConfig(
                    html=report_data.get("html", True),
                    json=report_data.get("json", True),
                    pdf=report_data.get("pdf", False),
                    output_dir=report_data.get("output_dir", "reports"),
                ),
            )
        except Exception as e:
            raise ConfigError(f"Failed to parse Sentinel configuration: {e}") from e

    @classmethod
    def from_yaml(cls, file_path: Path | str) -> SentinelConfig:
        path = Path(file_path)
        if not path.exists():
            raise ConfigError(f"Configuration file does not exist: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f) or {}
            return cls.from_dict(content)
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML syntax in {path}: {e}") from e

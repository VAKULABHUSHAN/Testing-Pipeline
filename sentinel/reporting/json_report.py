"""Structured JSON report generator for Mobile Sentinel."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.orchestrator.pipeline import ScanExecutionResult


class JsonReportGenerator:
    """Generates machine-readable report.json containing full structured evidence."""

    def generate(self, result: ScanExecutionResult, output_path: Path | str) -> str:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        data = result.to_dict()
        content = json.dumps(data, indent=2)

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)

        return content

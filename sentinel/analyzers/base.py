"""Base analyzer interface for Mobile Sentinel."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from sentinel.core.models import Finding, ScanMetadata


class BaseAnalyzer(ABC):
    """Abstract contract that all specialized analyzers must implement."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this analyzer."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief summary of what this analyzer evaluates."""
        pass

    @abstractmethod
    def analyze(self, target: Any, metadata: ScanMetadata) -> List[Finding]:
        """Executes analysis against the target and produces standardized findings."""
        pass

"""Core enumerations for Mobile Sentinel."""

from enum import Enum


class Severity(str, Enum):
    """Standardized finding severity ratings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher is more critical)."""
        ranks = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return ranks.get(self.value, 0)


class FindingCategory(str, Enum):
    """Standardized finding categories across analyzers."""
    SECURITY = "SECURITY"
    ATTACK_SURFACE = "ATTACK_SURFACE"
    CONFIGURATION = "CONFIGURATION"
    SECRETS = "SECRETS"
    DEPENDENCY = "DEPENDENCY"
    FLUTTER = "FLUTTER"
    RUNTIME = "RUNTIME"
    PERFORMANCE = "PERFORMANCE"
    UI_UX = "UI_UX"
    ACCESSIBILITY = "ACCESSIBILITY"
    NETWORK = "NETWORK"


class FindingCertainty(str, Enum):
    """Confidence classification for findings."""
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    OBSERVATION = "OBSERVATION"


class PermissionClassification(str, Enum):
    """Android permission risk and protection level classification."""
    NORMAL = "NORMAL"
    DANGEROUS = "DANGEROUS"
    SPECIAL = "SPECIAL"
    SIGNATURE = "SIGNATURE"
    UNKNOWN = "UNKNOWN"


class SafetyLevel(str, Enum):
    """Runtime test action safety classification."""
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DESTRUCTIVE = "DESTRUCTIVE"
    BLOCKED = "BLOCKED"


class ToolStatus(str, Enum):
    """Environment tool detection status."""
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    DEGRADED = "DEGRADED"
    UNKNOWN = "UNKNOWN"

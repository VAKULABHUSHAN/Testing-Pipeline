"""Domain-specific exceptions for Mobile Sentinel."""


class SentinelError(Exception):
    """Base exception for all Mobile Sentinel errors."""
    pass


class EnvironmentToolMissingError(SentinelError):
    """Raised when a required system tool or SDK is missing."""
    pass


class APKValidationError(SentinelError):
    """Raised when an APK file is invalid, corrupt, or inaccessible."""
    pass


class AnalysisError(SentinelError):
    """Raised when an analyzer fails during execution."""
    def __init__(self, analyzer_name: str, message: str, original_exception: Exception | None = None):
        super().__init__(f"[{analyzer_name}] {message}")
        self.analyzer_name = analyzer_name
        self.original_exception = original_exception


class RuntimeDeviceError(SentinelError):
    """Raised when an ADB device or emulator operation fails."""
    pass


class SafetyViolationError(SentinelError):
    """Raised when a prohibited or unsafe action is attempted in runtime testing."""
    pass


class ConfigError(SentinelError):
    """Raised when configuration parsing or validation fails."""
    pass


class TargetPackageViolation(SentinelError):
    """Raised when an operation attempts to target an unauthorized application package."""
    pass


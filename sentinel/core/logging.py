"""Structured, safe logging for Mobile Sentinel."""

import logging
import re
import sys
from typing import Optional

# Pre-compiled regex patterns for common sensitive material to prevent accidental log exposure
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(password|secret|api_?key|auth_token)\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?"),
    re.compile(r"(?i)\b(bearer|token)\s*[:=\s]\s*['\"]?([a-zA-Z0-9_\-\.\+/]{8,})['\"]?"),
    re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
    re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+)\b"),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
]


class RedactingFormatter(logging.Formatter):
    """Logging formatter that sanitizes potential secrets from log output."""

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return self.redact(msg)

    @classmethod
    def redact(cls, text: str) -> str:
        redacted = text
        for pattern in SENSITIVE_PATTERNS:
            def _replace(match: re.Match) -> str:
                if match.lastindex and match.lastindex >= 2:
                    secret = match.group(2)
                    if len(secret) <= 6:
                        masked = "***"
                    else:
                        masked = secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
                    matched_str = match.group(0)
                    idx = matched_str.rfind(secret)
                    if idx != -1:
                        return matched_str[:idx] + masked + matched_str[idx + len(secret):]
                    return masked

                full_val = match.group(0)
                if len(full_val) > 8:
                    return full_val[:3] + "*" * (len(full_val) - 6) + full_val[-3:]
                return "***REDACTED***"

            redacted = pattern.sub(_replace, redacted)
        return redacted


def setup_logger(name: str = "sentinel", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a centralized safe logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.propagate = False
    return logger


logger = setup_logger()

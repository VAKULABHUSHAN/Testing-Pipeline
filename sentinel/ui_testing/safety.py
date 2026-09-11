"""Safety classification and policy engine for automated UI exploration."""

from __future__ import annotations

import re
from typing import Tuple


class SafetyClassifier:
    """Classifies UI controls into SAFE, CAUTION, or DESTRUCTIVE actions."""

    DESTRUCTIVE_PATTERNS = [
        r"\bdelete\b",
        r"\bremove\b",
        r"\berase\b",
        r"\bclear\s+all\b",
        r"\bclear\s+data\b",
        r"\bfactory\s+reset\b",
        r"\breset\b",
        r"\bpurge\b",
        r"\bdestroy\b",
        r"\bunlink\b",
        r"\bdisconnect\b",
        r"\blogout\b",
        r"\blog\s+out\b",
        r"\bsign\s+out\b",
        r"\bdeactivate\b",
        r"\bclose\s+account\b",
        r"\bdelete\s+account\b",
        r"\bpayment\b",
        r"\bbuy\b",
        r"\bpurchase\b",
        r"\bcheckout\b",
        r"\bpay\s+now\b",
        r"\btransfer\s+funds\b",
        r"\bwithdraw\b",
    ]

    CAUTION_PATTERNS = [
        r"\bsave\b",
        r"\bedit\b",
        r"\bupdate\b",
        r"\bupload\b",
        r"\bexport\b",
        r"\bshare\b",
        r"\bapply\b",
        r"\bconfirm\b",
        r"\bsubmit\b",
    ]

    SAFE_PATTERNS = [
        r"\blogin\b",
        r"\bsign\s+in\b",
        r"\bregister\b",
        r"\bsign\s+up\b",
        r"\bskip\b",
        r"\bnext\b",
        r"\bcontinue\b",
        r"\bback\b",
        r"\bhome\b",
        r"\bprofile\b",
        r"\bsettings\b",
        r"\bcards\b",
        r"\bcategories\b",
        r"\bfaq\b",
        r"\bguidelines\b",
        r"\babout\b",
        r"\bhelp\b",
        r"\bsearch\b",
        r"\bfilter\b",
        r"\bview\b",
        r"\bopen\b",
        r"\binfo\b",
        r"\bdetails\b",
        r"\bclose\b",
        r"\bcancel\b",
        r"\bdone\b",
        r"\bok\b",
    ]

    def __init__(self, allow_destructive: bool = False, allow_caution: bool = True):
        self.allow_destructive = allow_destructive
        self.allow_caution = allow_caution

    def classify(self, text: str, content_desc: str = "", resource_id: str = "") -> Tuple[str, str]:
        """Classifies a control as SAFE, CAUTION, or DESTRUCTIVE.
        
        Returns:
            (classification, reason)
        """
        combined = f"{text} {content_desc} {resource_id}".lower().strip()

        # Check destructive
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, combined):
                match = re.search(pattern, combined).group(0)
                return "DESTRUCTIVE", f"Control matches destructive pattern '{match}'"

        # Check caution
        for pattern in self.CAUTION_PATTERNS:
            if re.search(pattern, combined):
                match = re.search(pattern, combined).group(0)
                return "CAUTION", f"Control matches caution pattern '{match}'"

        return "SAFE", "Standard non-destructive control"

    def is_action_allowed(self, safety_class: str) -> bool:
        """Determines if the action can be executed under the current safety policy."""
        if safety_class == "DESTRUCTIVE":
            return self.allow_destructive
        if safety_class == "CAUTION":
            return self.allow_caution
        return True

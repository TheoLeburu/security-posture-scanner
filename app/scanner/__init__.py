"""Zero-dependency scanning engine. Imports nothing from the rest of app/."""

from .base import Check, CheckResult, Finding, ScanContext, Severity, Target
from .engine import scan
from .grading import Grade, grade_results

__all__ = [
    "Check",
    "CheckResult",
    "Finding",
    "Grade",
    "ScanContext",
    "Severity",
    "Target",
    "grade_results",
    "scan",
]

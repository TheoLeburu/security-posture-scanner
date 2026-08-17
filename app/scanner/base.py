"""Core types shared by every check.

The scanner engine is deliberately dependency-free: it relies only on the
Python standard library so that it can be embedded in a CLI, a FastAPI
service, or a scheduled job without dragging in a web framework.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """How much a finding should worry the site owner.

    ``weight`` is the number of points deducted from a check's score when the
    finding is present. Keeping the weight on the enum means scoring stays
    consistent across checks instead of each check inventing its own scale.
    """

    INFO = ("info", 0)
    LOW = ("low", 5)
    MEDIUM = ("medium", 15)
    HIGH = ("high", 30)
    CRITICAL = ("critical", 50)

    def __init__(self, label: str, weight: int) -> None:
        self.label = label
        self.weight = weight

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


@dataclass(frozen=True)
class Finding:
    """A single observation about the target.

    Every finding carries a remediation string. A scanner that tells you
    something is wrong without telling you how to fix it is only half a tool,
    and remediation text is what makes the PDF report worth sending to a
    client.
    """

    title: str
    severity: Severity
    detail: str
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "detail": self.detail,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclass
class CheckResult:
    """The outcome of running one check against one target."""

    check_id: str
    name: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""

    @property
    def score(self) -> int:
        """Score from 0-100 for this check.

        Starts at 100 and deducts each finding's weight. Skipped or errored
        checks return 100 so that a network hiccup never silently penalises
        the target -- they are reported separately instead.
        """
        if self.skipped or self.error:
            return 100
        total = 100 - sum(f.severity.weight for f in self.findings)
        return max(0, total)

    @property
    def passed(self) -> bool:
        return not any(
            f.severity is not Severity.INFO for f in self.findings
        )

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "score": self.score,
            "passed": self.passed,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Target:
    """A normalised scan target."""

    hostname: str
    port: int = 443
    scheme: str = "https"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.hostname}"


class Check:
    """Base class for all checks.

    Subclasses implement :meth:`run` and return a list of findings. The base
    class handles the result wrapper and turns unexpected exceptions into a
    recorded error rather than letting one broken check abort the whole scan.
    """

    check_id: str = "base"
    name: str = "Base check"
    #: Relative importance of this check in the overall grade.
    weight: float = 1.0

    def run(self, target: Target, context: "ScanContext") -> list[Finding]:
        raise NotImplementedError

    def execute(self, target: Target, context: "ScanContext") -> CheckResult:
        result = CheckResult(check_id=self.check_id, name=self.name)
        try:
            result.findings = self.run(target, context)
        except SkipCheck as exc:
            result.skipped = True
            result.skip_reason = str(exc)
        except Exception as exc:  # noqa: BLE001 - one bad check must not kill the scan
            result.error = f"{type(exc).__name__}: {exc}"
        return result


class SkipCheck(Exception):
    """Raised by a check when it cannot meaningfully run."""


@dataclass
class ScanContext:
    """Data fetched once and shared across checks.

    Without this, six checks would each open their own connection to the
    target. Fetching once and passing the response around keeps the scan
    polite -- which matters, because scanning a host you do not own is not
    something this tool should make easy to do at volume.
    """

    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_headers: list[str] = field(default_factory=list)
    final_url: str = ""
    tls_info: dict = field(default_factory=dict)
    http_redirects_to_https: bool | None = None
    fetch_error: str = ""

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())

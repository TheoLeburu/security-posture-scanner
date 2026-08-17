"""Turn a set of check results into a single weighted grade.

Grading is separated from the checks so that the scoring policy can be tuned
in one place without touching detection logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import CheckResult, Severity

# Lower bound of each grade band.
GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (50, "E"),
    (0, "F"),
)

# A single finding at or above this severity caps the overall grade.
GRADE_CAPS: dict[Severity, str] = {
    Severity.CRITICAL: "F",
    Severity.HIGH: "C",
}

_GRADE_ORDER = ["A", "B", "C", "D", "E", "F"]


def letter_for_score(score: float) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def _worse(a: str, b: str) -> str:
    """Return whichever grade is worse."""
    return a if _GRADE_ORDER.index(a) >= _GRADE_ORDER.index(b) else b


@dataclass
class Grade:
    score: float
    letter: str
    capped_by: str = ""

    def to_dict(self) -> dict:
        return {"score": round(self.score, 1), "letter": self.letter, "capped_by": self.capped_by}


def grade_results(results: list[CheckResult], weights: dict[str, float]) -> Grade:
    """Compute the weighted average score and apply severity caps.

    A weighted average alone would let a site with one critical failure and
    five clean checks still score well, which is misleading. The cap makes the
    worst finding visible in the headline grade.
    """
    scored = [r for r in results if not r.skipped and not r.error]
    if not scored:
        return Grade(score=0.0, letter="F", capped_by="no checks could be completed")

    total_weight = sum(weights.get(r.check_id, 1.0) for r in scored)
    weighted_sum = sum(r.score * weights.get(r.check_id, 1.0) for r in scored)
    score = weighted_sum / total_weight

    letter = letter_for_score(score)
    capped_by = ""
    for result in scored:
        for finding in result.findings:
            cap = GRADE_CAPS.get(finding.severity)
            if cap and _worse(letter, cap) == cap and letter != cap:
                letter = cap
                capped_by = finding.title
            elif cap and _worse(letter, cap) == cap:
                capped_by = capped_by or finding.title

    return Grade(score=score, letter=letter, capped_by=capped_by)

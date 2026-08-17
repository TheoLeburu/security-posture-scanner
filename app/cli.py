"""Command-line interface. Depends only on the standard library.

    python -m app.cli example.com
    python -m app.cli example.com --json
"""

from __future__ import annotations

import argparse
import json
import sys

from .scanner.base import Severity
from .scanner.engine import scan

_COLOURS = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _colour(text: str, severity: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLOURS.get(severity, '')}{text}{_RESET}"


def render(report, use_colour: bool = True) -> str:
    lines: list[str] = []
    grade = report.grade
    header = f"{report.target.hostname}  -  Grade {grade.letter} ({grade.score:.0f}/100)"
    lines.append(f"{_BOLD if use_colour else ''}{header}{_RESET if use_colour else ''}")
    if grade.capped_by:
        lines.append(f"  Grade capped by: {grade.capped_by}")
    lines.append("")

    for result in report.results:
        if result.skipped:
            lines.append(f"[ skip ] {result.name}: {result.skip_reason}")
            continue
        if result.error:
            lines.append(f"[ err  ] {result.name}: {result.error}")
            continue

        status = "pass" if result.passed else "fail"
        lines.append(f"[ {status} ] {result.name} ({result.score}/100)")
        for finding in result.findings:
            label = finding.severity.label.upper().ljust(8)
            lines.append(f"    {_colour(label, finding.severity.label, use_colour)} {finding.title}")
            lines.append(f"             {finding.detail}")
            if finding.remediation:
                lines.append(f"             Fix: {finding.remediation}")
        lines.append("")

    counts = report.finding_counts
    if counts:
        summary = ", ".join(f"{n} {label}" for label, n in sorted(counts.items()))
        lines.append(f"Findings: {summary}")
    else:
        lines.append("No findings.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security-posture-scanner",
        description="Grade a website's header and transport security configuration.",
        epilog="Only scan hosts you own or have written permission to test.",
    )
    parser.add_argument("target", help="Hostname or URL, for example example.com")
    parser.add_argument("--json", action="store_true", help="Emit the raw JSON report")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-connection timeout in seconds")
    parser.add_argument("--no-colour", action="store_true", help="Disable ANSI colour output")
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="SCORE",
        help="Exit with status 1 if the score is below this value. Useful in CI.",
    )
    args = parser.parse_args(argv)

    try:
        report = scan(args.target, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render(report, use_colour=not args.no_colour and sys.stdout.isatty()))

    if args.fail_under is not None and report.grade.score < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

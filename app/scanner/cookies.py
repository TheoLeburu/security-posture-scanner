"""Cookie attribute and information-disclosure checks."""

from __future__ import annotations

import re

from .base import Check, Finding, ScanContext, Severity, SkipCheck, Target

# Matches "name=value" at the start of a Set-Cookie header.
_COOKIE_NAME = re.compile(r"^\s*([^=;\s]+)\s*=")

# Headers that commonly leak stack and version details.
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

# A version number looks like at least two dot-separated digit groups.
_VERSION_PATTERN = re.compile(r"\d+\.\d+")


def _parse_cookie(header: str) -> tuple[str, set[str], str | None]:
    """Return (name, lowercased attribute set, samesite value)."""
    match = _COOKIE_NAME.match(header)
    name = match.group(1) if match else "<unnamed>"

    attributes: set[str] = set()
    samesite: str | None = None
    for part in header.split(";")[1:]:
        part = part.strip().lower()
        if not part:
            continue
        if part.startswith("samesite="):
            samesite = part.split("=", 1)[1].strip()
            attributes.add("samesite")
        else:
            attributes.add(part.split("=", 1)[0])
    return name, attributes, samesite


class CookieFlagsCheck(Check):
    check_id = "cookies"
    name = "Cookie attributes"
    weight = 1.5

    def run(self, target: Target, context: ScanContext) -> list[Finding]:
        if context.fetch_error:
            raise SkipCheck(f"Could not fetch the target: {context.fetch_error}")
        if not context.set_cookie_headers:
            raise SkipCheck("The response set no cookies, so there is nothing to check.")

        findings: list[Finding] = []
        for header in context.set_cookie_headers:
            name, attributes, samesite = _parse_cookie(header)

            if "secure" not in attributes:
                findings.append(
                    Finding(
                        title=f"Cookie {name!r} missing Secure",
                        severity=Severity.HIGH,
                        detail=(
                            "The cookie can be transmitted over plain HTTP, which "
                            "exposes it to anyone on the network path."
                        ),
                        remediation="Add the Secure attribute so the cookie is only sent over HTTPS.",
                    )
                )

            if "httponly" not in attributes:
                findings.append(
                    Finding(
                        title=f"Cookie {name!r} missing HttpOnly",
                        severity=Severity.MEDIUM,
                        detail=(
                            "JavaScript can read this cookie, so a single XSS bug "
                            "becomes full session theft."
                        ),
                        remediation="Add HttpOnly unless client-side script genuinely needs to read it.",
                    )
                )

            if samesite is None:
                findings.append(
                    Finding(
                        title=f"Cookie {name!r} missing SameSite",
                        severity=Severity.LOW,
                        detail="Browsers default to Lax, but stating the intent explicitly avoids surprises.",
                        remediation="Add 'SameSite=Lax', or 'SameSite=Strict' for session cookies.",
                    )
                )
            elif samesite == "none" and "secure" not in attributes:
                findings.append(
                    Finding(
                        title=f"Cookie {name!r} uses SameSite=None without Secure",
                        severity=Severity.HIGH,
                        detail="Modern browsers reject SameSite=None cookies that are not also Secure.",
                        remediation="Add the Secure attribute, or change SameSite to Lax.",
                    )
                )

        return findings


class InformationDisclosureCheck(Check):
    check_id = "disclosure"
    name = "Information disclosure"
    weight = 0.5

    def run(self, target: Target, context: ScanContext) -> list[Finding]:
        if context.fetch_error:
            raise SkipCheck(f"Could not fetch the target: {context.fetch_error}")

        findings: list[Finding] = []
        for header_name in _DISCLOSURE_HEADERS:
            value = context.header(header_name)
            if value is None:
                continue
            if _VERSION_PATTERN.search(value):
                findings.append(
                    Finding(
                        title=f"{header_name} header exposes a version",
                        severity=Severity.LOW,
                        detail=(
                            f"The {header_name} header reports {value!r}. Version "
                            "strings let an attacker match your stack against known "
                            "vulnerabilities without probing for them."
                        ),
                        remediation=f"Suppress or genericise the {header_name} header at the web server or proxy.",
                    )
                )
            elif header_name in ("x-powered-by", "x-aspnet-version", "x-generator"):
                findings.append(
                    Finding(
                        title=f"{header_name} header present",
                        severity=Severity.INFO,
                        detail=f"The header reports {value!r}, revealing part of the technology stack.",
                        remediation=f"Remove the {header_name} header; it serves no functional purpose.",
                    )
                )
        return findings

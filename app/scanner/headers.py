"""HTTP security header checks.

Each header gets its own small analyser function so that the logic stays
testable in isolation and so that adding a header later does not mean editing
one large branching function.
"""

from __future__ import annotations

from .base import Check, Finding, ScanContext, Severity, SkipCheck, Target

# A year, the value recommended for preload-eligible sites.
HSTS_RECOMMENDED_MAX_AGE = 31_536_000

# Directives whose absence meaningfully weakens a policy.
CSP_IMPORTANT_DIRECTIVES = ("default-src", "object-src", "base-uri", "frame-ancestors")


def _analyse_hsts(value: str | None) -> list[Finding]:
    if value is None:
        return [
            Finding(
                title="Strict-Transport-Security missing",
                severity=Severity.HIGH,
                detail=(
                    "The response does not set an HSTS header, so a browser "
                    "visiting over plain HTTP can be downgraded by an attacker "
                    "on the network path before the redirect to HTTPS happens."
                ),
                remediation=(
                    "Send 'Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains' on all HTTPS responses."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            )
        ]

    findings: list[Finding] = []
    directives = [d.strip().lower() for d in value.split(";") if d.strip()]
    max_age: int | None = None
    for directive in directives:
        if directive.startswith("max-age="):
            raw = directive.split("=", 1)[1].strip().strip('"')
            if raw.isdigit():
                max_age = int(raw)

    if max_age is None:
        findings.append(
            Finding(
                title="HSTS max-age not set",
                severity=Severity.HIGH,
                detail="The HSTS header is present but has no valid max-age directive, so browsers ignore it.",
                remediation="Add 'max-age=31536000' to the Strict-Transport-Security header.",
            )
        )
    elif max_age == 0:
        findings.append(
            Finding(
                title="HSTS disabled by max-age=0",
                severity=Severity.HIGH,
                detail="A max-age of 0 instructs browsers to forget the HSTS policy entirely.",
                remediation="Set max-age to 31536000 unless you are deliberately rolling HSTS back.",
            )
        )
    elif max_age < HSTS_RECOMMENDED_MAX_AGE:
        findings.append(
            Finding(
                title="HSTS max-age below one year",
                severity=Severity.LOW,
                detail=f"max-age is {max_age} seconds; one year (31536000) is the recommended value.",
                remediation="Raise max-age to 31536000 once you are confident HTTPS is stable.",
            )
        )

    if "includesubdomains" not in directives:
        findings.append(
            Finding(
                title="HSTS does not cover subdomains",
                severity=Severity.LOW,
                detail=(
                    "Without includeSubDomains, a subdomain served over HTTP can be "
                    "used to set cookies that the parent domain will read."
                ),
                remediation="Add 'includeSubDomains' once every subdomain serves HTTPS.",
            )
        )

    return findings


def _analyse_csp(value: str | None) -> list[Finding]:
    if value is None:
        return [
            Finding(
                title="Content-Security-Policy missing",
                severity=Severity.HIGH,
                detail=(
                    "No CSP is set, so the browser will execute script from any "
                    "origin the page references. CSP is the strongest single "
                    "mitigation against cross-site scripting."
                ),
                remediation=(
                    "Start with a report-only policy such as "
                    "\"default-src 'self'; object-src 'none'; base-uri 'self'\", "
                    "review the reports, then enforce it."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
            )
        ]

    findings: list[Finding] = []
    policy = value.lower()

    if "unsafe-inline" in policy:
        findings.append(
            Finding(
                title="CSP allows unsafe-inline",
                severity=Severity.MEDIUM,
                detail=(
                    "'unsafe-inline' permits inline scripts and event handlers, "
                    "which is the exact vector CSP exists to block."
                ),
                remediation="Replace inline scripts with external files, or adopt a nonce or hash based policy.",
            )
        )

    if "unsafe-eval" in policy:
        findings.append(
            Finding(
                title="CSP allows unsafe-eval",
                severity=Severity.MEDIUM,
                detail="'unsafe-eval' permits eval() and equivalents, widening the impact of an injection bug.",
                remediation="Remove 'unsafe-eval' and refactor the code that requires dynamic evaluation.",
            )
        )

    declared = {d.strip().split(" ")[0] for d in policy.split(";") if d.strip()}
    missing = [d for d in CSP_IMPORTANT_DIRECTIVES if d not in declared]
    if missing:
        findings.append(
            Finding(
                title="CSP is missing key directives",
                severity=Severity.LOW,
                detail=f"The policy does not declare: {', '.join(missing)}.",
                remediation="Declare these directives explicitly rather than relying on browser defaults.",
            )
        )

    if "*" in policy.replace("*.", ""):
        findings.append(
            Finding(
                title="CSP uses a wildcard source",
                severity=Severity.MEDIUM,
                detail="A bare '*' source allows content from any origin, which largely defeats the policy.",
                remediation="Replace wildcard sources with an explicit allowlist of origins you control.",
            )
        )

    return findings


def _analyse_frame_options(headers: ScanContext) -> list[Finding]:
    csp = (headers.header("content-security-policy") or "").lower()
    if "frame-ancestors" in csp:
        # frame-ancestors supersedes X-Frame-Options in every modern browser.
        return []

    value = headers.header("x-frame-options")
    if value is None:
        return [
            Finding(
                title="Clickjacking protection missing",
                severity=Severity.MEDIUM,
                detail=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive is "
                    "set, so the page can be embedded in an attacker's iframe and "
                    "used to trick users into clicking controls they cannot see."
                ),
                remediation="Set \"Content-Security-Policy: frame-ancestors 'self'\", or 'X-Frame-Options: DENY'.",
            )
        ]

    if value.strip().lower() not in {"deny", "sameorigin"}:
        return [
            Finding(
                title="X-Frame-Options has an unrecognised value",
                severity=Severity.MEDIUM,
                detail=f"Value {value!r} is not DENY or SAMEORIGIN; browsers will ignore it.",
                remediation="Use DENY unless the page is deliberately embedded, in which case use SAMEORIGIN.",
            )
        ]
    return []


def _analyse_content_type_options(value: str | None) -> list[Finding]:
    if value is None or value.strip().lower() != "nosniff":
        return [
            Finding(
                title="X-Content-Type-Options not set to nosniff",
                severity=Severity.LOW,
                detail=(
                    "Without nosniff, browsers may guess a response's content type "
                    "and execute an uploaded file as script."
                ),
                remediation="Send 'X-Content-Type-Options: nosniff' on every response.",
            )
        ]
    return []


def _analyse_referrer_policy(value: str | None) -> list[Finding]:
    safe = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if value is None:
        return [
            Finding(
                title="Referrer-Policy missing",
                severity=Severity.LOW,
                detail=(
                    "Full URLs, including any tokens in query strings, may be sent "
                    "to third-party sites in the Referer header."
                ),
                remediation="Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
            )
        ]
    if value.strip().lower() not in safe:
        return [
            Finding(
                title="Referrer-Policy is permissive",
                severity=Severity.LOW,
                detail=f"Policy {value!r} can leak the full URL to other origins.",
                remediation="Use 'strict-origin-when-cross-origin' or stricter.",
            )
        ]
    return []


def _analyse_permissions_policy(value: str | None) -> list[Finding]:
    if value is None:
        return [
            Finding(
                title="Permissions-Policy missing",
                severity=Severity.INFO,
                detail=(
                    "No Permissions-Policy is set. Embedded third-party frames can "
                    "request access to camera, microphone and geolocation."
                ),
                remediation="Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()' if unused.",
            )
        ]
    return []


class SecurityHeadersCheck(Check):
    check_id = "http_headers"
    name = "HTTP security headers"
    weight = 2.0

    def run(self, target: Target, context: ScanContext) -> list[Finding]:
        if context.fetch_error:
            raise SkipCheck(f"Could not fetch the target: {context.fetch_error}")

        findings: list[Finding] = []
        findings += _analyse_hsts(context.header("strict-transport-security"))
        findings += _analyse_csp(context.header("content-security-policy"))
        findings += _analyse_frame_options(context)
        findings += _analyse_content_type_options(context.header("x-content-type-options"))
        findings += _analyse_referrer_policy(context.header("referrer-policy"))
        findings += _analyse_permissions_policy(context.header("permissions-policy"))
        return findings

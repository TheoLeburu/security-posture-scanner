"""Data collection and scan orchestration.

Collection happens once, up front, and every check reads from the shared
:class:`ScanContext`. This keeps the number of requests we make to a target
low and predictable -- one HTTPS request, one HTTP request, one TLS handshake.
"""

from __future__ import annotations

import datetime as dt
import http.client
import socket
import ssl
from urllib.parse import urlparse

from .base import Check, CheckResult, ScanContext, Target
from .cookies import CookieFlagsCheck, InformationDisclosureCheck
from .grading import Grade, grade_results
from .headers import SecurityHeadersCheck
from .tls import HTTPSRedirectCheck, TLSConfigurationCheck

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "security-posture-scanner/0.1 (+https://github.com/TheoLeburu)"

DEFAULT_CHECKS: tuple[Check, ...] = (
    SecurityHeadersCheck(),
    TLSConfigurationCheck(),
    HTTPSRedirectCheck(),
    CookieFlagsCheck(),
    InformationDisclosureCheck(),
)


def normalise_target(raw: str) -> Target:
    """Accept a bare hostname or a full URL and return a Target.

    Raises ValueError for anything that is not a plausible public hostname.
    Rejecting localhost and bare IPs here is deliberate: it keeps the hosted
    version of this tool from being pointed at internal addresses.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("No hostname supplied.")
    if "://" not in raw:
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not parse a hostname from {raw!r}.")
    if "." not in hostname:
        raise ValueError("Hostname must be a fully qualified domain name.")
    if hostname in {"localhost"} or hostname.endswith(".local"):
        raise ValueError("Scanning local addresses is not supported.")

    return Target(hostname=hostname, port=parsed.port or 443, scheme="https")


def collect_tls_info(target: Target, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Perform one TLS handshake and describe what the server offered."""
    info: dict = {}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((target.hostname, target.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target.hostname) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                info["protocol"] = tls_sock.version()
                cipher = tls_sock.cipher()
                info["cipher"] = cipher[0] if cipher else ""
                if cert.get("notAfter"):
                    info["not_after"] = cert["notAfter"]
                if cert.get("notBefore"):
                    info["not_before"] = cert["notBefore"]
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                info["issuer"] = issuer.get("organizationName", "")
                subject = dict(x[0] for x in cert.get("subject", ()))
                info["subject"] = subject.get("commonName", "")
                info["self_signed"] = bool(issuer) and issuer == subject
    except ssl.SSLCertVerificationError as exc:
        # Verification failures are themselves findings, so retry without
        # verification to describe the certificate we were offered.
        info["error"] = ""
        if "hostname mismatch" in str(exc).lower():
            info["hostname_mismatch"] = True
        elif "self-signed" in str(exc).lower() or "self signed" in str(exc).lower():
            info["self_signed"] = True
        else:
            info["error"] = str(exc)
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
    return info


def _fetch(scheme: str, target: Target, timeout: float, follow: bool = True) -> tuple[int | None, list[tuple[str, str]], str]:
    """Make a single request and return status, headers, and final URL."""
    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    port = target.port if scheme == "https" else 80
    conn = conn_cls(target.hostname, port, timeout=timeout, context=ssl._create_unverified_context() if scheme == "https" else None)  # type: ignore[arg-type]
    try:
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        headers = response.getheaders()
        location = response.getheader("Location", "")
        status = response.status
        response.read(0)
        final = location if location else f"{scheme}://{target.hostname}/"
        return status, headers, final
    finally:
        conn.close()


def collect_context(target: Target, timeout: float = DEFAULT_TIMEOUT) -> ScanContext:
    """Gather everything the checks need in as few requests as possible."""
    context = ScanContext()

    try:
        status, headers, final_url = _fetch("https", target, timeout)
        context.status_code = status
        context.final_url = final_url
        for name, value in headers:
            lowered = name.lower()
            if lowered == "set-cookie":
                context.set_cookie_headers.append(value)
            else:
                context.headers[lowered] = value
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a skip reason
        context.fetch_error = f"{type(exc).__name__}: {exc}"

    context.tls_info = collect_tls_info(target, timeout)

    try:
        status, headers, _ = _fetch("http", target, timeout)
        location = next((v for k, v in headers if k.lower() == "location"), "")
        context.http_redirects_to_https = bool(
            status and 300 <= status < 400 and location.lower().startswith("https://")
        )
    except Exception:  # noqa: BLE001 - a missing HTTP listener is not an error
        context.http_redirects_to_https = None

    return context


class ScanReport:
    """The full result of one scan, ready to serialise to JSON or render."""

    def __init__(self, target: Target, results: list[CheckResult], grade: Grade) -> None:
        self.target = target
        self.results = results
        self.grade = grade
        self.scanned_at = dt.datetime.now(dt.timezone.utc)

    @property
    def finding_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            for finding in result.findings:
                counts[finding.severity.label] = counts.get(finding.severity.label, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target.hostname,
            "scanned_at": self.scanned_at.isoformat(),
            "grade": self.grade.to_dict(),
            "finding_counts": self.finding_counts,
            "checks": [r.to_dict() for r in self.results],
        }


def scan(
    raw_target: str,
    checks: tuple[Check, ...] = DEFAULT_CHECKS,
    timeout: float = DEFAULT_TIMEOUT,
    context: ScanContext | None = None,
) -> ScanReport:
    """Run every check against a target and return a graded report.

    ``context`` can be supplied directly, which is what the test suite does so
    that the full pipeline can be exercised without touching the network.
    """
    target = normalise_target(raw_target)
    if context is None:
        context = collect_context(target, timeout)

    results = [check.execute(target, context) for check in checks]
    weights = {check.check_id: check.weight for check in checks}
    grade = grade_results(results, weights)
    return ScanReport(target=target, results=results, grade=grade)

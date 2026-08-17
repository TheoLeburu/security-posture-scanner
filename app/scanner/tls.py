"""TLS configuration, certificate hygiene, and HTTP-to-HTTPS redirect checks."""

from __future__ import annotations

import datetime as dt

from .base import Check, Finding, ScanContext, Severity, SkipCheck, Target

# Protocol versions with known weaknesses that should no longer be offered.
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

# Certificate expiry thresholds in days.
EXPIRY_CRITICAL_DAYS = 0
EXPIRY_WARNING_DAYS = 14
EXPIRY_NOTICE_DAYS = 30

# Cipher suite substrings that indicate a weak negotiated cipher.
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def _parse_cert_datetime(value: str) -> dt.datetime:
    """Parse OpenSSL's certificate date format into an aware datetime."""
    parsed = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=dt.timezone.utc)


def analyse_tls_info(info: dict, now: dt.datetime | None = None) -> list[Finding]:
    """Turn a raw TLS info dict into findings.

    Split out from the check class so it can be unit tested with fixture data
    instead of requiring a live TLS handshake.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    findings: list[Finding] = []

    protocol = info.get("protocol")
    if protocol in DEPRECATED_PROTOCOLS:
        findings.append(
            Finding(
                title=f"Connection negotiated {protocol}",
                severity=Severity.HIGH,
                detail=(
                    f"{protocol} is deprecated and has known weaknesses. Modern "
                    "clients will warn or refuse to connect."
                ),
                remediation="Disable everything below TLS 1.2 and prefer TLS 1.3 at the server or load balancer.",
            )
        )
    elif protocol == "TLSv1.2":
        findings.append(
            Finding(
                title="TLS 1.3 not negotiated",
                severity=Severity.INFO,
                detail="The connection used TLS 1.2. TLS 1.3 is faster and removes several legacy constructions.",
                remediation="Enable TLS 1.3 support if your server software allows it.",
            )
        )

    cipher = info.get("cipher") or ""
    if any(marker in cipher.upper() for marker in WEAK_CIPHER_MARKERS):
        findings.append(
            Finding(
                title="Weak cipher suite negotiated",
                severity=Severity.HIGH,
                detail=f"The server selected {cipher!r}, which relies on a broken or obsolete primitive.",
                remediation="Restrict the cipher list to modern AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
            )
        )

    not_after = info.get("not_after")
    if not_after:
        expiry = not_after if isinstance(not_after, dt.datetime) else _parse_cert_datetime(not_after)
        days_left = (expiry - now).days
        if days_left < EXPIRY_CRITICAL_DAYS:
            findings.append(
                Finding(
                    title="Certificate has expired",
                    severity=Severity.CRITICAL,
                    detail=f"The certificate expired {abs(days_left)} days ago. Browsers will block the site.",
                    remediation="Renew the certificate immediately and automate renewal so this cannot recur.",
                )
            )
        elif days_left <= EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    title="Certificate expires very soon",
                    severity=Severity.HIGH,
                    detail=f"Only {days_left} days remain before the certificate expires.",
                    remediation="Renew now and set up automated renewal, for example with certbot or ACME in your proxy.",
                )
            )
        elif days_left <= EXPIRY_NOTICE_DAYS:
            findings.append(
                Finding(
                    title="Certificate expires within a month",
                    severity=Severity.LOW,
                    detail=f"{days_left} days remain before expiry.",
                    remediation="Confirm that automated renewal is working.",
                )
            )

    if info.get("self_signed"):
        findings.append(
            Finding(
                title="Certificate is self-signed",
                severity=Severity.HIGH,
                detail="A self-signed certificate is not trusted by browsers and trains users to click through warnings.",
                remediation="Obtain a certificate from a trusted CA. Let's Encrypt issues them at no cost.",
            )
        )

    if info.get("hostname_mismatch"):
        findings.append(
            Finding(
                title="Certificate does not match the hostname",
                severity=Severity.CRITICAL,
                detail="The presented certificate is not valid for the requested hostname.",
                remediation="Reissue the certificate with the correct common name or subject alternative names.",
            )
        )

    return findings


class TLSConfigurationCheck(Check):
    check_id = "tls"
    name = "TLS configuration"
    weight = 2.0

    def run(self, target: Target, context: ScanContext) -> list[Finding]:
        if not context.tls_info:
            raise SkipCheck("No TLS handshake data was collected for this target.")
        if context.tls_info.get("error"):
            raise SkipCheck(f"TLS handshake failed: {context.tls_info['error']}")
        return analyse_tls_info(context.tls_info)


class HTTPSRedirectCheck(Check):
    check_id = "https_redirect"
    name = "HTTP to HTTPS redirect"
    weight = 1.5

    def run(self, target: Target, context: ScanContext) -> list[Finding]:
        if context.http_redirects_to_https is None:
            raise SkipCheck("The plain HTTP endpoint could not be reached.")
        if context.http_redirects_to_https:
            return []
        return [
            Finding(
                title="HTTP does not redirect to HTTPS",
                severity=Severity.HIGH,
                detail=(
                    "A request to the plain HTTP endpoint was served without "
                    "redirecting to HTTPS, so traffic can be read or modified in transit."
                ),
                remediation="Return a 301 redirect from all HTTP requests to the HTTPS equivalent, then enable HSTS.",
            )
        ]

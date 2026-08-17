"""Tests for the scanning engine.

Every test runs offline. Network behaviour is represented by fixture
ScanContext objects, which means the suite is fast and deterministic and can
run in CI without reaching out to third-party hosts.
"""

from __future__ import annotations

import datetime as dt
import unittest

from app.scanner.base import ScanContext, Severity, Target
from app.scanner.cookies import CookieFlagsCheck, InformationDisclosureCheck
from app.scanner.engine import normalise_target, scan
from app.scanner.grading import grade_results, letter_for_score
from app.scanner.headers import SecurityHeadersCheck
from app.scanner.tls import analyse_tls_info

TARGET = Target(hostname="example.com")

SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": (
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def titles(findings) -> set[str]:
    return {f.title for f in findings}


class HeaderCheckTests(unittest.TestCase):
    def test_well_configured_site_produces_no_findings(self):
        context = ScanContext(status_code=200, headers=dict(SECURE_HEADERS))
        result = SecurityHeadersCheck().execute(TARGET, context)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.score, 100)
        self.assertTrue(result.passed)

    def test_bare_site_flags_every_missing_header(self):
        context = ScanContext(status_code=200, headers={})
        findings = SecurityHeadersCheck().run(TARGET, context)
        found = titles(findings)
        self.assertIn("Strict-Transport-Security missing", found)
        self.assertIn("Content-Security-Policy missing", found)
        self.assertIn("Clickjacking protection missing", found)
        self.assertIn("X-Content-Type-Options not set to nosniff", found)

    def test_short_hsts_max_age_is_low_severity(self):
        headers = dict(SECURE_HEADERS, **{"strict-transport-security": "max-age=600; includeSubDomains"})
        findings = SecurityHeadersCheck().run(TARGET, ScanContext(headers=headers))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertIn("below one year", findings[0].title)

    def test_hsts_max_age_zero_is_high_severity(self):
        headers = dict(SECURE_HEADERS, **{"strict-transport-security": "max-age=0"})
        findings = SecurityHeadersCheck().run(TARGET, ScanContext(headers=headers))
        severities = {f.severity for f in findings}
        self.assertIn(Severity.HIGH, severities)

    def test_csp_unsafe_inline_is_flagged(self):
        headers = dict(
            SECURE_HEADERS,
            **{
                "content-security-policy": (
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                    "object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
                )
            },
        )
        findings = SecurityHeadersCheck().run(TARGET, ScanContext(headers=headers))
        self.assertIn("CSP allows unsafe-inline", titles(findings))

    def test_frame_ancestors_satisfies_clickjacking_requirement(self):
        """A CSP frame-ancestors directive should not also demand X-Frame-Options."""
        headers = dict(SECURE_HEADERS)
        findings = SecurityHeadersCheck().run(TARGET, ScanContext(headers=headers))
        self.assertNotIn("Clickjacking protection missing", titles(findings))

    def test_xfo_alone_also_satisfies_the_requirement(self):
        headers = {k: v for k, v in SECURE_HEADERS.items()}
        headers["content-security-policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'"
        headers["x-frame-options"] = "DENY"
        findings = SecurityHeadersCheck().run(TARGET, ScanContext(headers=headers))
        self.assertNotIn("Clickjacking protection missing", titles(findings))

    def test_fetch_error_skips_rather_than_fails(self):
        context = ScanContext(fetch_error="timed out")
        result = SecurityHeadersCheck().execute(TARGET, context)
        self.assertTrue(result.skipped)
        self.assertEqual(result.score, 100)


class CookieCheckTests(unittest.TestCase):
    def test_insecure_session_cookie_is_flagged(self):
        context = ScanContext(set_cookie_headers=["session=abc123; Path=/"])
        findings = CookieFlagsCheck().run(TARGET, context)
        found = titles(findings)
        self.assertIn("Cookie 'session' missing Secure", found)
        self.assertIn("Cookie 'session' missing HttpOnly", found)
        self.assertIn("Cookie 'session' missing SameSite", found)

    def test_hardened_cookie_passes(self):
        context = ScanContext(
            set_cookie_headers=["session=abc; Path=/; Secure; HttpOnly; SameSite=Strict"]
        )
        self.assertEqual(CookieFlagsCheck().run(TARGET, context), [])

    def test_samesite_none_without_secure_is_high(self):
        context = ScanContext(set_cookie_headers=["tracker=1; HttpOnly; SameSite=None"])
        findings = CookieFlagsCheck().run(TARGET, context)
        self.assertIn("Cookie 'tracker' uses SameSite=None without Secure", titles(findings))

    def test_no_cookies_skips(self):
        result = CookieFlagsCheck().execute(TARGET, ScanContext(status_code=200))
        self.assertTrue(result.skipped)


class DisclosureCheckTests(unittest.TestCase):
    def test_versioned_server_header_is_flagged(self):
        context = ScanContext(headers={"server": "Apache/2.4.41 (Ubuntu)"})
        findings = InformationDisclosureCheck().run(TARGET, context)
        self.assertIn("server header exposes a version", titles(findings))

    def test_generic_server_header_is_clean(self):
        context = ScanContext(headers={"server": "nginx"})
        self.assertEqual(InformationDisclosureCheck().run(TARGET, context), [])


class TLSAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    def test_modern_tls_is_clean(self):
        info = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": self.now + dt.timedelta(days=200),
        }
        self.assertEqual(analyse_tls_info(info, now=self.now), [])

    def test_deprecated_protocol_is_high(self):
        info = {"protocol": "TLSv1", "cipher": "AES256-SHA"}
        findings = analyse_tls_info(info, now=self.now)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_expired_certificate_is_critical(self):
        info = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": self.now - dt.timedelta(days=3),
        }
        findings = analyse_tls_info(info, now=self.now)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_certificate_expiring_soon_is_high(self):
        info = {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "not_after": self.now + dt.timedelta(days=5),
        }
        findings = analyse_tls_info(info, now=self.now)
        self.assertIn("Certificate expires very soon", titles(findings))

    def test_weak_cipher_is_flagged(self):
        info = {"protocol": "TLSv1.2", "cipher": "ECDHE-RSA-RC4-SHA"}
        findings = analyse_tls_info(info, now=self.now)
        self.assertIn("Weak cipher suite negotiated", titles(findings))

    def test_openssl_date_string_is_parsed(self):
        info = {"protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "not_after": "Jan 26 12:00:00 2026 GMT"}
        findings = analyse_tls_info(info, now=self.now)
        self.assertIn("Certificate expires within a month", titles(findings))


class GradingTests(unittest.TestCase):
    def test_letter_bands(self):
        self.assertEqual(letter_for_score(95), "A")
        self.assertEqual(letter_for_score(80), "B")
        self.assertEqual(letter_for_score(55), "E")
        self.assertEqual(letter_for_score(10), "F")

    def test_critical_finding_caps_grade_at_f(self):
        context = ScanContext(
            headers=dict(SECURE_HEADERS),
            tls_info={
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "not_after": dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
            },
            http_redirects_to_https=True,
        )
        report = scan("example.com", context=context)
        self.assertEqual(report.grade.letter, "F")
        self.assertTrue(report.grade.capped_by)

    def test_all_skipped_grades_f(self):
        grade = grade_results([], {})
        self.assertEqual(grade.letter, "F")


class TargetNormalisationTests(unittest.TestCase):
    def test_bare_hostname_gets_https(self):
        target = normalise_target("example.com")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.port, 443)

    def test_full_url_is_reduced_to_hostname(self):
        self.assertEqual(normalise_target("https://example.com/path?x=1").hostname, "example.com")

    def test_localhost_is_rejected(self):
        with self.assertRaises(ValueError):
            normalise_target("localhost")

    def test_bare_word_is_rejected(self):
        with self.assertRaises(ValueError):
            normalise_target("intranet")

    def test_empty_is_rejected(self):
        with self.assertRaises(ValueError):
            normalise_target("   ")


class EndToEndTests(unittest.TestCase):
    def test_well_configured_site_scores_an_a(self):
        context = ScanContext(
            status_code=200,
            headers=dict(SECURE_HEADERS, server="nginx"),
            set_cookie_headers=["session=abc; Secure; HttpOnly; SameSite=Strict"],
            tls_info={
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "not_after": dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=300),
            },
            http_redirects_to_https=True,
        )
        report = scan("example.com", context=context)
        self.assertEqual(report.grade.letter, "A")
        self.assertEqual(report.finding_counts, {})

    def test_neglected_site_scores_badly_and_serialises(self):
        context = ScanContext(
            status_code=200,
            headers={"server": "Apache/2.4.41"},
            set_cookie_headers=["session=abc"],
            tls_info={"protocol": "TLSv1", "cipher": "RC4-MD5"},
            http_redirects_to_https=False,
        )
        report = scan("example.com", context=context)
        self.assertIn(report.grade.letter, {"C", "D", "E", "F"})
        payload = report.to_dict()
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(len(payload["checks"]), 5)
        self.assertGreater(payload["finding_counts"].get("high", 0), 0)


if __name__ == "__main__":
    unittest.main()

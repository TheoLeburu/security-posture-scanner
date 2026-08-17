# Security Posture Scanner

[![CI](https://github.com/TheoLeburu/security-posture-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/TheoLeburu/security-posture-scanner/actions/workflows/ci.yml)

Grades a website's HTTP header and TLS configuration, explains what each finding means, and tells you how to fix it.

Point it at a domain you own and it returns a letter grade from A to F, a per-check score, and a remediation step for every issue found. Built as a reusable Python library first, with an HTTP API and a CLI as two interfaces onto the same engine.

> **Scope and ethics.** This tool makes three ordinary requests to a target: one HTTPS GET, one HTTP GET, and one TLS handshake. It sends no payloads, attempts no exploitation, and probes no paths. It is a configuration reviewer, not a penetration testing tool. Only scan hosts you own or have written permission to test.

---

## What it checks

| Check | Weight | Covers |
|---|---|---|
| HTTP security headers | 2.0 | HSTS (including `max-age` and `includeSubDomains`), Content-Security-Policy, clickjacking protection, `X-Content-Type-Options`, Referrer-Policy, Permissions-Policy |
| TLS configuration | 2.0 | Negotiated protocol version, cipher suite strength, certificate expiry, self-signed and hostname-mismatch certificates |
| HTTP to HTTPS redirect | 1.5 | Whether the plain HTTP endpoint redirects to HTTPS |
| Cookie attributes | 1.5 | `Secure`, `HttpOnly`, `SameSite`, and the `SameSite=None` without `Secure` combination browsers now reject |
| Information disclosure | 0.5 | Version strings leaked via `Server`, `X-Powered-By`, and similar headers |

Each check scores from 0 to 100 and contributes to a weighted overall score. A single **critical** finding caps the grade at F and a **high** finding caps it at C, so a serious problem cannot be averaged away by five clean checks.

## Quick start

```bash
git clone https://github.com/TheoLeburu/security-posture-scanner.git
cd security-posture-scanner
```

The engine needs nothing beyond Python 3.11+:

```bash
python -m app.cli example.com
```

```
example.com  -  Grade C (78/100)
  Grade capped by: Content-Security-Policy missing

[ fail ] HTTP security headers (55/100)
    HIGH     Content-Security-Policy missing
             No CSP is set, so the browser will execute script from any origin
             the page references.
             Fix: Start with a report-only policy such as "default-src 'self';
             object-src 'none'; base-uri 'self'", review the reports, then enforce it.
    LOW      Referrer-Policy missing
             ...

[ pass ] TLS configuration (100/100)

Findings: 1 high, 2 low
```

Machine-readable output for scripting:

```bash
python -m app.cli example.com --json
```

Use it as a quality gate in your own CI:

```bash
python -m app.cli example.com --fail-under 80
```

## Running the API

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `http://localhost:8000/docs` for interactive OpenAPI documentation.

```bash
curl -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target": "example.com"}'
```

The endpoint is rate limited to 10 scans per minute per client IP. A public deployment without that limit becomes a free request relay for whoever finds it.

## Architecture

```
app/
├── scanner/          # Zero-dependency engine. Imports nothing from app/.
│   ├── base.py       # Severity, Finding, CheckResult, Check ABC, ScanContext
│   ├── headers.py    # HTTP security header analysis
│   ├── cookies.py    # Cookie attributes + information disclosure
│   ├── tls.py        # TLS configuration + HTTPS redirect
│   ├── grading.py    # Weighted scoring and grade caps
│   └── engine.py     # Data collection and orchestration
├── main.py           # FastAPI interface
└── cli.py            # Command-line interface
```

Three decisions worth calling out:

**The engine has no third-party dependencies.** Everything in `app/scanner/` uses only `ssl`, `socket`, and `http.client`. That makes the engine embeddable in a CLI, a Lambda, or a cron job without dragging a web framework along, and it keeps the supply-chain surface of the security-critical code at zero.

**Data is collected once and shared.** All checks read from a single `ScanContext` populated by three requests. Six checks each opening their own connection would be both slower and ruder to the target.

**One failing check cannot abort a scan.** `Check.execute()` catches exceptions per check and records them as an error on that check's result. A malformed header on an obscure site degrades one score instead of returning a 500.

## Tests

```bash
python -m unittest discover -s tests -v
```

30 tests, all offline. Network behaviour is represented by fixture `ScanContext` objects, so the suite is deterministic, runs in milliseconds, and never sends traffic to third-party hosts from CI.

## Roadmap

- [ ] DNS email authentication checks (SPF, DKIM, DMARC)
- [ ] PDF report export for client-facing summaries
- [ ] React frontend with a shareable results page
- [ ] Scheduled rescans with change notifications
- [ ] Subresource integrity check on external scripts

## Licence

MIT — see [LICENSE](LICENSE).

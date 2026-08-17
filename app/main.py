"""FastAPI front end for the scanning engine.

The engine does not import anything from this module. That direction of
dependency is deliberate: the scanner is a library, and this is one of several
possible interfaces to it (see cli.py for another).
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .scanner.engine import DEFAULT_TIMEOUT, scan

app = FastAPI(
    title="Security Posture Scanner",
    description=(
        "Grades a website's transport and header security configuration. "
        "Only scan hosts you own or have written permission to test."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Scanning makes outbound requests on the caller's behalf, so the endpoint is
# rate limited per client IP. Without this, a public deployment becomes a free
# request relay for anyone who finds it.
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60
_request_log: dict[str, deque[float]] = defaultdict(deque)


def _enforce_rate_limit(client_ip: str) -> None:
    now = time.monotonic()
    log = _request_log[client_ip]
    while log and now - log[0] > RATE_LIMIT_WINDOW_SECONDS:
        log.popleft()
    if len(log) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {RATE_LIMIT_REQUESTS} scans per minute.",
        )
    log.append(now)


class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        description="Hostname or URL to scan, for example example.com",
        min_length=3,
        max_length=253,
        examples=["example.com"],
    )
    timeout: float = Field(DEFAULT_TIMEOUT, ge=1.0, le=30.0)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/scan")
async def run_scan(payload: ScanRequest, request: Request) -> dict:
    """Scan a target and return a graded report."""
    _enforce_rate_limit(request.client.host if request.client else "unknown")

    try:
        # The engine is synchronous and network-bound, so it runs in a worker
        # thread to avoid blocking the event loop.
        report = await asyncio.to_thread(scan, payload.target, timeout=payload.timeout)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}") from exc

    return report.to_dict()

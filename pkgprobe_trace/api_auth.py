"""
API key authentication middleware for the pkgprobe production API.

Reads X-API-Key header, validates against the database, checks tier
permissions, and injects customer context into request state.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from .api_db import ApiKey, UsageRecord, lookup_api_key
from .api_usage import record_usage

TIER_ENDPOINT_ACCESS = {
    "free": {"/v1/analyze", "/health", "/v1/billing/checkout", "/v1/billing/status", "/v1/billing/portal"},
    "pro": {"/v1/analyze", "/v1/trace", "/health", "/v1/billing/checkout", "/v1/billing/status", "/v1/billing/portal"},
    "auto_wrap": {"/v1/analyze", "/v1/trace", "/v1/auto-wrap", "/v1/artifacts", "/health", "/v1/billing/checkout", "/v1/billing/status", "/v1/billing/portal"},
}

PUBLIC_ENDPOINTS = {"/health", "/v1/stripe/webhook", "/v1/billing/checkout", "/docs", "/openapi.json"}

PAID_ENDPOINTS = {"/v1/trace", "/v1/auto-wrap"}

RATE_LIMITS = {
    "free": 60,
    "pro": 300,
    "auto_wrap": 600,
}


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that:
    1. Skips auth for public endpoints
    2. Validates X-API-Key header
    3. Checks tier access for the requested endpoint
    4. Applies rate limiting
    5. Records usage for paid endpoints
    6. Injects customer context into request.state
    """

    def __init__(self, app, *, db_session_factory):
        super().__init__(app)
        self._db_session_factory = db_session_factory
        self._rate_counters: dict[int, list[float]] = defaultdict(list)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path

        db_session = self._db_session_factory()
        request.state.db_session = db_session

        try:
            if self._is_public(path):
                return await call_next(request)

            api_key_header = request.headers.get("X-API-Key", "")
            if not api_key_header:
                raise HTTPException(status_code=401, detail="Missing X-API-Key header")

            api_key = lookup_api_key(db_session, api_key_header)
            if api_key is None:
                raise HTTPException(status_code=401, detail="Invalid or revoked API key")

            if not self._check_tier_access(api_key.tier, path):
                raise HTTPException(
                    status_code=403,
                    detail=f"Your tier ({api_key.tier}) does not have access to this endpoint. Upgrade at /v1/billing/checkout",
                )

            if not self._check_rate_limit(api_key.id, api_key.tier):
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded. Try again later.",
                )

            request.state.api_key = api_key
            request.state.customer = api_key.customer

            response = await call_next(request)

            if path in PAID_ENDPOINTS and response.status_code < 400:
                record_usage(db_session, api_key_id=api_key.id, endpoint=path)

            return response

        except HTTPException:
            raise
        finally:
            db_session.close()

    def _is_public(self, path: str) -> bool:
        for public in PUBLIC_ENDPOINTS:
            if path == public or path.startswith(public + "/"):
                return True
        return False

    def _check_tier_access(self, tier: str, path: str) -> bool:
        allowed = TIER_ENDPOINT_ACCESS.get(tier, set())
        for endpoint in allowed:
            if path == endpoint or path.startswith(endpoint + "/"):
                return True
        return False

    def _check_rate_limit(self, api_key_id: int, tier: str) -> bool:
        now = time.time()
        window = 60.0
        limit = RATE_LIMITS.get(tier, 60)

        timestamps = self._rate_counters[api_key_id]
        timestamps[:] = [t for t in timestamps if now - t < window]

        if len(timestamps) >= limit:
            return False

        timestamps.append(now)
        return True

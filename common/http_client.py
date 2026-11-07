"""
common.http_client – Async httpx client with timeouts, retries, and backoff.

Usage:
    from common.http_client import get, post

    resp = await post("http://m5_ml:8005/score", json=payload)
    data = resp.json()
"""

import asyncio
from typing import Any

import httpx

from common.auth import service_token_headers
from common.logging_utils import get_logger

log = get_logger(__name__)

# Default timeouts (seconds)
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 10.0
MAX_RETRIES = 3
BACKOFF_BASE = 0.5  # seconds; actual wait = BACKOFF_BASE * 2^attempt


def _build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=5.0, pool=5.0),
        headers=service_token_headers(),
    )


async def _request_with_retry(
    method: str,
    url: str,
    *,
    json: Any = None,
    params: dict | None = None,
    extra_headers: dict | None = None,
) -> httpx.Response:
    """
    Make an HTTP request with exponential-backoff retries.
    Raises httpx.HTTPError on final failure.
    """
    headers = {**(extra_headers or {})}
    last_exc: Exception | None = None

    for attempt in range(MAX_RETRIES):
        try:
            async with _build_client() as client:
                resp = await client.request(
                    method, url, json=json, params=params, headers=headers
                )
                resp.raise_for_status()
                return resp
        except (httpx.HTTPError, httpx.TransportError) as exc:
            last_exc = exc
            wait = BACKOFF_BASE * (2 ** attempt)
            log.warning(
                "http_retry",
                url=url,
                method=method,
                attempt=attempt + 1,
                wait_s=wait,
                error=str(exc),
            )
            await asyncio.sleep(wait)

    raise last_exc  # type: ignore[misc]


async def get(url: str, params: dict | None = None, **kwargs: Any) -> httpx.Response:
    """Async GET with retries."""
    return await _request_with_retry("GET", url, params=params, **kwargs)


async def post(url: str, json: Any = None, **kwargs: Any) -> httpx.Response:
    """Async POST with retries."""
    return await _request_with_retry("POST", url, json=json, **kwargs)


# ── Sync convenience wrappers (for scripts, not for FastAPI handlers) ────────

def get_sync(url: str, params: dict | None = None) -> httpx.Response:
    """Sync GET (use in scripts / CLI tools only)."""
    with httpx.Client(
        timeout=httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=5.0, pool=5.0),
        headers=service_token_headers(),
    ) as client:
        resp = client.get(url, params=params)
        resp.raise_for_status()
        return resp


def post_sync(url: str, json: Any = None) -> httpx.Response:
    """Sync POST (use in scripts / CLI tools only)."""
    with httpx.Client(
        timeout=httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT, write=5.0, pool=5.0),
        headers=service_token_headers(),
    ) as client:
        resp = client.post(url, json=json)
        resp.raise_for_status()
        return resp

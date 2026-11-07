"""
common.auth – Shared-secret service-token authentication (OQ6).

All inter-service HTTP calls MUST include:
    X-Service-Token: <SERVICE_TOKEN>

The token is loaded from the SERVICE_TOKEN environment variable.
It is NEVER committed to the repo (use .env file or Docker env).

Usage (FastAPI dependency):
    from common.auth import require_service_token
    @app.get("/internal/endpoint")
    def endpoint(_: None = Depends(require_service_token)):
        ...

Usage (outbound httpx):
    from common.auth import service_token_headers
    headers = service_token_headers()
"""

import os

from fastapi import Header, HTTPException, status

# Read at import time so misconfiguration fails fast.
_SERVICE_TOKEN: str = os.environ.get("SERVICE_TOKEN", "dev-secret-change-in-prod")

SERVICE_TOKEN_HEADER = "X-Service-Token"


def service_token_headers() -> dict[str, str]:
    """Return the auth header dict for outbound inter-service requests."""
    return {SERVICE_TOKEN_HEADER: _SERVICE_TOKEN}


async def require_service_token(
    x_service_token: str | None = Header(default=None, alias=SERVICE_TOKEN_HEADER),
) -> None:
    """
    FastAPI dependency that enforces the shared-secret token.

    Raise HTTP 401 if the header is absent or incorrect.
    Internal endpoints should declare this as a dependency.
    """
    if x_service_token != _SERVICE_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing service token.",
        )

"""
Dashboard – ZTSP Live Monitoring Dashboard  (port 8080)
========================================================
Static HTML/JS served by FastAPI, live updates via SSE.
No Node.js build step required.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# In Docker: main.py is at /app/main.py, common/ is at /app/common/
# Locally:   main.py is at .../dashboard/main.py, common/ is at ../common/
_HERE = Path(__file__).parent
_PROJECT_ROOT = _HERE if (_HERE / "common").exists() else _HERE.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from common.auth import service_token_headers
from common.config import get_settings
from common.logging_utils import get_logger

log = get_logger(__name__)
settings = get_settings()

app = FastAPI(title="ZTSP Dashboard", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_STATIC_DIR = _HERE / "static"


# ── Data aggregation helpers ──────────────────────────────────────────────────

async def _fetch(url: str) -> Any:
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(url, headers=service_token_headers())
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


async def _get_dashboard_snapshot() -> dict[str, Any]:
    """Fetch live state from all modules."""
    sessions, decisions, actions = await asyncio.gather(
        _fetch(f"{settings.m1_url}/sessions"),
        _fetch(f"{settings.m2_url}/audit/decisions?limit=50"),
        _fetch(f"{settings.m3_url}/audit/actions?limit=50"),
    )
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sessions": sessions or [],
        "decisions": decisions or [],
        "actions": actions or [],
    }


# ── SSE endpoint ─────────────────────────────────────────────────────────────

async def _event_generator() -> AsyncGenerator[str, None]:
    while True:
        try:
            snapshot = await _get_dashboard_snapshot()
            data = json.dumps(snapshot)
            yield f"data: {data}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
        await asyncio.sleep(3)


@app.get("/events")
async def sse_events() -> StreamingResponse:
    """Server-Sent Events endpoint for live dashboard updates."""
    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── API proxy endpoints (for dashboard buttons) ───────────────────────────────

@app.get("/api/sessions")
async def api_sessions() -> Any:
    return await _fetch(f"{settings.m1_url}/sessions") or []


@app.post("/api/scenario/{name}")
async def run_scenario(name: str) -> dict[str, str]:
    """Trigger a named attack scenario directly in background thread."""
    import os
    import importlib

    os.environ["M1_URL"] = os.environ.get("M1_URL", settings.m1_url)
    os.environ["M2_URL"] = os.environ.get("M2_URL", settings.m2_url)
    os.environ["RESOURCE_APP_URL"] = os.environ.get("RESOURCE_APP_URL", settings.resource_app_url)

    scenario_map = {
        "s1": ("testbed.scenarios.s1_credential_misuse", "run_s1"),
        "s2": ("testbed.scenarios.s2_lateral_movement", "run_s2"),
        "s3": ("testbed.scenarios.s3_privilege_escalation", "run_s3"),
        "s4": ("testbed.scenarios.s4_slow_and_low", "run_s4"),
    }

    if name not in scenario_map:
        return {"status": "error", "detail": f"Unknown scenario: {name}"}

    mod_path, func_name = scenario_map[name]

    def _execute() -> None:
        try:
            mod = importlib.import_module(mod_path)
            fn = getattr(mod, func_name)
            fn()
            log.info("scenario_completed", scenario=name)
        except Exception as exc:
            log.error("scenario_failed", scenario=name, error=str(exc))

    asyncio.create_task(asyncio.to_thread(_execute))
    return {"status": "started", "scenario": name}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "dashboard"}


# ── Serve static HTML/JS ─────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard() -> HTMLResponse:
    html_path = _STATIC_DIR / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

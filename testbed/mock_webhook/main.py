"""
testbed/mock_webhook – Mock SIEM / SOC Webhook Receiver (port 8099)
===================================================================
Receives alert_soc payloads from M3 Automated Response engine.
Records alerts in memory and appends to /data/audit/webhook_alerts.jsonl.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Mock SOC Webhook Receiver",
    description="Simulated SOC / SIEM webhook receiver for M3 alert_soc actions.",
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_AUDIT_PATH = Path("/data/audit/webhook_alerts.jsonl")
_alerts: list[dict[str, Any]] = []
_lock = threading.Lock()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mock_webhook", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/webhook")
async def receive_webhook(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        payload = {"raw": (await request.body()).decode("utf-8", errors="replace")}

    record = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    with _lock:
        _alerts.append(record)
        try:
            _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
            with _AUDIT_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass

    return {"status": "received", "count": len(_alerts)}


@app.get("/alerts")
def get_alerts() -> list[dict[str, Any]]:
    with _lock:
        return list(_alerts)


@app.delete("/alerts")
def clear_alerts() -> dict[str, str]:
    with _lock:
        _alerts.clear()
    return {"status": "cleared"}

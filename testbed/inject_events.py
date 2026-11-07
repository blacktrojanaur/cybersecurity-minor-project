"""
testbed/inject_events.py – Telemetry event injector client for ZTSP.
=====================================================================
Reads generated NDJSON events and posts them to M1 (/telemetry/events)
at a controlled rate to simulate live telemetry streaming.

Usage:
    python testbed/inject_events.py --file testbed/data/all_labelled.ndjson --delay 0.05
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.auth import service_token_headers

M1_URL = os.environ.get("M1_URL", "http://localhost:8001")


def inject_events(file_path: Path, delay: float = 0.02, max_events: int = 500) -> dict[str, int]:
    if not file_path.exists():
        print(f"[-] File not found: {file_path}")
        return {"injected": 0, "errors": 0}

    lines = file_path.read_text(encoding="utf-8").strip().splitlines()
    print(f"[*] Loaded {len(lines)} events from {file_path}. Injecting up to {max_events}...")

    headers = service_token_headers()
    injected = 0
    errors = 0

    with httpx.Client(timeout=10.0) as client:
        # First ensure a session exists for the user in M1
        active_sessions: dict[str, str] = {}

        for i, line in enumerate(lines[:max_events]):
            if not line.strip():
                continue
            ev = json.loads(line)
            user_id = ev.get("user_id", "alice")
            device_id = ev.get("device_id", "dev-alice-laptop")
            source_ip = ev.get("source_ip", "10.0.1.10")

            if user_id not in active_sessions:
                try:
                    resp = client.post(
                        f"{M1_URL}/auth/login",
                        json={
                            "user_id": user_id,
                            "device_id": device_id,
                            "source_ip": source_ip,
                        },
                    )
                    if resp.status_code == 200:
                        active_sessions[user_id] = resp.json()["session_id"]
                    else:
                        active_sessions[user_id] = ev.get("session_id", f"sess-{user_id}")
                except Exception:
                    active_sessions[user_id] = ev.get("session_id", f"sess-{user_id}")

            session_id = active_sessions[user_id]

            payload = {
                "session_id": session_id,
                "event_type": ev.get("event_type", "access_request"),
                "resource": ev.get("raw_features", {}).get("resource_path", "/code"),
                "raw_features": ev.get("raw_features", {}),
            }

            try:
                r = client.post(f"{M1_URL}/telemetry/events", json=payload, headers=headers)
                if r.status_code in (200, 202):
                    injected += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

            if delay > 0:
                time.sleep(delay)

            if (i + 1) % 50 == 0:
                print(f"    ├─ Processed {i + 1} events... (Injected: {injected}, Errors: {errors})")

    print(f"[+] Completed: {injected} successfully ingested, {errors} errors.")
    return {"injected": injected, "errors": errors}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZTSP Telemetry Injector")
    parser.add_argument("--file", default="testbed/data/all_labelled.ndjson", help="Path to NDJSON events file")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between events in seconds")
    parser.add_argument("--max-events", type=int, default=200, help="Maximum events to inject")
    args = parser.parse_args()

    inject_events(Path(args.file), delay=args.delay, max_events=args.max_events)


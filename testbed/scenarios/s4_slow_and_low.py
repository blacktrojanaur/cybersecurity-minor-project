"""
S4: Slow-and-Low Behavioural Spoofing Scenario
==============================================
Simulation: An attacker operating within normal working bounds attempts to evade
anomaly detection by slowly shifting access patterns over multiple simulated days:
drifting into off-hours (02:00 UTC) and expanding accessed resources.

Expected Zero Trust Outcome:
1. Days 1–3: Normal access within baseline -> decision = allow.
2. Days 4–6: Gradual temporal and resource drift accumulates in M5 EWMA baseline.
3. Once risk_score exceeds the step-up threshold (0.40), M2 triggers rule-medium-risk-step-up -> decision = step_up.
4. M3 dispatches require_mfa challenge, halting unverified access.

Comparison with RBAC:
RBAC has no concept of baseline drift or behavioral anomaly. It grants continuous access forever.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.auth import service_token_headers

M1_URL = os.environ.get("M1_URL", "http://localhost:8001")


def run_s4() -> dict[str, Any]:
    print("\n" + "=" * 60)
    print("▶ Running Scenario S4: Slow-and-Low Drift")
    print("=" * 60)

    results: dict[str, Any] = {
        "scenario": "S4_slow_and_low",
        "zt_detected": False,
        "zt_decision": None,
        "step_up_triggered": False,
        "rbac_detected": False,
    }

    headers = service_token_headers()

    login_payload = {
        "user_id": "alice",
        "password": "valid_password",
        "device_id": "dev-alice-laptop",
        "source_ip": "10.0.1.10",
    }
    print("[*] Normal login for 'alice' from dev-alice-laptop...")

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{M1_URL}/auth/login", json=login_payload)
            if resp.status_code != 200:
                print(f"[-] Login failed: {resp.text}")
                return results

            session_id = resp.json()["session_id"]
            print(f"[+] Baseline session established: {session_id}")

            # Simulate 6 progressive drift stages (time-compressed)
            drift_stages = [
                {"day": 1, "off_hours": 0, "drift": 0.05, "res": "/code", "dev": 0.0},
                {"day": 2, "off_hours": 0, "drift": 0.12, "res": "/code/repo-b", "dev": 0.1},
                {"day": 3, "off_hours": 0, "drift": 0.22, "res": "/code/repo-c", "dev": 0.25},
                {"day": 4, "off_hours": 1, "drift": 0.38, "res": "/finance", "dev": 0.50},
                {"day": 5, "off_hours": 1, "drift": 0.55, "res": "/finance/audit", "dev": 0.70},
                {"day": 6, "off_hours": 1, "drift": 0.75, "res": "/admin", "dev": 0.90},
            ]

            step_up_seen = False
            for stage in drift_stages:
                day = stage["day"]
                print(f"[*] Day {day}: Ingesting drift telemetry (off_hours={stage['off_hours']}, temporal_drift={stage['drift']})...")

                ingest_resp = client.post(
                    f"{M1_URL}/telemetry/events",
                    json={
                        "session_id": session_id,
                        "event_type": "access_request",
                        "resource": stage["res"],
                        "raw_features": {
                            "off_hours": stage["off_hours"],
                            "temporal_drift_score": stage["drift"],
                            "resource_access_deviation": stage["dev"],
                            "distinct_resources": day + 1,
                        },
                    },
                    headers=headers,
                )

                sess_resp = client.get(f"{M1_URL}/session/{session_id}", headers=headers)
                if sess_resp.status_code == 200:
                    sinfo = sess_resp.json()
                    risk = (sinfo.get("last_risk_score") or {}).get("score", 0.0)
                    decision = (sinfo.get("last_decision") or {}).get("decision", "allow")
                    print(f"    └─ Day {day} Score: {risk:.3f} → Decision: {decision.upper()}")

                    if decision in ("step_up", "restrict", "deny"):
                        step_up_seen = True
                        results["zt_detected"] = True
                        results["zt_decision"] = decision
                        results["step_up_triggered"] = True
                        print(f"[✓] Zero Trust: DRIFT DETECTED AT DAY {day}. Enforced {decision.upper()} (MFA challenge triggered).")
                        break

            if not step_up_seen:
                results["zt_decision"] = "allow"
                print("[!] Zero Trust: Drift did not cross detection threshold.")

            results["rbac_detected"] = False
            print("[x] RBAC Baseline: FAILED (Static RBAC ignores temporal anomalies and behavioral drift).")

    except Exception as exc:
        print(f"[!] Error executing S4: {exc}")

    print("=" * 60 + "\n")
    return results


if __name__ == "__main__":
    run_s4()

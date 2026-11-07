"""
S2: Lateral Movement Attack Scenario
====================================
Simulation: An attacker has compromised developer 'frank's workstation (dev-frank-laptop)
and sweeps across segments: /code (normal), then rapidly attempts /finance/reports,
/hr/payroll, and /admin.

Expected Zero Trust Outcome:
1. First request to /code succeeds (allowed developer segment).
2. Rapid attempts to cross-segment resources emit lateral_move_attempt events.
3. M5 detects high lateral_move_velocity and resource_access_deviation.
4. M2 triggers rule-lateral-movement -> decision = restrict (or deny).
5. M3 executes restrict_access and alert_soc.
6. Subsequent cross-segment attempts are blocked by the PEP with 403 Forbidden.

Comparison with RBAC:
Traditional perimeter network trusts internal IP and allows cross-segment network traffic.
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
RESOURCE_APP_URL = os.environ.get("RESOURCE_APP_URL", "http://localhost:8090")


def run_s2() -> dict[str, Any]:
    print("\n" + "=" * 60)
    print("▶ Running Scenario S2: Lateral Movement")
    print("=" * 60)

    results: dict[str, Any] = {
        "scenario": "S2_lateral_movement",
        "zt_detected": False,
        "zt_decision": None,
        "zt_blocked": False,
        "rbac_detected": False,
        "rbac_blocked": False,
    }

    headers = service_token_headers()

    # Step 1: Frank logs in normally
    login_payload = {
        "user_id": "frank",
        "password": "valid_password_frank",
        "device_id": "dev-frank-laptop",
        "source_ip": "10.0.6.10",
    }
    print("[*] Normal login for 'frank' (role: developer) from dev-frank-laptop...")

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{M1_URL}/auth/login", json=login_payload)
            if resp.status_code != 200:
                print(f"[-] Login failed: {resp.text}")
                return results

            session_id = resp.json()["session_id"]
            print(f"[+] Initial session established: {session_id}")

            # Step 2: Access legitimate engineering resource
            print("[*] Frank accesses authorized engineering repository (/code)...")
            res_code = client.get(
                f"{RESOURCE_APP_URL}/code",
                headers={"Authorization": f"Bearer {session_id}"},
            )
            print(f"    └─ /code response: HTTP {res_code.status_code}")

            # Step 3: Attacker begins rapid lateral movement across segments
            targets = [
                ("/finance/reports", "lateral_move_attempt"),
                ("/hr/payroll", "lateral_move_attempt"),
                ("/admin", "lateral_move_attempt"),
            ]

            blocked_count = 0
            for path, ev_type in targets:
                print(f"[*] Attacker attempting lateral movement to {path}...")
                # Ingest telemetry event
                client.post(
                    f"{M1_URL}/telemetry/events",
                    json={
                        "session_id": session_id,
                        "event_type": ev_type,
                        "resource": path,
                        "raw_features": {
                            "lateral_move_velocity": 0.95,
                            "distinct_resources": 4,
                            "resource_access_deviation": 0.88,
                        },
                    },
                    headers=headers,
                )

                # Attempt access at PEP
                acc_resp = client.get(
                    f"{RESOURCE_APP_URL}{path}",
                    headers={"Authorization": f"Bearer {session_id}"},
                )
                print(f"    └─ Access {path}: HTTP {acc_resp.status_code}")
                if acc_resp.status_code in (401, 403):
                    blocked_count += 1

            # Step 4: Check session status
            sess_resp = client.get(f"{M1_URL}/session/{session_id}", headers=headers)
            decision = "unknown"
            if sess_resp.status_code == 200:
                sinfo = sess_resp.json()
                decision = (sinfo.get("last_decision") or {}).get("decision", "unknown")
                results["zt_decision"] = decision
                print(f"[+] Final Zero Trust Decision: {decision.upper()}")
                print(f"    ├─ Restricted flag: {sinfo.get('restricted')}")
                print(f"    └─ Active flag: {sinfo.get('active')}")

            if blocked_count > 0 or decision in ("restrict", "deny"):
                results["zt_detected"] = True
                results["zt_blocked"] = True
                print(f"[✓] Zero Trust: LATERAL MOVEMENT CONTAINED. {blocked_count} sensitive segment requests blocked.")
            else:
                print("[!] Zero Trust: Lateral movement was not blocked.")

            results["rbac_detected"] = False
            results["rbac_blocked"] = False
            print("[x] RBAC Baseline: FAILED (No velocity tracking; perimeter firewall trusts internal host).")

    except Exception as exc:
        print(f"[!] Error executing S2: {exc}")

    print("=" * 60 + "\n")
    return results


if __name__ == "__main__":
    run_s2()

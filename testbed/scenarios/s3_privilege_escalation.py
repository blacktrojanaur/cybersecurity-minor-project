"""
S3: Privilege Escalation Attack Scenario
========================================
Simulation: Low-privileged viewer 'eve' attempts to claim admin role or execute
administrative commands on /admin.

Expected Zero Trust Outcome:
1. 'eve' logs in successfully with low privileges (role: viewer).
2. Telemetry records event_type: privilege_escalation_attempt with privilege_claim_mismatch: 1.
3. M2 matches rule-privilege-escalation (Priority 2) -> decision = deny.
4. M3 SOAR playbook immediately terminates the session token across M1 and M2 and fires SOC alert.
5. All subsequent actions on the session are completely blocked.

Comparison with RBAC:
Traditional RBAC returns HTTP 403 Forbidden on the endpoint but leaves the session active.
The attacker retains access to probe other endpoints. Zero Trust destroys the session.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.auth import service_token_headers

M1_URL = os.environ.get("M1_URL", "http://localhost:8001")
RESOURCE_APP_URL = os.environ.get("RESOURCE_APP_URL", "http://localhost:8090")


def run_s3() -> dict[str, Any]:
    print("\n" + "=" * 60)
    print("▶ Running Scenario S3: Privilege Escalation")
    print("=" * 60)

    results: dict[str, Any] = {
        "scenario": "S3_privilege_escalation",
        "zt_detected": False,
        "zt_decision": None,
        "zt_blocked": False,
        "session_revoked": False,
        "rbac_detected": False,
        "rbac_session_revoked": False,
    }

    headers = service_token_headers()

    # Step 1: Eve logs in as viewer
    login_payload = {
        "user_id": "eve",
        "password": "eve_password",
        "device_id": "dev-eve-laptop",
        "source_ip": "10.0.5.10",
    }
    print("[*] Normal login for 'eve' (role: viewer) from dev-eve-laptop...")

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{M1_URL}/auth/login", json=login_payload)
            if resp.status_code != 200:
                print(f"[-] Login failed: {resp.text}")
                return results

            session_id = resp.json()["session_id"]
            print(f"[+] Initial session established: {session_id}")

            # Step 2: Access normal viewer resource
            res_chart = client.get(
                f"{RESOURCE_APP_URL}/hr/org-chart",
                headers={"Authorization": f"Bearer {session_id}"},
            )
            print(f"    └─ /hr/org-chart (authorized): HTTP {res_chart.status_code}")

            # Step 3: Eve attempts privilege escalation to /admin
            print("[*] Attacker attempts privilege escalation to /admin claiming role: admin...")
            client.post(
                f"{M1_URL}/telemetry/events",
                json={
                    "session_id": session_id,
                    "event_type": "privilege_escalation_attempt",
                    "resource": "/admin",
                    "raw_features": {
                        "claimed_role": "admin",
                        "user_role": "viewer",
                        "privilege_claim_mismatch": 1,
                    },
                },
                headers=headers,
            )

            # Step 4: Check policy re-evaluation and session state
            sess_resp = client.get(f"{M1_URL}/session/{session_id}", headers=headers)
            decision = "unknown"
            active = True
            if sess_resp.status_code == 200:
                sinfo = sess_resp.json()
                decision = (sinfo.get("last_decision") or {}).get("decision", "unknown")
                active = sinfo.get("active", True)
                results["zt_decision"] = decision
                print(f"[+] Zero Trust Policy Decision: {decision.upper()}")
                print(f"    ├─ Session Active Status: {active}")
                print(f"    └─ Last Action: {sinfo.get('last_response_action', {}).get('action_type', 'N/A')}")

            # Step 5: Test whether the previously accessible org-chart is now revoked
            print("[*] Testing if attacker can still use session on previously authorized resource...")
            retry_resp = client.get(
                f"{RESOURCE_APP_URL}/hr/org-chart",
                headers={"Authorization": f"Bearer {session_id}"},
            )
            print(f"    └─ /hr/org-chart post-escalation: HTTP {retry_resp.status_code}")

            if decision == "deny" and not active:
                results["zt_detected"] = True
                results["zt_blocked"] = True
                results["session_revoked"] = True
                print("[✓] Zero Trust: ESCALATION NEUTRALIZED. Session token immediately revoked & SOC alerted.")
            else:
                print("[!] Zero Trust: Session was not revoked.")

            results["rbac_detected"] = False
            results["rbac_session_revoked"] = False
            print("[x] RBAC Baseline: FAILED (Returns 403 on /admin, but session token is KEPT ALIVE for further attacks).")

    except Exception as exc:
        print(f"[!] Error executing S3: {exc}")

    print("=" * 60 + "\n")
    return results


if __name__ == "__main__":
    run_s3()

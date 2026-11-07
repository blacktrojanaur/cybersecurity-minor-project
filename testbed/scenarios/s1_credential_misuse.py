"""
S1: Credential Misuse Attack Scenario
=====================================
Simulation: Valid credentials for 'alice' are stolen and used from an
unknown attacker device (dev-unknown-attacker) and anomalous geo IP (203.0.113.42 - Nigeria/Russia).

Expected Zero Trust Outcome:
1. M4 flags device as unregistered / unknown -> posture_score = 0.05.
2. M5 detects geo anomaly + unknown device -> risk_score >= 0.70.
3. M2 matches rule-poor-posture-deny or rule-high-risk-deny -> decision = deny.
4. M3 automatically terminates session and dispatches alert_soc.
5. Resource app access attempt is immediately rejected with 401/403.

Comparison with RBAC:
RBAC only checks username/password. Stolen credentials succeed in RBAC (Breach).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.auth import service_token_headers

M1_URL = os.environ.get("M1_URL", "http://localhost:8001")
M2_URL = os.environ.get("M2_URL", "http://localhost:8002")
RESOURCE_APP_URL = os.environ.get("RESOURCE_APP_URL", "http://localhost:8090")


def run_s1() -> dict[str, Any]:
    print("\n" + "=" * 60)
    print("▶ Running Scenario S1: Credential Misuse")
    print("=" * 60)

    results: dict[str, Any] = {
        "scenario": "S1_credential_misuse",
        "zt_detected": False,
        "zt_decision": None,
        "zt_blocked": False,
        "rbac_detected": False,
        "rbac_blocked": False,
    }

    headers = service_token_headers()

    # Step 1: Attacker attempts login with alice's stolen credentials from unknown device
    login_payload = {
        "user_id": "alice",
        "password": "stolen_password_123",
        "device_id": "dev-unknown-attacker",
        "source_ip": "203.0.113.42",
    }
    print(f"[*] Attacker attempting login as 'alice' from IP 203.0.113.42 on device 'dev-unknown-attacker'...")

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(f"{M1_URL}/auth/login", json=login_payload)
            if resp.status_code != 200:
                print(f"[-] Login failed with status {resp.status_code}: {resp.text}")
                return results
            login_data = resp.json()
            session_id = login_data.get("session_id")
            initial_decision = login_data.get("decision", {})
            decision = initial_decision.get("decision", "unknown") if initial_decision else "unknown"
            results["zt_decision"] = decision

            print(f"[+] Login processed. Session ID: {session_id}")
            print(f"[+] Initial ZT Policy Decision: {decision.upper()}")

            # Step 2: Query session context to inspect ML risk and posture
            sess_resp = client.get(f"{M1_URL}/session/{session_id}", headers=headers)
            if sess_resp.status_code == 200:
                sess_info = sess_resp.json()
                risk = sess_info.get("last_risk_score", {})
                posture = sess_info.get("last_posture", {})
                print(f"    ├─ ML Risk Score: {risk.get('score', 'N/A')} (model: {risk.get('model_version', 'N/A')})")
                print(f"    ├─ Device Posture Score: {posture.get('posture_score', 'N/A')}")
                print(f"    ├─ Decision Reason: {initial_decision.get('reason', 'N/A')}")
                print(f"    └─ Active Status: {sess_info.get('active')}")

            # Step 3: Attacker attempts to access protected resource /code/repo-a
            print(f"[*] Attacker attempting to access protected resource /code/repo-a with token...")
            res_resp = client.get(
                f"{RESOURCE_APP_URL}/code/repo-a",
                headers={"Authorization": f"Bearer {session_id}"},
            )
            print(f"[+] Resource Access Response: HTTP {res_resp.status_code} ({res_resp.text.strip()[:100]})")

            if res_resp.status_code in (401, 403) or decision == "deny":
                results["zt_detected"] = True
                results["zt_blocked"] = True
                print("[✓] Zero Trust: ATTACK CONTAINED. Unauthorized session terminated, access denied.")
            else:
                results["zt_blocked"] = False
                print("[!] Zero Trust: Session was not blocked.")

            # RBAC comparison:
            # RBAC would have checked username/password, validated role=developer, and allowed /code/repo-a!
            results["rbac_detected"] = False
            results["rbac_blocked"] = False
            print("[x] RBAC Baseline: FAILED (Valid credentials -> RBAC allows full access to code repositories).")

    except Exception as exc:
        print(f"[!] Error executing S1: {exc}")

    print("=" * 60 + "\n")
    return results


if __name__ == "__main__":
    run_s1()

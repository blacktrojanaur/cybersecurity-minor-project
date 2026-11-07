"""
run_local.py – Self-Healing Local Multi-Service Launcher (Zero Docker Needed)
=============================================================================
1. Frees ports if previously held by Docker or zombie processes.
2. Launches all 8 ZTSP microservices as background processes on localhost.
3. Actively checks each service's /health endpoint until verified healthy.
4. Executes the live attack scenarios (S1–S4) vs RBAC baseline.
5. Launches the Live Web Dashboard in your default browser.

Usage:
    python run_local.py
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
PYTHON_EXE = sys.executable

SERVICES = [
    ("Mock Webhook", "testbed.mock_webhook.main:app", 8099),
    ("M4 Posture",   "m4_posture.main:app",          8004),
    ("M5 ML Engine", "m5_ml.main:app",               8005),
    ("M3 Response",  "m3_response.main:app",         8003),
    ("M2 Policy",    "m2_policy.main:app",           8002),
    ("M1 Identity",  "m1_identity.main:app",         8001),
    ("Resource App", "testbed.resource_app.main:app",8090),
    ("Dashboard",    "dashboard.main:app",           8080),
]


def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def free_ports() -> None:
    """Free any ports held by Docker containers or orphaned processes."""
    busy = [port for _, _, port in SERVICES if is_port_in_use(port)]
    if busy:
        print(f"[*] Ports currently occupied: {busy}")
        print("    Stopping any background Docker containers...")
        try:
            subprocess.run(["docker", "compose", "down"], cwd=str(PROJECT_ROOT), capture_output=True, timeout=10)
        except Exception:
            pass

        # If on Windows, kill any orphaned Python uvicorn processes
        if sys.platform == "win32":
            for port in busy:
                try:
                    cmd = f'netstat -ano | findstr :{port}'
                    out = subprocess.check_output(cmd, shell=True).decode()
                    for line in out.strip().splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and "LISTENING" in line:
                            pid = parts[-1]
                            if pid != "0" and int(pid) != os.getpid():
                                subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
                except Exception:
                    pass
        time.sleep(1.5)


def wait_for_health(port: int, name: str, timeout: float = 12.0) -> bool:
    """Poll a service's /health endpoint until it returns HTTP 200."""
    url = f"http://127.0.0.1:{port}/health"
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck", "Connection": "close"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                resp.read()
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main() -> None:
    print("\n" + "=" * 65)
    print("  ZERO TRUST SECURITY PLATFORM — SELF-VERIFYING RUNNER")
    print("=" * 65 + "\n")

    free_ports()

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["SERVICE_TOKEN"] = "dev-secret-change-in-prod"
    env["M1_URL"] = "http://127.0.0.1:8001"
    env["M2_URL"] = "http://127.0.0.1:8002"
    env["M3_URL"] = "http://127.0.0.1:8003"
    env["M4_URL"] = "http://127.0.0.1:8004"
    env["M5_URL"] = "http://127.0.0.1:8005"
    env["RESOURCE_APP_URL"] = "http://127.0.0.1:8090"
    env["WEBHOOK_URL"] = "http://127.0.0.1:8099/webhook"

    procs: list[subprocess.Popen] = []

    try:
        print("[*] Launching 8 microservices on localhost...")
        for name, app_str, port in SERVICES:
            cmd = [
                PYTHON_EXE, "-m", "uvicorn", app_str,
                "--host", "127.0.0.1",
                "--port", str(port),
                "--log-level", "warning",
            ]
            p = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), env=env)
            procs.append(p)
            print(f"  -> Starting {name:<18} (port {port})...")
            time.sleep(0.3)

        print("\n[*] Verifying health status of each microservice...")
        all_healthy = True
        for name, _, port in SERVICES:
            healthy = wait_for_health(port, name)
            if healthy:
                print(f"  [✓] {name:<18} is HEALTHY on port {port}")
            else:
                print(f"  [✗] {name:<18} FAILED to respond on port {port}")
                all_healthy = False

        if not all_healthy:
            print("\n[!] One or more services failed to start. Check dependencies or logs above.")
            return

        print("\n" + "#" * 65)
        print("  ALL SERVICES HEALTHY — TRIGGERING ATTACK SCENARIOS")
        print("#" * 65)

        from testbed.scenarios.run_all import run_all
        run_all()

        print("\n" + "=" * 65)
        print("  ZTSP ALL SERVICES ACTIVE & OPERATIONAL!")
        print("  Live Web Dashboard: http://localhost:8080")
        print("  Press Ctrl+C anytime to stop all services.")
        print("=" * 65 + "\n")

        webbrowser.open("http://localhost:8080")

        # Keep server alive for user
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Stopping all microservices...")
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        print("[+] All services stopped cleanly.")


if __name__ == "__main__":
    main()

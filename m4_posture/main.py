"""
M4 – Vulnerability & Posture Integration  (port 8004)
======================================================
Phase 2: Real device inventory, posture formula from YAML weights,
compliance control mapping (NIST SP 800-207 aligned [TO VERIFY]),
and a local CVE sample feed.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.logging_utils import get_logger
from common.auth import require_service_token

log = get_logger(__name__)

app = FastAPI(
    title="M4 – Vulnerability & Posture Integration",
    description="Device posture scoring with YAML-driven weights and compliance control mapping.",
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Data directories ─────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).parent / "data"
_CONFIG_DIR = Path(__file__).parent / "config"

# ── Load device registry ─────────────────────────────────────────────────────

def _load_devices() -> dict[str, dict]:
    path = _DATA_DIR / "devices.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {d["device_id"]: d for d in data.get("devices", [])}


_DEVICES: dict[str, dict] = _load_devices()

# ── Load posture weights from YAML (OQ7) ─────────────────────────────────────

def _load_weights() -> dict[str, float]:
    path = _CONFIG_DIR / "posture_weights.yaml"
    defaults = {
        "patch_level": 0.40,
        "os_compliant": 0.30,
        "antivirus_active": 0.20,
        "vuln_penalty": 0.10,
        "mfa_enrolled_bonus": 0.05,
        "disk_encrypted_bonus": 0.05,
        "critical_vuln_cap": 0.30,
        "patch_age_penalty_per_30d": 0.05,
        "max_patch_age_days": 365,
    }
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        defaults.update(loaded)
    return defaults


_WEIGHTS = _load_weights()

# ── Posture cache (5-min TTL) ─────────────────────────────────────────────────

_posture_cache: dict[str, tuple[dict, float]] = {}
_cache_lock = threading.Lock()
CACHE_TTL = 300.0  # 5 minutes


# ── NIST SP 800-207 control mapping [TO VERIFY] ───────────────────────────────

CONTROL_MAP = {
    "patch_level": {
        "control": "NIST SP 800-207 §3.3 – Device integrity considered before access [TO VERIFY]",
        "description": "OS and application patches must be current.",
    },
    "os_compliant": {
        "control": "NIST SP 800-207 §3.4 – Access determined by dynamic policy [TO VERIFY]",
        "description": "OS version must meet minimum compliance baseline.",
    },
    "antivirus_active": {
        "control": "NIST CSF PR.PT-3 – Principle of least functionality [TO VERIFY]",
        "description": "Approved AV/EDR must be running and updated.",
    },
    "mfa_enrolled": {
        "control": "NIST SP 800-207 §3.6 – Authentication dynamically enforced [TO VERIFY]",
        "description": "MFA enrollment required for all managed devices.",
    },
    "disk_encrypted": {
        "control": "NIST SP 800-207 §3.1 – All data sources treated as resources [TO VERIFY]",
        "description": "Device storage must be encrypted at rest.",
    },
    "critical_vuln": {
        "control": "NIST SP 800-207 §3.3 – Device integrity considered before access [TO VERIFY]",
        "description": "No critical (CVSS 9.0+) vulnerabilities permitted.",
    },
}


# ── Posture computation ───────────────────────────────────────────────────────

def _compute_posture(device: dict) -> dict[str, Any]:
    w = _WEIGHTS
    patch_age = device.get("os_patch_age_days", 0)
    patch_level = max(0.0, 1.0 - (patch_age / w["max_patch_age_days"]))
    os_ok = device.get("os_patch_age_days", 999) < 180  # OS compliant if patched within 6 months
    av_ok = device.get("av_active", False)
    mfa_ok = device.get("mfa_enrolled", False)
    disk_ok = device.get("disk_encrypted", False)
    vuln_count = device.get("known_vulns", 0)
    crit_vulns = 1 if vuln_count > 10 else 0  # simplified: >10 vulns → critical risk

    vuln_penalty_ratio = min(vuln_count / 20.0, 1.0)

    score = (
        patch_level * w["patch_level"]
        + (1.0 if os_ok else 0.0) * w["os_compliant"]
        + (1.0 if av_ok else 0.0) * w["antivirus_active"]
        + (1.0 - vuln_penalty_ratio) * w["vuln_penalty"]
        + (w["mfa_enrolled_bonus"] if mfa_ok else 0.0)
        + (w["disk_encrypted_bonus"] if disk_ok else 0.0)
    )
    score = max(0.0, min(1.0, score))

    # Critical vuln hard cap
    if crit_vulns > 0:
        score = min(score, w["critical_vuln_cap"])

    # Identify failed controls
    failed_controls = []
    if patch_level < 0.5:
        failed_controls.append(CONTROL_MAP["patch_level"])
    if not os_ok:
        failed_controls.append(CONTROL_MAP["os_compliant"])
    if not av_ok:
        failed_controls.append(CONTROL_MAP["antivirus_active"])
    if not mfa_ok:
        failed_controls.append(CONTROL_MAP["mfa_enrolled"])
    if not disk_ok:
        failed_controls.append(CONTROL_MAP["disk_encrypted"])
    if crit_vulns > 0:
        failed_controls.append(CONTROL_MAP["critical_vuln"])

    return {
        "schema_version": "1.0",
        "device_id": device["device_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "patch_level": round(patch_level, 4),
        "vuln_count": vuln_count,
        "critical_vuln_count": crit_vulns,
        "os_compliant": os_ok,
        "antivirus_active": av_ok,
        "posture_score": round(score, 4),
        # Extra fields (not in contract schema, sent in metadata separately)
        "_failed_controls": failed_controls,
        "_mfa_enrolled": mfa_ok,
        "_disk_encrypted": disk_ok,
        "_patch_age_days": patch_age,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "module": "m4_posture", "version": "2.0.0",
            "devices_registered": str(len(_DEVICES))}


@app.get("/posture/{device_id}", tags=["Posture"])
def get_posture(
    device_id: str,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Retrieve posture assessment for a device.
    Results are cached for 5 minutes (CACHE_TTL).
    Unknown devices return posture_score=0.0 (maximum risk).
    """
    with _cache_lock:
        cached = _posture_cache.get(device_id)
        if cached and (time.monotonic() - cached[1]) < CACHE_TTL:
            return cached[0]

    device = _DEVICES.get(device_id)
    if not device:
        # Unknown device: maximum risk
        result: dict[str, Any] = {
            "schema_version": "1.0",
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "patch_level": 0.0,
            "vuln_count": 99,
            "critical_vuln_count": 1,
            "os_compliant": False,
            "antivirus_active": False,
            "posture_score": 0.0,
            "_failed_controls": list(CONTROL_MAP.values()),
            "_unknown_device": True,
        }
    else:
        result = _compute_posture(device)

    with _cache_lock:
        _posture_cache[device_id] = (result, time.monotonic())

    log.info("posture_computed", device_id=device_id, score=result["posture_score"])
    return result


@app.post("/posture/scan", status_code=202, tags=["Posture"])
def trigger_scan(
    body: dict,
    _: None = Depends(require_service_token),
) -> dict[str, str]:
    """Queue an on-demand posture re-assessment (invalidates cache)."""
    device_id = body.get("device_id", "")
    with _cache_lock:
        _posture_cache.pop(device_id, None)
    return {"status": "scan_queued", "device_id": device_id}


@app.get("/posture/{device_id}/compliance", tags=["Compliance"])
def get_compliance(
    device_id: str,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """Return detailed compliance state including failed NIST controls."""
    posture = get_posture(device_id, _)
    return {
        "device_id": device_id,
        "posture_score": posture["posture_score"],
        "failed_controls": posture.get("_failed_controls", []),
        "all_controls": list(CONTROL_MAP.keys()),
        "compliant": posture["posture_score"] >= 0.6,
    }


@app.get("/devices", tags=["Inventory"])
def list_devices(
    _: None = Depends(require_service_token),
) -> list[dict[str, Any]]:
    """Return all registered devices with their posture summaries."""
    results = []
    for did in _DEVICES:
        p = get_posture(did, _)
        results.append({
            "device_id": did,
            "owner": _DEVICES[did].get("owner"),
            "os": _DEVICES[did].get("os"),
            "posture_score": p["posture_score"],
        })
    return results

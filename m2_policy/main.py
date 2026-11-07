"""
M2 – Policy Enforcement & Micro-segmentation  (port 8002)
==========================================================
Phase 2: Real YAML-driven rule engine (PDP), per-request enforcement (PEP),
append-only audit log, segment-based access control, and enforcement API for M3.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.logging_utils import get_logger
from common.auth import require_service_token

log = get_logger(__name__)

app = FastAPI(
    title="M2 – Policy Enforcement & Micro-segmentation",
    description="YAML rule engine (PDP), enforcement API, and audit log.",
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Config ────────────────────────────────────────────────────────────────────

_CONFIG_DIR = Path(__file__).parent / "config"
_AUDIT_PATH = Path("/data/audit/m2_decisions.jsonl")


def _load_rules() -> tuple[list[dict], str]:
    path = _CONFIG_DIR / "rules.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rules = sorted(data.get("rules", []), key=lambda r: r.get("priority", 99))
    version = data.get("rule_version", "1.0")
    return rules, version


def _load_segments() -> list[dict]:
    path = _CONFIG_DIR / "segments.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("segments", [])


_rules, _rule_version = _load_rules()
_segments = _load_segments()
_rules_lock = threading.Lock()
_last_reload = time.monotonic()
RELOAD_INTERVAL = 30.0  # hot-reload every 30 s


def _maybe_reload() -> None:
    global _rules, _rule_version, _last_reload
    if time.monotonic() - _last_reload > RELOAD_INTERVAL:
        try:
            new_rules, new_ver = _load_rules()
            with _rules_lock:
                _rules, _rule_version = new_rules, new_ver
            _last_reload = time.monotonic()
        except Exception as exc:
            log.warning("rules_reload_failed", error=str(exc))


# ── Decision cache ────────────────────────────────────────────────────────────

_decision_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()

# ── Audit log ────────────────────────────────────────────────────────────────

def _audit(record: dict) -> None:
    try:
        _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        log.warning("audit_write_failed", error=str(exc))


# ── Rule engine ───────────────────────────────────────────────────────────────

def _evaluate_rules(
    risk_score: float,
    posture_score: float,
    risk_payload: dict | None = None,
    posture_payload: dict | None = None,
) -> tuple[str, int, str, list[str]]:
    """
    Evaluate policy rules in priority order.
    Returns (decision, ttl_seconds, reason, applied_policy_ids).
    """
    _maybe_reload()
    with _rules_lock:
        rules = list(_rules)
        version = _rule_version

    # Extract useful fields from payloads
    critical_vuln = int((posture_payload or {}).get("critical_vuln_count", 0))
    event_type = str((risk_payload or {}).get("_event_type", ""))

    applied = []
    for rule in rules:
        cond = rule.get("conditions", {})
        matched = True
        for key, val in cond.items():
            if key == "risk_score_gte" and risk_score < float(val):
                matched = False; break
            elif key == "risk_score_lt" and risk_score >= float(val):
                matched = False; break
            elif key == "posture_score_lt" and posture_score >= float(val):
                matched = False; break
            elif key == "posture_score_gte" and posture_score < float(val):
                matched = False; break
            elif key == "critical_vuln_count_gt" and critical_vuln <= int(val):
                matched = False; break
            elif key == "event_type_eq" and event_type != str(val):
                matched = False; break
        if matched:
            applied.append(rule["id"])
            decision = rule["decision"]
            ttl = rule["ttl_seconds"]
            reason = (
                f"Rule '{rule['id']}' [{version}]: {rule['description']}. "
                f"risk={risk_score:.4f}, posture={posture_score:.4f}"
            )
            return decision, ttl, reason, applied

    # Fallback (should never reach here)
    return "allow", 300, "Default allow.", []


# ── Segment enforcement ───────────────────────────────────────────────────────

def _check_segment(resource_path: str, user_role: str) -> bool:
    """Return True if user_role is allowed to access resource_path."""
    for seg in _segments:
        if resource_path.startswith(seg["path_prefix"]):
            return user_role in seg.get("allowed_roles", [])
    return True  # unlisted paths are open


# ── Request models ────────────────────────────────────────────────────────────

class EvaluationRequest(BaseModel):
    session_id: str
    risk_score: float
    posture_score: float
    risk_score_payload: dict[str, Any] | None = None
    posture_score_payload: dict[str, Any] | None = None


class EnforceRequest(BaseModel):
    session_id: str
    resource_path: str
    user_role: str = "viewer"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "module": "m2_policy", "version": "2.0.0",
            "rule_version": _rule_version, "rules_count": str(len(_rules))}


@app.post("/policy/evaluate", tags=["Policy"])
def evaluate_policy(
    request: EvaluationRequest,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Policy Decision Point (PDP): evaluate rules and return a PolicyDecision.
    Conforming to contracts/policy_decision.schema.json.
    """
    decision, ttl, reason, applied = _evaluate_rules(
        request.risk_score, request.posture_score,
        request.risk_score_payload, request.posture_score_payload,
    )
    result = {
        "schema_version": "1.0",
        "session_id": request.session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "reason": reason,
        "ttl_seconds": ttl,
        "applied_policies": applied,
    }
    with _cache_lock:
        _decision_cache[request.session_id] = result
    _audit({**result, "rule_version": _rule_version})
    log.info("decision", session_id=request.session_id, decision=decision,
             risk=request.risk_score, posture=request.posture_score)
    return result


@app.get("/policy/{session_id}", tags=["Policy"])
def get_policy(
    session_id: str,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """Retrieve the cached policy decision for a session."""
    with _cache_lock:
        cached = _decision_cache.get(session_id)
    if not cached:
        raise HTTPException(status_code=404,
                            detail=f"No cached decision for session {session_id!r}")
    return cached


@app.post("/policy/enforce", tags=["Enforcement"])
def enforce_access(
    request: EnforceRequest,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Policy Enforcement Point (PEP): check whether a session can access a resource.
    Combines the cached decision with segment-based role check.
    """
    with _cache_lock:
        cached = _decision_cache.get(request.session_id)

    # If no cached decision, default to deny (zero-trust: never allow without evaluation)
    decision = (cached or {}).get("decision", "deny")
    reason = (cached or {}).get("reason", "No policy evaluation found; defaulting to deny.")

    # Segment check (even for 'allow' decisions)
    segment_ok = _check_segment(request.resource_path, request.user_role)
    if not segment_ok:
        decision = "deny"
        reason = (f"Micro-segmentation: role '{request.user_role}' "
                  f"not permitted in segment for '{request.resource_path}'.")

    # Restrict means read-only (no lateral movement allowed)
    if decision == "restrict" and request.resource_path.startswith("/admin"):
        decision = "deny"
        reason = "Restricted session cannot access admin segment."

    result = {
        "session_id": request.session_id,
        "resource_path": request.resource_path,
        "user_role": request.user_role,
        "decision": decision,
        "reason": reason,
        "segment_ok": segment_ok,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _audit({**result, "event": "enforcement"})
    return result


@app.post("/enforcement/terminate", tags=["Enforcement"])
def terminate_session_enforcement(
    body: dict,
    _: None = Depends(require_service_token),
) -> dict[str, str]:
    """Called by M3 to enforce session termination in the decision cache."""
    session_id = body.get("session_id", "")
    with _cache_lock:
        if session_id in _decision_cache:
            _decision_cache[session_id]["decision"] = "deny"
            _decision_cache[session_id]["reason"] = "Session terminated by M3 response action."
    log.info("enforcement_terminate", session_id=session_id)
    return {"status": "terminated", "session_id": session_id}


@app.get("/segments", tags=["Segmentation"])
def get_segments(
    _: None = Depends(require_service_token),
) -> list[dict]:
    """Return the logical micro-segmentation map."""
    return _segments


@app.get("/audit/decisions", tags=["Audit"])
def get_audit_log(
    limit: int = 100,
    _: None = Depends(require_service_token),
) -> list[dict]:
    """Return recent audit log entries."""
    if not _AUDIT_PATH.exists():
        return []
    lines = _AUDIT_PATH.read_text(encoding="utf-8").strip().splitlines()
    records = [json.loads(ln) for ln in lines if ln.strip()]
    return records[-limit:]

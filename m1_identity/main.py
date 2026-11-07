"""
M1 – Identity & Context Engine  (port 8001)
============================================
Phase 2: Real session store, OIDC-like login, telemetry emitter,
TTL-driven continuous re-evaluation loop, and closed-loop wiring.
"""

import asyncio
import json
import time
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.logging_utils import get_logger
from common.auth import require_service_token, service_token_headers
from common.config import get_settings

log = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="M1 – Identity & Context Engine",
    description="Session management, telemetry emission, and TTL-driven re-evaluation loop.",
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Load user/device directory ────────────────────────────────────────────────

_DATA_DIR = Path(__file__).parent / "data"

def _load_users() -> dict[str, dict]:
    path = _DATA_DIR / "users.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {u["user_id"]: u for u in data.get("users", [])}


_USERS: dict[str, dict] = _load_users()

# ── Session store ────────────────────────────────────────────────────────────

class SessionState:
    """In-memory per-session state."""
    def __init__(self, session_id: str, user_id: str, device_id: str,
                 source_ip: str, geo: dict):
        self.session_id = session_id
        self.user_id = user_id
        self.device_id = device_id
        self.source_ip = source_ip
        self.geo = geo
        self.created_at = datetime.now(timezone.utc)
        self.last_event: dict | None = None
        self.last_risk_score: dict | None = None
        self.last_posture: dict | None = None
        self.last_decision: dict | None = None
        self.last_response_action: dict | None = None
        self.ttl_deadline: float = 0.0
        self.active = True
        self.mfa_required = False
        self.restricted = False


_sessions: dict[str, SessionState] = {}
_sessions_lock = threading.Lock()

# ── Audit log ────────────────────────────────────────────────────────────────

_AUDIT_PATH = Path("/data/audit/m1_events.jsonl")


def _audit(record: dict) -> None:
    try:
        _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        log.warning("audit_write_failed", error=str(exc))


# ── Geo-IP helper (synthetic: IP prefix → country) ───────────────────────────

def _geo_from_ip(ip: str, user_id: str | None = None) -> dict:
    """
    Synthetic geo lookup.  For known user IPs returns their home geo.
    For external IPs uses IP range heuristics.
    """
    if user_id and user_id in _USERS:
        user = _USERS[user_id]
        known_ips = user.get("normal_ips", [])
        if ip in known_ips:
            c, ci, la, lo = user["home_geo"]
            return {"country": c, "city": ci, "lat": la, "lon": lo}
    # Heuristic: 10.x = internal India, 203.x = external
    if ip.startswith("10."):
        return {"country": "IN", "city": "Internal", "lat": 20.59, "lon": 78.96}
    return {"country": "XX", "city": "Unknown", "lat": 0.0, "lon": 0.0}


# ── HTTP helpers ──────────────────────────────────────────────────────────────

async def _call_m4_posture(device_id: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"{settings.m4_url}/posture/{device_id}",
                headers=service_token_headers(),
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("m4_call_failed", device_id=device_id, error=str(exc))
        return None


async def _call_m5_score(session_id: str, telemetry: dict, posture: dict | None) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                f"{settings.m5_url}/score",
                json={"session_id": session_id, "telemetry_event": telemetry,
                      "posture_score": posture},
                headers=service_token_headers(),
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("m5_call_failed", session_id=session_id, error=str(exc))
        return None


async def _call_m2_evaluate(session_id: str, risk: float, posture: float,
                            risk_payload: dict | None, posture_payload: dict | None) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.m2_url}/policy/evaluate",
                json={
                    "session_id": session_id,
                    "risk_score": risk,
                    "posture_score": posture,
                    "risk_score_payload": risk_payload,
                    "posture_score_payload": posture_payload,
                },
                headers=service_token_headers(),
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("m2_call_failed", session_id=session_id, error=str(exc))
        return None


async def _call_m3_trigger(session_id: str, decision: str, reason: str) -> dict | None:
    if decision not in ("step_up", "restrict", "deny"):
        return None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{settings.m3_url}/response/trigger",
                json={"session_id": session_id, "decision": decision, "reason": reason},
                headers=service_token_headers(),
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("m3_call_failed", session_id=session_id, error=str(exc))
        return None


# ── Core evaluation loop ──────────────────────────────────────────────────────

async def _evaluate_session(sess: SessionState) -> dict | None:
    """Run one full evaluation cycle for a session."""
    if not sess.active:
        return None

    # Build telemetry event from session state
    geo = sess.geo
    last_event = sess.last_event or {}
    # Carry through the event_type from the last ingested telemetry (default: access_request)
    event_type = last_event.get("event_type", "access_request")
    telemetry = {
        "schema_version": "1.0",
        "session_id": sess.session_id,
        "user_id": sess.user_id,
        "device_id": sess.device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "source_ip": sess.source_ip,
        "geo": geo,
        "raw_features": last_event.get("raw_features", {}),
    }

    posture = await _call_m4_posture(sess.device_id)
    sess.last_posture = posture

    risk_result = await _call_m5_score(sess.session_id, telemetry, posture)
    sess.last_risk_score = risk_result

    if risk_result:
        risk_score = risk_result.get("score", 0.3)
        posture_score = posture.get("posture_score", 0.7) if posture else 0.7

        # Inject _event_type into risk_payload so M2's event_type_eq rules fire correctly
        risk_payload_with_event = {**(risk_result or {}), "_event_type": event_type}

        decision = await _call_m2_evaluate(
            sess.session_id, risk_score, posture_score, risk_payload_with_event, posture
        )
        sess.last_decision = decision

        if decision:
            d = decision.get("decision", "allow")
            sess.ttl_deadline = time.monotonic() + decision.get("ttl_seconds", 300)
            reason = decision.get("reason", "")
            _audit({
                "event": "decision",
                "session_id": sess.session_id,
                "decision": d,
                "risk_score": risk_score,
                "posture_score": posture_score,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            if d in ("step_up", "restrict", "deny"):
                response = await _call_m3_trigger(sess.session_id, d, reason)
                sess.last_response_action = response
                if d == "deny":
                    sess.active = False
                elif d == "step_up":
                    sess.mfa_required = True
                elif d == "restrict":
                    sess.restricted = True

            log.info("evaluated", session_id=sess.session_id,
                     decision=d, risk=risk_score)
        return decision
    return None


# ── Background TTL re-evaluation loop ─────────────────────────────────────────

async def _reevaluation_loop() -> None:
    """Continuously re-evaluate sessions whose TTL has expired."""
    import time
    while True:
        await asyncio.sleep(5)
        now = time.monotonic()
        with _sessions_lock:
            active = [s for s in _sessions.values() if s.active and s.ttl_deadline < now]
        for sess in active:
            try:
                await _evaluate_session(sess)
            except Exception as exc:
                log.error("reeval_error", session_id=sess.session_id, error=str(exc))


async def _seed_baseline_sessions() -> None:
    """Seed initial normal employee sessions so dashboard displays live state immediately."""
    await asyncio.sleep(3)
    for uid, dev, ip in [
        ("bob", "dev-bob-laptop", "10.0.2.10"),
        ("carol", "dev-carol-laptop", "10.0.3.10"),
    ]:
        try:
            sess_id = f"sess-{uid}-{uuid.uuid4().hex[:8]}"
            geo = _geo_from_ip(ip, uid)
            s = SessionState(sess_id, uid, dev, ip, geo)
            with _sessions_lock:
                _sessions[sess_id] = s
            await _evaluate_session(s)
            log.info("baseline_session_seeded", user_id=uid, session_id=sess_id)
        except Exception as exc:
            log.warning("baseline_seed_failed", user_id=uid, error=str(exc))


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(_reevaluation_loop())
    asyncio.create_task(_seed_baseline_sessions())
    log.info("m1_startup", status="ok")


# ── Request/response models ───────────────────────────────────────────────────

class LoginRequest(BaseModel):
    user_id: str
    password: str = "simulated"  # always accepted in simulation
    device_id: str
    source_ip: str = "10.0.0.1"


class TelemetryIngest(BaseModel):
    session_id: str
    event_type: str
    resource: str | None = None
    raw_features: dict[str, Any] | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "module": "m1_identity", "version": "2.0.0",
            "active_sessions": str(len(_sessions))}


@app.post("/auth/login", tags=["Auth"])
async def login(request: Request, body: LoginRequest) -> dict[str, Any]:
    """
    OIDC-like simulated login.  Any user in the directory is accepted.
    Returns a session_id (our 'access token').
    """
    if body.user_id not in _USERS and body.user_id != "unknown":
        raise HTTPException(status_code=401, detail="User not found.")

    session_id = f"sess-{body.user_id}-{uuid.uuid4().hex[:8]}"
    geo = _geo_from_ip(body.source_ip, body.user_id)

    sess = SessionState(
        session_id=session_id,
        user_id=body.user_id,
        device_id=body.device_id,
        source_ip=body.source_ip,
        geo=geo,
    )
    with _sessions_lock:
        _sessions[session_id] = sess

    # Kick off first evaluation
    decision = await _evaluate_session(sess)

    _audit({"event": "login", "session_id": session_id, "user_id": body.user_id,
            "device_id": body.device_id, "source_ip": body.source_ip,
            "timestamp": datetime.now(timezone.utc).isoformat()})

    log.info("login", session_id=session_id, user_id=body.user_id)
    return {
        "session_id": session_id,
        "user_id": body.user_id,
        "decision": decision,
        "status": "active",
    }


@app.post("/telemetry/events", status_code=202, tags=["Telemetry"])
async def ingest_telemetry(
    body: TelemetryIngest,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Ingest a telemetry event for an active session.
    Re-scores immediately and returns the updated decision.
    """
    with _sessions_lock:
        sess = _sessions.get(body.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")

    raw = body.raw_features or {}
    if body.resource:
        raw["resource_path"] = body.resource
    sess.last_event = {
        "event_type": body.event_type,
        "raw_features": raw,
    }
    decision = await _evaluate_session(sess)
    return {"status": "accepted", "session_id": body.session_id, "decision": decision}


@app.get("/session/{session_id}", tags=["Session"])
def get_session_context(
    session_id: str,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """Retrieve full session context including last risk score and decision."""
    with _sessions_lock:
        sess = _sessions.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found.")
    return {
        "session_id": sess.session_id,
        "user_id": sess.user_id,
        "device_id": sess.device_id,
        "source_ip": sess.source_ip,
        "geo": sess.geo,
        "active": sess.active,
        "mfa_required": sess.mfa_required,
        "restricted": sess.restricted,
        "last_risk_score": sess.last_risk_score,
        "last_posture": sess.last_posture,
        "last_decision": sess.last_decision,
        "last_response_action": sess.last_response_action,
        "created_at": sess.created_at.isoformat(),
    }


@app.get("/sessions", tags=["Session"])
def list_sessions(
    _: None = Depends(require_service_token),
) -> list[dict[str, Any]]:
    """List all active sessions (for dashboard)."""
    with _sessions_lock:
        sessions = list(_sessions.values())
    return [
        {
            "session_id": s.session_id,
            "user_id": s.user_id,
            "device_id": s.device_id,
            "active": s.active,
            "mfa_required": s.mfa_required,
            "restricted": s.restricted,
            "risk_score": s.last_risk_score.get("score") if s.last_risk_score else None,
            "posture_score": s.last_posture.get("posture_score") if s.last_posture else None,
            "decision": s.last_decision.get("decision") if s.last_decision else None,
            "created_at": s.created_at.isoformat(),
        }
        for s in sessions
    ]


@app.delete("/session/{session_id}", tags=["Session"])
def terminate_session(
    session_id: str,
    _: None = Depends(require_service_token),
) -> dict[str, str]:
    """Forcibly terminate a session (called by M3)."""
    with _sessions_lock:
        sess = _sessions.get(session_id)
    if sess:
        sess.active = False
    log.info("session_terminated", session_id=session_id)
    return {"status": "terminated", "session_id": session_id}

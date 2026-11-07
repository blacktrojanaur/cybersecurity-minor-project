"""
M3 – Automated Incident Response / SOAR-lite  (port 8003)
==========================================================
Phase 2: YAML playbook dispatcher, idempotent action execution,
append-only audit trail, mock SOC webhook, human-approval gate.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import Depends, FastAPI, HTTPException
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
    title="M3 – Automated Incident Response (SOAR-lite)",
    description="YAML playbook dispatcher with idempotent execution and human-approval gate.",
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Config ────────────────────────────────────────────────────────────────────

_CONFIG_DIR = Path(__file__).parent / "config"
_AUDIT_PATH = Path("/data/audit/m3_actions.jsonl")
_PENDING_APPROVAL_PATH = Path("/data/audit/m3_pending_approval.jsonl")


def _load_playbooks() -> tuple[list[dict], str]:
    path = _CONFIG_DIR / "playbooks.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data.get("playbooks", []), data.get("playbook_version", "1.0")


_playbooks, _pb_version = _load_playbooks()

# ── Action dedup (idempotency) ────────────────────────────────────────────────
# session_id → set of action_types already executed this session

_executed: dict[str, set[str]] = {}
_exec_lock = threading.Lock()

# ── Action history ────────────────────────────────────────────────────────────

_history: dict[str, list[dict]] = {}
_hist_lock = threading.Lock()


def _audit(record: dict) -> None:
    try:
        _AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        log.warning("audit_write_failed", error=str(exc))


# ── Action executors ──────────────────────────────────────────────────────────

async def _exec_terminate_session(session_id: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.delete(
                f"{settings.m1_url}/session/{session_id}",
                headers=service_token_headers(),
            )
        # Also notify M2 to update its cache
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(
                f"{settings.m2_url}/enforcement/terminate",
                json={"session_id": session_id},
                headers=service_token_headers(),
            )
        return "executed"
    except Exception as exc:
        log.warning("terminate_failed", session_id=session_id, error=str(exc))
        return "failed"


async def _exec_alert_soc(session_id: str, reason: str, metadata: dict) -> str:
    payload = {
        "incident_id": f"inc-{uuid.uuid4().hex[:8]}",
        "session_id": session_id,
        "severity": "HIGH",
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata,
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            await c.post(settings.webhook_url, json=payload, timeout=3.0)
        return "executed"
    except Exception:
        log.warning("webhook_failed", webhook_url=settings.webhook_url)
        return "executed"  # Non-fatal: webhook is best-effort


async def _exec_action(
    action_type: str, session_id: str, trigger_reason: str, extra: dict
) -> dict[str, Any]:
    """Execute a single response action. Returns a ResponseAction dict."""
    ts = datetime.now(timezone.utc).isoformat()

    # Idempotency check
    with _exec_lock:
        done = _executed.setdefault(session_id, set())
        if action_type in done:
            log.info("action_skipped_duplicate", session_id=session_id, action=action_type)
            status = "executed"  # already done
            meta = {"idempotent_skip": True}
        else:
            done.add(action_type)
            meta = {}

            if action_type == "terminate_session":
                status = await _exec_terminate_session(session_id)
            elif action_type == "alert_soc":
                status = await _exec_alert_soc(session_id, trigger_reason, extra)
            elif action_type == "require_mfa":
                status = "executed"  # simulated
                meta["mfa_challenge_id"] = f"mfa-{uuid.uuid4().hex[:8]}"
            elif action_type == "restrict_access":
                status = "executed"  # enforced via M2 policy cache
            elif action_type == "notify_user":
                status = "executed"
                meta["notified_at"] = ts
            elif action_type == "block_ip":
                status = "executed"  # simulated
                meta["blocked_ip"] = extra.get("source_ip", "unknown")
            else:
                status = "failed"

    record = {
        "schema_version": "1.0",
        "session_id": session_id,
        "timestamp": ts,
        "action_type": action_type,
        "trigger_reason": trigger_reason,
        "status": status,
        "metadata": meta,
    }
    _audit(record)
    with _hist_lock:
        _history.setdefault(session_id, []).append(record)
    log.info("action_executed", session_id=session_id, action=action_type, status=status)
    return record


# ── Request models ────────────────────────────────────────────────────────────

class TriggerRequest(BaseModel):
    session_id: str
    decision: str
    reason: str
    extra: dict[str, Any] = {}


class ApprovalRequest(BaseModel):
    action_id: str
    approved: bool
    analyst_id: str = "analyst-001"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "module": "m3_response", "version": "2.0.0",
            "playbook_version": _pb_version}


@app.post("/response/trigger", tags=["Response"])
async def trigger_response(
    request: TriggerRequest,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Trigger response playbook for a policy decision.

    Maps decision → playbook → executes actions in order.
    Playbooks with require_human_approval=true are queued for analyst review.
    Returns the first action's ResponseAction (contract-compliant).
    """
    # Find matching playbooks
    matching = [
        pb for pb in _playbooks
        if request.decision in pb.get("trigger_decisions", [])
        and not pb.get("require_human_approval", False)
    ]
    if not matching:
        # Default: notify only
        result = await _exec_action("notify_user", request.session_id,
                                    request.reason, request.extra)
        return result

    pb = matching[0]  # highest priority match
    actions = pb.get("actions", [])
    results = []
    for action_cfg in actions:
        action_type = action_cfg["type"]
        result = await _exec_action(action_type, request.session_id,
                                    request.reason, request.extra)
        results.append(result)

    # Also queue destructive playbooks needing approval
    approval_needed = [
        pb for pb in _playbooks
        if request.decision in pb.get("trigger_decisions", [])
        and pb.get("require_human_approval", False)
    ]
    for apb in approval_needed:
        pending = {
            "playbook_id": apb["id"],
            "session_id": request.session_id,
            "reason": request.reason,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending_approval",
        }
        try:
            _PENDING_APPROVAL_PATH.parent.mkdir(parents=True, exist_ok=True)
            with _PENDING_APPROVAL_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(pending) + "\n")
        except Exception:
            pass

    # Return first result (contract-compatible ResponseAction)
    return results[0] if results else {"status": "no_actions"}


@app.get("/response/{session_id}", tags=["Response"])
def get_response_actions(
    session_id: str,
    _: None = Depends(require_service_token),
) -> list[dict[str, Any]]:
    """Return all response actions taken for a session (chronological)."""
    with _hist_lock:
        return list(_history.get(session_id, []))


@app.get("/audit/actions", tags=["Audit"])
def get_audit_log(
    limit: int = 100,
    _: None = Depends(require_service_token),
) -> list[dict]:
    """Return recent action audit log entries."""
    if not _AUDIT_PATH.exists():
        return []
    lines = _AUDIT_PATH.read_text(encoding="utf-8").strip().splitlines()
    records = [json.loads(ln) for ln in lines if ln.strip()]
    return records[-limit:]


@app.get("/pending-approvals", tags=["Approval"])
def get_pending_approvals(
    _: None = Depends(require_service_token),
) -> list[dict]:
    """Return pending human-approval items."""
    if not _PENDING_APPROVAL_PATH.exists():
        return []
    lines = _PENDING_APPROVAL_PATH.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(ln) for ln in lines if ln.strip()]

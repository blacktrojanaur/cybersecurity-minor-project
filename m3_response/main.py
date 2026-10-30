"""
M3 – Automated Incident Response / SOAR-lite  (port 8003)
==========================================================
Phase 1 stub: returns mock response actions that validate against
contracts/response_action.schema.json.

Phase 2 responsibilities (NOT implemented here):
- Session termination via M1 API
- Step-up MFA challenge dispatch (email / TOTP)
- SOC alert creation (webhook / SIEM integration)
- IP blocklist update via M2 micro-segmentation
- Audit-trail logging with case IDs
- Escalation timer: auto-escalate if no ack within N minutes
"""

from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="M3 – Automated Incident Response (SOAR-lite)",
    description=(
        "Triggers automated responses (session termination, MFA, SOC alerts) "
        "based on policy decisions. Phase 1 stub only."
    ),
    version="1.0.0-stub",
)

# ── Pydantic models (mirror contracts/response_action.schema.json) ────────────

class ResponseAction(BaseModel):
    """Automated response action produced by M3."""

    schema_version: str = "1.0"
    session_id: str
    timestamp: str
    action_type: str       # terminate_session | require_mfa | restrict_access | alert_soc | block_ip | notify_user
    trigger_reason: str
    status: str            # pending | executed | failed
    metadata: dict = {}


class TriggerRequest(BaseModel):
    """Request payload for /response/trigger."""

    session_id: str
    decision: str   # step_up | restrict | deny
    reason: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check – confirms the stub is running."""
    return {"status": "ok", "module": "m3_response", "version": "1.0.0-stub"}


@app.post("/response/trigger", response_model=ResponseAction, tags=["Response"])
def trigger_response(request: TriggerRequest) -> ResponseAction:
    """
    Trigger an automated response action for a policy decision.

    Phase 1 stub: always returns ``action_type=notify_user`` with ``status=executed``.
    Phase 2: select action based on decision type and execute it.

    Action mapping (Phase 2 design intent – NOT enforced here):
    - step_up → require_mfa
    - restrict → restrict_access
    - deny → terminate_session + alert_soc
    """
    return ResponseAction(
        schema_version="1.0",
        session_id=request.session_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        action_type="notify_user",
        trigger_reason=request.reason or "Routine policy enforcement. (stub)",
        status="executed",
        metadata={"notified_at": datetime.now(timezone.utc).isoformat(), "stub": True},
    )


@app.get("/response/{session_id}", response_model=list[ResponseAction], tags=["Response"])
def get_response_actions(session_id: str) -> list[ResponseAction]:
    """
    Retrieve all response actions taken for a session (chronological).

    Phase 1 stub: returns a single mock notify_user action.
    Phase 2: query response log store.
    """
    return [
        ResponseAction(
            schema_version="1.0",
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_type="notify_user",
            trigger_reason="Routine policy enforcement. (stub)",
            status="executed",
            metadata={},
        )
    ]

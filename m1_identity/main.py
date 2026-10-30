"""
M1 – Identity & Context Engine  (port 8001)
============================================
Phase 1 stub: returns mock telemetry event payloads that validate against
contracts/telemetry_event.schema.json.

Phase 2 responsibilities (NOT implemented here):
- Integrate with LDAP/OIDC identity provider
- Real-time geo-IP enrichment (MaxMind GeoLite2)
- Device fingerprinting and posture signal collection
- Forward telemetry to M5 /score and M4 /posture/scan
- Re-evaluation trigger on TTL expiry from M2
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="M1 – Identity & Context Engine",
    description=(
        "Collects device posture, geo/IP and session telemetry. "
        "Phase 1 stub only – returns mock data."
    ),
    version="1.0.0-stub",
)

# ── Pydantic models (mirror contracts/telemetry_event.schema.json) ────────────

class GeoLocation(BaseModel):
    """Geographic context derived from source IP."""

    country: str
    city: str
    lat: float
    lon: float


class TelemetryEvent(BaseModel):
    """Telemetry event produced by M1 and consumed by M5 and M4."""

    schema_version: str = "1.0"
    session_id: str
    user_id: str
    device_id: str
    timestamp: str
    event_type: str
    source_ip: str
    geo: GeoLocation | None = None
    user_agent: str | None = None
    raw_features: dict[str, Any] | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check – confirms the stub is running."""
    return {"status": "ok", "module": "m1_identity", "version": "1.0.0-stub"}


@app.post("/telemetry/events", status_code=202, tags=["Telemetry"])
def ingest_telemetry_event(event: TelemetryEvent) -> dict[str, str]:
    """
    Ingest a session telemetry event.

    Phase 1 stub: validates the payload via Pydantic and acknowledges receipt.
    Phase 2: store, enrich, and forward to M5 and M4.
    """
    return {"status": "accepted", "session_id": event.session_id}


@app.get("/session/{session_id}", response_model=TelemetryEvent, tags=["Session"])
def get_session_context(session_id: str) -> TelemetryEvent:
    """
    Retrieve enriched session context.

    Phase 1 stub: returns a hardcoded mock payload regardless of session_id.
    The mock payload validates against telemetry_event.schema.json.
    """
    return TelemetryEvent(
        schema_version="1.0",
        session_id=session_id,
        user_id="user-mock-001",
        device_id="dev-mock-001",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="access_request",
        source_ip="192.168.1.100",
        geo=GeoLocation(country="IN", city="Mumbai", lat=19.0760, lon=72.8777),
        user_agent="Mozilla/5.0 (stub)",
        raw_features={"bytes_sent": 1024, "session_duration": 300},
    )

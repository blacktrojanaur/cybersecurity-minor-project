"""
M4 – Vulnerability & Posture Integration  (port 8004)
======================================================
Phase 1 stub: returns mock posture scores that validate against
contracts/posture_score.schema.json.

Phase 2 responsibilities (NOT implemented here):
- Pull CVE/patch data from NVD API or Nessus/OpenVAS scan results
- Compute posture_score from weighted formula:
    score = w1*patch_level + w2*(1 - crit_vuln_penalty) + w3*os_compliant + w4*av_active
- Cache results per device_id with configurable staleness TTL
- Expose webhook for scanner push notifications
- Feed real-time posture updates to M5 and M2
"""

from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="M4 – Vulnerability & Posture Integration",
    description=(
        "Provides device posture and vulnerability data to M5 and M2. "
        "Phase 1 stub only – returns mock posture scores."
    ),
    version="1.0.0-stub",
)

# ── Pydantic models (mirror contracts/posture_score.schema.json) ──────────────

class PostureScore(BaseModel):
    """Device posture and vulnerability summary produced by M4."""

    schema_version: str = "1.0"
    device_id: str
    timestamp: str
    patch_level: float          # 0.0–1.0
    vuln_count: int
    critical_vuln_count: int
    os_compliant: bool
    antivirus_active: bool
    posture_score: float        # 0.0–1.0


class ScanRequest(BaseModel):
    """Request payload for /posture/scan."""

    device_id: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check – confirms the stub is running."""
    return {"status": "ok", "module": "m4_posture", "version": "1.0.0-stub"}


@app.get("/posture/{device_id}", response_model=PostureScore, tags=["Posture"])
def get_posture(device_id: str) -> PostureScore:
    """
    Retrieve the latest posture assessment for a device.

    Phase 1 stub: returns a mock compliant device with 3 low-severity vulns.
    Phase 2: look up cached scan results; trigger re-scan if stale.
    """
    return PostureScore(
        schema_version="1.0",
        device_id=device_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        patch_level=0.85,
        vuln_count=3,
        critical_vuln_count=0,
        os_compliant=True,
        antivirus_active=True,
        posture_score=0.78,
    )


@app.post("/posture/scan", status_code=202, tags=["Posture"])
def trigger_scan(request: ScanRequest) -> dict[str, str]:
    """
    Queue an on-demand posture re-assessment for a device.

    Phase 1 stub: acknowledges the request without performing a scan.
    Phase 2: enqueue a scan job and return a job ID for polling.
    """
    return {"status": "scan_queued", "device_id": request.device_id}

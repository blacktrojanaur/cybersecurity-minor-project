"""
M5 – ML Risk-Scoring Engine  (port 8005)
=========================================
Phase 1 stub: returns a DETERMINISTIC mock risk score (0.2300) so that
M2, M3, and M1 are never blocked waiting for a real model.

All responses validate against contracts/risk_score.schema.json.

Phase 2 responsibilities (NOT implemented here):
- Train Isolation Forest on synthetic + real telemetry dataset
- Implement autoencoder baseline for comparison
- SHAP-based feature attributions for top_features
- Model versioning and hot-swap without service restart
- Feedback loop: receive ground-truth labels from M3 (confirmed incidents)
  to trigger periodic re-training
- A/B testing harness for model comparison
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="M5 – ML Risk-Scoring Engine",
    description=(
        "Behavioural anomaly detection producing a continuous risk score [0, 1]. "
        "Phase 1 stub returns deterministic score=0.2300. "
        "Phase 2 replaces this with Isolation Forest / autoencoder."
    ),
    version="1.0.0-stub",
)

# ── Constants ─────────────────────────────────────────────────────────────────

STUB_SCORE: float = 0.2300          # Deterministic value – do not change until Phase 2
STUB_CONFIDENCE: float = 0.8700
STUB_MODEL_VERSION: str = "stub-v1.0"

# ── Pydantic models (mirror contracts/risk_score.schema.json) ─────────────────

class ScoreFeature(BaseModel):
    """A single feature's contribution to the risk score."""

    name: str
    contribution: float


class RiskScore(BaseModel):
    """Risk score produced by M5 and consumed by M2 and M3."""

    schema_version: str = "1.0"
    session_id: str
    timestamp: str
    score: float
    confidence: float
    top_features: list[ScoreFeature]
    model_version: str


class ScoreRequest(BaseModel):
    """Request payload for POST /score."""

    session_id: str
    telemetry_event: dict[str, Any]
    posture_score: dict[str, Any] | None = None


# ── Helper ────────────────────────────────────────────────────────────────────

def _stub_score(session_id: str) -> RiskScore:
    """Return the deterministic stub risk score."""
    return RiskScore(
        schema_version="1.0",
        session_id=session_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        score=STUB_SCORE,
        confidence=STUB_CONFIDENCE,
        top_features=[
            ScoreFeature(name="geo_anomaly",       contribution=0.12),
            ScoreFeature(name="off_hours_access",  contribution=0.07),
            ScoreFeature(name="new_device",        contribution=0.04),
        ],
        model_version=STUB_MODEL_VERSION,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check – confirms the stub is running."""
    return {"status": "ok", "module": "m5_ml", "version": "1.0.0-stub"}


@app.post("/score", response_model=RiskScore, tags=["Scoring"])
def compute_risk_score(request: ScoreRequest) -> RiskScore:
    """
    Compute a behavioural risk score for a session.

    Phase 1 stub: ignores all input features and returns score=0.2300.
    This deterministic value ensures M2 and M3 are unblocked during Phase 1.

    Phase 2: run telemetry_event features + posture_score through the
    trained Isolation Forest model and compute SHAP attributions.
    """
    return _stub_score(request.session_id)


@app.get("/score/{session_id}", response_model=RiskScore, tags=["Scoring"])
def get_latest_score(session_id: str) -> RiskScore:
    """
    Retrieve the latest cached risk score for a session.

    Phase 1 stub: returns the same deterministic mock score.
    Phase 2: query the score cache (Redis / in-memory store).
    """
    return _stub_score(session_id)

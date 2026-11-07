"""
M5 – ML Risk-Scoring Engine  (port 8005)
=========================================
Phase 2: Real Isolation Forest + Random Forest ensemble with SHAP explainability.
Replaces the Phase 1 stub entirely while keeping all existing endpoints compatible.
"""

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from common.logging_utils import get_logger
from common.auth import require_service_token

from m5_ml.scorer import get_scorer
from m5_ml.feedback_store import record_feedback, load_feedback
from m5_ml.trainer import train, MODELS_DIR

log = get_logger(__name__)

app = FastAPI(
    title="M5 – ML Risk-Scoring Engine",
    description=(
        "Behavioural anomaly detection producing a continuous risk score [0, 1]. "
        "Phase 2: Isolation Forest + Random Forest ensemble with SHAP attributions."
    ),
    version="2.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Score cache: session_id → last RiskScore dict
_score_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup() -> None:
    scorer = get_scorer()
    scorer.load()
    if scorer.is_ready():
        log.info("m5_startup", status="models_loaded", version=scorer.model_version)
    else:
        log.warning("m5_startup", status="models_not_found",
                    hint="Run `make train` to train models before scoring.")


# ── Pydantic request/response models ─────────────────────────────────────────

class ScoreRequest(BaseModel):
    session_id: str
    telemetry_event: dict[str, Any]
    posture_score: dict[str, Any] | None = None


class FeedbackRequest(BaseModel):
    session_id: str
    confirmed_incident: bool
    event_snapshot: dict[str, Any] | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    scorer = get_scorer()
    return {
        "status": "ok",
        "module": "m5_ml",
        "version": "2.0.0",
        "model_ready": str(scorer.is_ready()),
        "model_version": scorer.model_version,
    }


@app.post("/score", tags=["Scoring"])
def compute_risk_score(
    request: ScoreRequest,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Compute a risk score for a session telemetry event.

    Returns a RiskScore object conforming to contracts/risk_score.schema.json.
    """
    scorer = get_scorer()
    result = scorer.score(
        session_id=request.session_id,
        telemetry=request.telemetry_event,
        posture=request.posture_score,
    )
    with _cache_lock:
        _score_cache[request.session_id] = result
    log.info("scored", session_id=request.session_id,
             score=result["score"], model=result["model_version"])
    return result


@app.get("/score/{session_id}", tags=["Scoring"])
def get_latest_score(
    session_id: str,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """Retrieve the latest cached risk score for a session."""
    with _cache_lock:
        cached = _score_cache.get(session_id)
    if not cached:
        raise HTTPException(status_code=404, detail=f"No score cached for session {session_id!r}.")
    return cached


@app.post("/feedback", tags=["Feedback"])
def submit_feedback(
    request: FeedbackRequest,
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Submit analyst-confirmed ground-truth label for a session.
    Labels accumulate in the feedback store for periodic retraining.
    Only confirmed labels are accepted (no automated labels).
    """
    record = record_feedback(
        session_id=request.session_id,
        confirmed_incident=request.confirmed_incident,
        event_snapshot=request.event_snapshot,
    )
    log.info("feedback_recorded", session_id=request.session_id,
             confirmed_incident=request.confirmed_incident)
    return {"status": "recorded", "record": record}


@app.post("/retrain", tags=["Training"])
def trigger_retrain(
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """
    Trigger model retraining from the current synthetic data + feedback store.
    Runs synchronously (laptop scale); production systems would run this async.
    Only analyst-confirmed samples from feedback are incorporated.
    """
    from pathlib import Path
    data_dir = Path("testbed/data")
    if not data_dir.exists():
        raise HTTPException(
            status_code=400,
            detail="Training data not found. Run `make train` first.",
        )
    try:
        meta = train(data_dir)
        get_scorer().load()  # hot-reload
        log.info("retrained", model_version=meta["model_version"])
        return {"status": "retrained", "metadata": meta}
    except Exception as exc:
        log.error("retrain_failed", error=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/feedback/summary", tags=["Feedback"])
def feedback_summary(
    _: None = Depends(require_service_token),
) -> dict[str, Any]:
    """Return summary statistics of the analyst feedback store."""
    records = load_feedback()
    attacks = sum(1 for r in records if r.get("confirmed_incident"))
    normals = len(records) - attacks
    return {"total": len(records), "confirmed_attacks": attacks, "confirmed_normal": normals}

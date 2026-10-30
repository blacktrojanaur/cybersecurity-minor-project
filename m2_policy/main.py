"""
M2 – Policy Enforcement & Micro-segmentation  (port 8002)
==========================================================
Phase 1 stub: returns mock policy decisions that validate against
contracts/policy_decision.schema.json.

Phase 2 responsibilities (NOT implemented here):
- Load policy rules from a YAML/DB rule store
- Evaluate risk_score + posture_score thresholds against rules
- Enforce micro-segmentation (iptables / service-mesh integration)
- Emit TTL-driven re-evaluation triggers
- Log every decision to an append-only audit store
"""

from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="M2 – Policy Enforcement & Micro-segmentation",
    description=(
        "Evaluates risk scores and posture data to produce per-session policy decisions. "
        "Phase 1 stub only – returns mock allow decisions."
    ),
    version="1.0.0-stub",
)

# ── Pydantic models (mirror contracts/policy_decision.schema.json) ────────────

class PolicyDecision(BaseModel):
    """Policy enforcement decision produced by M2."""

    schema_version: str = "1.0"
    session_id: str
    timestamp: str
    decision: str          # allow | step_up | restrict | deny
    reason: str
    ttl_seconds: int
    applied_policies: list[str] = []


class EvaluationRequest(BaseModel):
    """Request payload for /policy/evaluate."""

    session_id: str
    risk_score: float
    posture_score: float


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Health check – confirms the stub is running."""
    return {"status": "ok", "module": "m2_policy", "version": "1.0.0-stub"}


@app.post("/policy/evaluate", response_model=PolicyDecision, tags=["Policy"])
def evaluate_policy(request: EvaluationRequest) -> PolicyDecision:
    """
    Evaluate policy for a session given its current risk and posture scores.

    Phase 1 stub: always returns ``decision=allow`` with TTL=300 s.
    Phase 2: apply rule engine (risk thresholds, attribute-based rules).

    Decision thresholds (Phase 2 design intent – NOT enforced here):
    - score < 0.40 and posture > 0.60  → allow
    - score 0.40–0.70 or posture 0.40–0.60 → step_up
    - score > 0.70 or critical_vuln_count > 0 → deny
    """
    return PolicyDecision(
        schema_version="1.0",
        session_id=request.session_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        decision="allow",
        reason=(
            f"Stub: risk_score={request.risk_score:.4f}, "
            f"posture_score={request.posture_score:.4f}. "
            "Phase 1 always allows."
        ),
        ttl_seconds=300,
        applied_policies=["policy-baseline-rbac", "policy-geo-allow"],
    )


@app.get("/policy/{session_id}", response_model=PolicyDecision, tags=["Policy"])
def get_policy(session_id: str) -> PolicyDecision:
    """
    Retrieve the current policy decision for a session.

    Phase 1 stub: returns a mock allow decision.
    Phase 2: look up from decision cache; check TTL validity.
    """
    return PolicyDecision(
        schema_version="1.0",
        session_id=session_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        decision="allow",
        reason="Stub: cached allow decision.",
        ttl_seconds=300,
        applied_policies=["policy-baseline-rbac"],
    )

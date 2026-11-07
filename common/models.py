"""
common.models – Pydantic v2 models that mirror every frozen v1.0 contract schema.

These are the single source of truth for in-process type checking.
The JSON schemas in /contracts/ remain the authoritative wire-format validators.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ── TelemetryEvent (M1 → M5, M4)  ──────────────────────────────────────────

class GeoLocation(BaseModel):
    """Geographic context derived from source IP."""
    country: str
    city: str | None = None
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)


class TelemetryEvent(BaseModel):
    """Telemetry event produced by M1 and consumed by M5 and M4."""
    schema_version: Literal["1.0"] = "1.0"
    session_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    timestamp: str  # ISO 8601
    event_type: Literal[
        "login", "access_request", "file_access",
        "lateral_move_attempt", "auth_failure", "logout",
        "privilege_escalation_attempt",
    ]
    source_ip: str
    geo: GeoLocation | None = None
    user_agent: str | None = None
    raw_features: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}


# ── RiskScore (M5 → M2, M3)  ────────────────────────────────────────────────

class ScoreFeature(BaseModel):
    """A single feature's SHAP contribution to the risk score."""
    name: str = Field(min_length=1)
    contribution: float = Field(ge=0.0, le=1.0)

    model_config = {"extra": "forbid"}


class RiskScore(BaseModel):
    """Risk score produced by M5 and consumed by M2 and M3."""
    schema_version: Literal["1.0"] = "1.0"
    session_id: str = Field(min_length=1)
    timestamp: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    top_features: list[ScoreFeature] = Field(min_length=1, max_length=10)
    model_version: str = Field(min_length=1)

    model_config = {"extra": "forbid"}


# ── PostureScore (M4 → M5, M2)  ─────────────────────────────────────────────

class PostureScore(BaseModel):
    """Device posture and vulnerability summary produced by M4."""
    schema_version: Literal["1.0"] = "1.0"
    device_id: str = Field(min_length=1)
    timestamp: str
    patch_level: float = Field(ge=0.0, le=1.0)
    vuln_count: int = Field(ge=0)
    critical_vuln_count: int = Field(ge=0)
    os_compliant: bool
    antivirus_active: bool
    posture_score: float = Field(ge=0.0, le=1.0)

    model_config = {"extra": "forbid"}


# ── PolicyDecision (M2 → M1, M3)  ───────────────────────────────────────────

class PolicyDecision(BaseModel):
    """Policy enforcement decision produced by M2."""
    schema_version: Literal["1.0"] = "1.0"
    session_id: str = Field(min_length=1)
    timestamp: str
    decision: Literal["allow", "step_up", "restrict", "deny"]
    reason: str = Field(min_length=1)
    ttl_seconds: int = Field(ge=30, le=3600)
    applied_policies: list[str] = []

    model_config = {"extra": "forbid"}


# ── ResponseAction (M3 → M1, M2)  ───────────────────────────────────────────

class ResponseAction(BaseModel):
    """Automated response action produced by M3."""
    schema_version: Literal["1.0"] = "1.0"
    session_id: str = Field(min_length=1)
    timestamp: str
    action_type: Literal[
        "terminate_session", "require_mfa", "restrict_access",
        "alert_soc", "block_ip", "notify_user",
    ]
    trigger_reason: str = Field(min_length=1)
    status: Literal["pending", "executed", "failed"]
    metadata: dict[str, Any] = {}

    model_config = {"extra": "forbid"}


# ── Request bodies (not in contracts, used internally)  ─────────────────────

class ScoreRequest(BaseModel):
    """Request body for M5 POST /score."""
    session_id: str
    telemetry_event: dict[str, Any]
    posture_score: dict[str, Any] | None = None


class EvaluationRequest(BaseModel):
    """Request body for M2 POST /policy/evaluate."""
    session_id: str
    risk_score: float = Field(ge=0.0, le=1.0)
    posture_score: float = Field(ge=0.0, le=1.0)
    risk_score_payload: dict[str, Any] | None = None
    posture_score_payload: dict[str, Any] | None = None


class TriggerRequest(BaseModel):
    """Request body for M3 POST /response/trigger."""
    session_id: str
    decision: Literal["step_up", "restrict", "deny"]
    reason: str


class FeedbackRequest(BaseModel):
    """Request body for M5 POST /feedback."""
    session_id: str
    confirmed_incident: bool
    event_snapshot: dict[str, Any] | None = None

"""
M5 – ML Risk-Scoring Engine: Feature extraction pipeline.

Converts a raw TelemetryEvent dict + optional PostureScore dict
into a fixed-length numeric feature vector for the ML models.

Feature list (25 features, names are contract-stable):
  0  bytes_sent_norm         – bytes_sent normalised [0,1]
  1  session_duration_norm   – session_duration normalised [0,1]
  2  distinct_resources      – count of distinct resources accessed
  3  off_hours               – 1 if access outside 09:00–18:00 UTC
  4  new_device              – 1 if device_id not in user's known devices
  5  geo_anomaly             – 1 if source country != user home country
  6  lateral_move_velocity   – float 0-1 from raw_features
  7  privilege_claim_mismatch– 0/1 flag
  8  temporal_drift_score    – float 0-1
  9  resource_access_deviation – float 0-1
  10 failed_auth_count       – count, clipped at 10
  11 is_login                – event_type == login
  12 is_access_request       – event_type == access_request
  13 is_file_access          – event_type == file_access
  14 is_lateral_move         – event_type == lateral_move_attempt
  15 is_auth_failure         – event_type == auth_failure
  16 is_privilege_esc        – event_type == privilege_escalation_attempt
  17 patch_level             – from PostureScore [0,1]
  18 vuln_count_norm         – vuln_count / 20 clipped [0,1]
  19 critical_vuln_count_flag– 1 if critical_vuln_count > 0
  20 os_compliant            – 1/0
  21 antivirus_active        – 1/0
  22 posture_score           – from PostureScore [0,1]
  23 hour_sin                – sin(2π * hour / 24)
  24 hour_cos                – cos(2π * hour / 24)
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

import numpy as np

FEATURE_NAMES: list[str] = [
    "bytes_sent_norm", "session_duration_norm", "distinct_resources",
    "off_hours", "new_device", "geo_anomaly",
    "lateral_move_velocity", "privilege_claim_mismatch",
    "temporal_drift_score", "resource_access_deviation",
    "failed_auth_count", "is_login", "is_access_request",
    "is_file_access", "is_lateral_move", "is_auth_failure",
    "is_privilege_esc", "patch_level", "vuln_count_norm",
    "critical_vuln_count_flag", "os_compliant", "antivirus_active",
    "posture_score", "hour_sin", "hour_cos",
]

N_FEATURES = len(FEATURE_NAMES)

# Clipping bounds for adversarial resilience (OQ5/adversarial)
CLIP_BOUNDS: dict[str, tuple[float, float]] = {
    "bytes_sent_norm": (0.0, 1.0),
    "session_duration_norm": (0.0, 1.0),
    "distinct_resources": (0.0, 50.0),
    "off_hours": (0.0, 1.0),
    "new_device": (0.0, 1.0),
    "geo_anomaly": (0.0, 1.0),
    "lateral_move_velocity": (0.0, 1.0),
    "privilege_claim_mismatch": (0.0, 1.0),
    "temporal_drift_score": (0.0, 1.0),
    "resource_access_deviation": (0.0, 1.0),
    "failed_auth_count": (0.0, 10.0),
    "posture_score": (0.0, 1.0),
}


def _parse_hour(timestamp: str) -> int:
    """Extract UTC hour from ISO 8601 timestamp."""
    try:
        dt = datetime.fromisoformat(timestamp)
        return dt.astimezone(timezone.utc).hour
    except Exception:
        return 12  # default to noon on parse failure


def extract_features(
    telemetry: dict[str, Any],
    posture: dict[str, Any] | None = None,
) -> np.ndarray:
    """
    Extract a 25-element feature vector from a TelemetryEvent + optional PostureScore.

    Returns: np.ndarray shape (25,) dtype float32
    """
    raw: dict[str, Any] = telemetry.get("raw_features") or {}
    et: str = telemetry.get("event_type", "")

    # Scalar features from raw_features (with input clipping)
    bytes_sent = min(float(raw.get("bytes_sent", 1024)), 65536) / 65536
    sess_dur = min(float(raw.get("session_duration", 300)), 86400) / 86400
    distinct_res = min(float(raw.get("distinct_resources", 1)), 50.0)
    off_hours = float(raw.get("off_hours", 0))
    new_device = float(raw.get("new_device", 0))
    geo_anomaly = float(raw.get("geo_anomaly", 0))
    lat_vel = min(float(raw.get("lateral_move_velocity", 0.0)), 1.0)
    priv_mismatch = float(raw.get("privilege_claim_mismatch", 0))
    temporal_drift = min(float(raw.get("temporal_drift_score", 0.0)), 1.0)
    res_deviation = min(float(raw.get("resource_access_deviation", 0.0)), 1.0)
    failed_auth = min(float(raw.get("failed_auth_count", 0)), 10.0)

    # Event type one-hot
    is_login = 1.0 if et == "login" else 0.0
    is_access = 1.0 if et == "access_request" else 0.0
    is_file = 1.0 if et == "file_access" else 0.0
    is_lateral = 1.0 if et == "lateral_move_attempt" else 0.0
    is_auth_fail = 1.0 if et == "auth_failure" else 0.0
    is_priv_esc = 1.0 if et == "privilege_escalation_attempt" else 0.0

    # Posture features (default to moderate values if not provided)
    p = posture or {}
    patch_level = float(p.get("patch_level", 0.7))
    vuln_count = min(float(p.get("vuln_count", 3)), 20.0) / 20.0
    crit_vuln = 1.0 if int(p.get("critical_vuln_count", 0)) > 0 else 0.0
    os_ok = 1.0 if p.get("os_compliant", True) else 0.0
    av_ok = 1.0 if p.get("antivirus_active", True) else 0.0
    posture_sc = float(p.get("posture_score", 0.7))

    # Time cyclical features
    hour = _parse_hour(telemetry.get("timestamp", ""))
    hour_sin = math.sin(2 * math.pi * hour / 24)
    hour_cos = math.cos(2 * math.pi * hour / 24)

    vec = np.array([
        bytes_sent, sess_dur, distinct_res,
        off_hours, new_device, geo_anomaly,
        lat_vel, priv_mismatch,
        temporal_drift, res_deviation,
        failed_auth, is_login, is_access,
        is_file, is_lateral, is_auth_fail,
        is_priv_esc, patch_level, vuln_count,
        crit_vuln, os_ok, av_ok,
        posture_sc, hour_sin, hour_cos,
    ], dtype=np.float32)

    assert len(vec) == N_FEATURES, f"Expected {N_FEATURES}, got {len(vec)}"
    return vec

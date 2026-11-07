"""
M5 – ML Risk-Scoring Engine: Scoring, SHAP explainability, and EWMA baseline.

The scorer:
  1. Extracts features from TelemetryEvent + PostureScore.
  2. Scales with the trained StandardScaler.
  3. Gets an anomaly score from IsolationForest.
  4. Gets an attack probability from RandomForest.
  5. Fuses them: risk = 0.6 * IF_score + 0.4 * RF_prob.
  6. Computes SHAP top-k features via TreeExplainer (cached per session).
  7. Maintains a per-user EWMA baseline for drift detection.
  8. Returns a fully contract-compliant RiskScore dict.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import shap

from m5_ml.features import extract_features, FEATURE_NAMES, N_FEATURES

MODELS_DIR = Path(__file__).parent / "models"

# EWMA parameters (adversarial drift detection)
EWMA_ALPHA = 0.1           # smoothing factor
DRIFT_THRESHOLD = 0.20     # alert if short_term - long_term > threshold
BASELINE_WINDOW = 50       # events before drift detection is active

# SHAP cache: keyed by session_id, stores (shap_values, timestamp)
_shap_cache: dict[str, tuple[list[dict], float]] = {}
SHAP_CACHE_TTL = 30.0  # seconds


class Scorer:
    """
    Stateful scorer — holds loaded models and per-user EWMA baselines.
    """

    def __init__(self) -> None:
        self.iso: Any = None
        self.rf: Any = None
        self.scaler: Any = None
        self.model_version: str = "not-loaded"
        self._iso_explainer: Any = None
        self._rf_explainer: Any = None
        # EWMA baselines: user_id → (ewma_score, event_count)
        self._user_baseline: dict[str, list[float]] = defaultdict(list)
        self._loaded = False

    def load(self) -> None:
        """Load models from disk.  Called at startup or on retrain."""
        if not (MODELS_DIR / "isolation_forest.pkl").exists():
            return  # models not yet trained; will return stub scores
        self.scaler = joblib.load(MODELS_DIR / "scaler.pkl")
        self.iso = joblib.load(MODELS_DIR / "isolation_forest.pkl")
        rf_path = MODELS_DIR / "random_forest.pkl"
        if rf_path.exists():
            self.rf = joblib.load(rf_path)
        # Load version from metadata
        meta_path = MODELS_DIR / "metadata.json"
        if meta_path.exists():
            import json
            meta = json.loads(meta_path.read_text())
            self.model_version = meta.get("model_version", "v1")
        # Build SHAP explainers
        try:
            if self.iso is not None:
                self._iso_explainer = shap.TreeExplainer(self.iso)
            if self.rf is not None:
                self._rf_explainer = shap.TreeExplainer(self.rf)
        except Exception:
            pass  # SHAP init failures are non-fatal; fallback to feature importance
        self._loaded = True

    def is_ready(self) -> bool:
        return self._loaded and self.iso is not None

    def _isolation_score(self, X_scaled: np.ndarray) -> float:
        """Convert IF decision_function output to [0,1] risk score."""
        # decision_function: negative = more anomalous; range ~ [-0.5, 0.5]
        raw = float(self.iso.decision_function(X_scaled.reshape(1, -1))[0])
        # Map: raw=-0.5 → 1.0 (high risk), raw=0.5 → 0.0 (low risk)
        clipped = max(-0.5, min(0.5, raw))
        return round(1.0 - (clipped + 0.5), 4)

    def _rf_prob(self, X_scaled: np.ndarray) -> float:
        """Return P(attack) from RF, or 0.0 if RF not loaded."""
        if self.rf is None:
            return 0.0
        probs = self.rf.predict_proba(X_scaled.reshape(1, -1))[0]
        classes = list(self.rf.classes_)
        attack_idx = classes.index(1) if 1 in classes else -1
        return round(float(probs[attack_idx]) if attack_idx >= 0 else 0.0, 4)

    def _get_shap_features(
        self, X_scaled: np.ndarray, session_id: str, k: int = 5
    ) -> list[dict]:
        """
        Compute SHAP top-k features.  Results are cached per session for SHAP_CACHE_TTL.
        Falls back to |feature| magnitude if SHAP fails.
        """
        now = time.monotonic()
        if session_id in _shap_cache:
            cached, ts = _shap_cache[session_id]
            if now - ts < SHAP_CACHE_TTL:
                return cached

        top_features = []
        try:
            # Use RF explainer preferentially (class-conditional SHAP)
            explainer = self._rf_explainer or self._iso_explainer
            if explainer is not None:
                sv = explainer.shap_values(X_scaled.reshape(1, -1))
                # For RF multi-output, take attack class (index 1)
                if isinstance(sv, list) and len(sv) > 1:
                    vals = np.abs(sv[1][0])
                else:
                    vals = np.abs(sv[0]) if hasattr(sv, '__len__') else np.abs(sv[0])
                idx_sorted = np.argsort(vals)[::-1]
                total = float(np.sum(vals)) or 1.0
                top_features = [
                    {
                        "name": FEATURE_NAMES[i],
                        "contribution": round(min(float(vals[i] / total), 1.0), 4),
                    }
                    for i in idx_sorted[:k]
                ]
        except Exception:
            pass

        if not top_features:
            # Fallback: use raw feature magnitudes as proxy
            magnitudes = np.abs(X_scaled[0])
            total = float(magnitudes.sum()) or 1.0
            idx_sorted = np.argsort(magnitudes)[::-1]
            top_features = [
                {
                    "name": FEATURE_NAMES[i],
                    "contribution": round(min(float(magnitudes[i] / total), 1.0), 4),
                }
                for i in idx_sorted[:k]
            ]

        # Ensure at least 1 feature with valid contribution
        if not top_features:
            top_features = [{"name": "score_unavailable", "contribution": 0.5}]

        _shap_cache[session_id] = (top_features, now)
        return top_features

    def _update_ewma(self, user_id: str, score: float) -> tuple[float, bool]:
        """
        Update per-user EWMA baseline.  Returns (ewma_score, drift_detected).
        """
        history = self._user_baseline[user_id]
        history.append(score)
        if len(history) < BASELINE_WINDOW:
            return score, False
        # Compute short-term EWMA (last 10) vs long-term (all)
        short_window = history[-10:]
        ewma_short = float(np.mean(short_window))
        ewma_long = float(np.mean(history[-BASELINE_WINDOW:]))
        drift = (ewma_short - ewma_long) > DRIFT_THRESHOLD
        return ewma_long, drift

    def score(
        self,
        session_id: str,
        telemetry: dict[str, Any],
        posture: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Compute and return a contract-compliant RiskScore dict.
        Falls back to stub values if models not loaded.
        """
        ts = datetime.now(timezone.utc).isoformat()

        if not self.is_ready():
            # Return stub score with honest model_version label
            return {
                "schema_version": "1.0",
                "session_id": session_id,
                "timestamp": ts,
                "score": 0.23,
                "confidence": 0.50,
                "top_features": [{"name": "model_not_trained", "contribution": 1.0}],
                "model_version": "stub-untrained",
            }

        # Feature extraction + scaling
        vec = extract_features(telemetry, posture)
        X_scaled = self.scaler.transform(vec.reshape(1, -1))

        # Ensemble scoring
        if_score = self._isolation_score(X_scaled)
        rf_prob = self._rf_prob(X_scaled)
        risk = round(0.6 * if_score + 0.4 * rf_prob, 4)
        risk = max(0.0, min(1.0, risk))

        # Confidence: higher when models agree
        agreement = 1.0 - abs(if_score - rf_prob)
        confidence = round(0.5 + 0.5 * agreement, 4)

        # SHAP top features
        top_features = self._get_shap_features(X_scaled, session_id)

        # EWMA drift check
        user_id = telemetry.get("user_id", "unknown")
        _, drift_detected = self._update_ewma(user_id, risk)
        if drift_detected:
            # Boost score if drift detected (adversarial defence)
            risk = min(1.0, risk + 0.15)

        return {
            "schema_version": "1.0",
            "session_id": session_id,
            "timestamp": ts,
            "score": risk,
            "confidence": confidence,
            "top_features": top_features[:10],
            "model_version": self.model_version,
        }


# Singleton instance
_scorer = Scorer()


def get_scorer() -> Scorer:
    return _scorer

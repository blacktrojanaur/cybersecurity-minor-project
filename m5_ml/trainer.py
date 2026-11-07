"""
M5 – ML Risk-Scoring Engine: Training pipeline (OQ4, OQ5).

Models:
  1. Isolation Forest (primary unsupervised anomaly detector)
  2. Random Forest classifier (secondary, trained on labelled synthetic data)
  Ensemble: weighted average (0.6 * IF + 0.4 * RF)

SHAP: TreeExplainer on both models, cached per session window.

Usage:
    python m5_ml/trainer.py --data-dir testbed/data --seed 42
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
)

from m5_ml.features import extract_features, FEATURE_NAMES

MODELS_DIR = Path(__file__).parent / "models"
MODEL_VERSION = "ensemble-v1.0"


def load_ndjson(path: Path) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(ln) for ln in lines if ln.strip()]


def events_to_matrix(
    events: list[dict],
    include_labels: bool = False,
) -> tuple[np.ndarray, list[str] | None]:
    """Convert event dicts to feature matrix X (and optionally labels)."""
    X_rows = []
    labels = [] if include_labels else None
    for ev in events:
        vec = extract_features(ev)
        X_rows.append(vec)
        if include_labels:
            label = ev.get("ground_truth_label", "normal")
            labels.append("attack" if label.startswith("attack") else "normal")  # type: ignore[union-attr]
    return np.array(X_rows, dtype=np.float32), labels


def train(data_dir: Path, seed: int = 42, contamination: float = 0.05) -> dict[str, Any]:
    """
    Train Isolation Forest + Random Forest ensemble on synthetic data.
    Saves models and returns training metadata.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[trainer] Loading training data from {data_dir} ...")
    train_events = load_ndjson(data_dir / "train" / "normal.ndjson")
    print(f"[trainer] Train normal events: {len(train_events)}")

    X_train, _ = events_to_matrix(train_events)

    # ── Scale ─────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # ── Isolation Forest ─────────────────────────────────────────────────
    print(f"[trainer] Training IsolationForest (contamination={contamination}) ...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    iso.fit(X_train_scaled)

    # ── Random Forest on labelled test data ───────────────────────────────
    # Build labelled training set from test files (normal + all attacks)
    labelled_events = load_ndjson(data_dir / "all_labelled.ndjson")
    print(f"[trainer] Labelled events for RF: {len(labelled_events)}")

    rf_model = None
    rf_meta: dict = {}
    if labelled_events:
        X_all, y_str = events_to_matrix(labelled_events, include_labels=True)
        y_bin = np.array([1 if lb == "attack" else 0 for lb in y_str])  # type: ignore[union-attr]
        X_all_scaled = scaler.transform(X_all)

        # 80/20 split for RF evaluation
        n = len(X_all_scaled)
        perm = np.random.default_rng(seed).permutation(n)
        n_train = int(0.8 * n)
        X_rf_tr, y_rf_tr = X_all_scaled[perm[:n_train]], y_bin[perm[:n_train]]
        X_rf_te, y_rf_te = X_all_scaled[perm[n_train:]], y_bin[perm[n_train:]]

        print(f"[trainer] Training RandomForestClassifier ...")
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
        rf_model.fit(X_rf_tr, y_rf_tr)
        y_pred = rf_model.predict(X_rf_te)
        y_prob = rf_model.predict_proba(X_rf_te)[:, 1]
        rf_meta = {
            "precision": float(round(precision_score(y_rf_te, y_pred, zero_division=0), 4)),
            "recall": float(round(recall_score(y_rf_te, y_pred, zero_division=0), 4)),
            "f1": float(round(f1_score(y_rf_te, y_pred, zero_division=0), 4)),
            "roc_auc": float(round(roc_auc_score(y_rf_te, y_prob), 4)),
            "test_samples": len(y_rf_te),
        }
        print(f"[trainer] RF eval: {rf_meta}")

    # ── Persist ───────────────────────────────────────────────────────────
    joblib.dump(iso, MODELS_DIR / "isolation_forest.pkl")
    joblib.dump(scaler, MODELS_DIR / "scaler.pkl")
    if rf_model is not None:
        joblib.dump(rf_model, MODELS_DIR / "random_forest.pkl")

    meta: dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "contamination": contamination,
        "train_samples": len(X_train),
        "features": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "models": ["isolation_forest", "random_forest"],
        "ensemble_weights": {"isolation_forest": 0.6, "random_forest": 0.4},
        "rf_eval": rf_meta,
        "limitations": [
            "Trained on synthetic data only; performance on real traffic unknown.",
            "IsolationForest contamination=0.05 is a design assumption.",
            "SHAP values are approximations; verify with domain experts.",
        ],
    }
    (MODELS_DIR / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[trainer] Models saved to {MODELS_DIR}")
    return meta


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="testbed/data")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()
    train(Path(args.data_dir), seed=args.seed, contamination=args.contamination)

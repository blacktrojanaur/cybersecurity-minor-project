"""
M5 – ML Risk-Scoring Engine: Feedback store for analyst-confirmed labels.

Only accepts labels from confirmed incidents (OQ5 adversarial resilience).
Accumulates labels for periodic retraining.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FEEDBACK_PATH = Path(__file__).parent / "models" / "feedback.jsonl"
_lock = threading.Lock()


def record_feedback(
    session_id: str,
    confirmed_incident: bool,
    event_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Append a confirmed analyst label to the feedback store.

    Only analyst-confirmed labels are written (confirmed_incident must be
    explicitly True or False — not inferred automatically).
    """
    FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "session_id": session_id,
        "confirmed_incident": confirmed_incident,
        "label": "attack" if confirmed_incident else "normal",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "event_snapshot": event_snapshot,
    }
    with _lock:
        with FEEDBACK_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    return record


def load_feedback() -> list[dict[str, Any]]:
    """Return all accumulated feedback records."""
    if not FEEDBACK_PATH.exists():
        return []
    lines = FEEDBACK_PATH.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(ln) for ln in lines if ln.strip()]

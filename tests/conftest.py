"""
Pytest configuration for ZTSP contract tests.

Provides a session-scoped ``schemas`` fixture that pre-loads every JSON schema
from /contracts/ so individual tests don't have to re-read files.
"""

import json
from pathlib import Path

import pytest

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"

SCHEMA_FILES = [
    "telemetry_event.schema.json",
    "risk_score.schema.json",
    "posture_score.schema.json",
    "policy_decision.schema.json",
    "response_action.schema.json",
]


@pytest.fixture(scope="session")
def schemas() -> dict[str, dict]:
    """Load all JSON schemas from the contracts directory once per session."""
    return {
        name: json.loads((CONTRACTS_DIR / name).read_text(encoding="utf-8"))
        for name in SCHEMA_FILES
    }

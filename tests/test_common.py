"""
Unit tests for common/ package (models, auth, schema_validator).
"""

import sys
from pathlib import Path
import pytest

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.models import TelemetryEvent, RiskScore, PostureScore, PolicyDecision, ResponseAction
from common.schema_validator import validate_telemetry_event, validate_risk_score, validate_posture_score, validate_policy_decision, validate_response_action
from common.auth import service_token_headers, SERVICE_TOKEN_HEADER


def test_telemetry_event_model():
    data = {
        "schema_version": "1.0",
        "session_id": "s-123",
        "user_id": "alice",
        "device_id": "d-123",
        "timestamp": "2024-01-01T00:00:00Z",
        "event_type": "access_request",
        "source_ip": "10.0.0.1",
        "geo": {"country": "IN", "city": "Bengaluru", "lat": 12.97, "lon": 77.59},
    }
    model = TelemetryEvent(**data)
    assert model.session_id == "s-123"
    validate_telemetry_event(model.model_dump())


def test_risk_score_model():
    data = {
        "schema_version": "1.0",
        "session_id": "s-123",
        "timestamp": "2024-01-01T00:00:00Z",
        "score": 0.45,
        "confidence": 0.90,
        "top_features": [{"name": "geo_anomaly", "contribution": 0.35}],
        "model_version": "ensemble-v1.0",
    }
    model = RiskScore(**data)
    assert model.score == 0.45
    validate_risk_score(model.model_dump())


def test_service_token_headers():
    headers = service_token_headers()
    assert SERVICE_TOKEN_HEADER in headers
    assert len(headers[SERVICE_TOKEN_HEADER]) > 0

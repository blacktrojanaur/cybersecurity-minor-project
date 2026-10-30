"""
Contract tests for ZTSP Phase 1.
=====================================
Validates that:
1. All schema files exist in /contracts/.
2. Mock payloads (mirroring what stubs return) are valid against each schema.
3. Deliberately invalid payloads are correctly rejected.

These tests do NOT require running Docker containers.
They validate the contracts and stub mock data in isolation.

Run with: pytest tests/ -v
"""

import json
from pathlib import Path

import jsonschema
import pytest

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"


# ═══════════════════════════════════════════════════════════════════════════════
# Inline mock payloads  –  must mirror what each stub endpoint returns
# ═══════════════════════════════════════════════════════════════════════════════

MOCK_TELEMETRY_EVENT = {
    "schema_version": "1.0",
    "session_id": "sess-mock-001",
    "user_id": "user-mock-001",
    "device_id": "dev-mock-001",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "event_type": "access_request",
    "source_ip": "192.168.1.100",
    "geo": {"country": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    "user_agent": "Mozilla/5.0 (stub)",
    "raw_features": {"bytes_sent": 1024, "session_duration": 300},
}

MOCK_RISK_SCORE = {
    "schema_version": "1.0",
    "session_id": "sess-mock-001",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "score": 0.23,
    "confidence": 0.87,
    "top_features": [
        {"name": "geo_anomaly",      "contribution": 0.12},
        {"name": "off_hours_access", "contribution": 0.07},
        {"name": "new_device",       "contribution": 0.04},
    ],
    "model_version": "stub-v1.0",
}

MOCK_POSTURE_SCORE = {
    "schema_version": "1.0",
    "device_id": "dev-mock-001",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "patch_level": 0.85,
    "vuln_count": 3,
    "critical_vuln_count": 0,
    "os_compliant": True,
    "antivirus_active": True,
    "posture_score": 0.78,
}

MOCK_POLICY_DECISION = {
    "schema_version": "1.0",
    "session_id": "sess-mock-001",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "decision": "allow",
    "reason": "Risk score below threshold; posture compliant. (stub)",
    "ttl_seconds": 300,
    "applied_policies": ["policy-baseline-rbac", "policy-geo-allow"],
}

MOCK_RESPONSE_ACTION = {
    "schema_version": "1.0",
    "session_id": "sess-mock-001",
    "timestamp": "2024-01-01T00:00:00+00:00",
    "action_type": "notify_user",
    "trigger_reason": "Routine policy enforcement check. (stub)",
    "status": "executed",
    "metadata": {"notified_at": "2024-01-01T00:00:01+00:00"},
}


# ═══════════════════════════════════════════════════════════════════════════════
# Helper
# ═══════════════════════════════════════════════════════════════════════════════

def load_schema(filename: str) -> dict:
    """Read and parse a JSON schema from /contracts/."""
    path = CONTRACTS_DIR / filename
    assert path.exists(), f"Schema file not found: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def assert_valid(payload: dict, schema_filename: str) -> None:
    """Assert that *payload* validates successfully against *schema_filename*."""
    schema = load_schema(schema_filename)
    jsonschema.validate(instance=payload, schema=schema)  # raises ValidationError on failure


def assert_invalid(payload: dict, schema_filename: str) -> None:
    """Assert that *payload* correctly fails validation against *schema_filename*."""
    schema = load_schema(schema_filename)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=payload, schema=schema)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Schema file existence tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestContractFilesExist:
    """Verify every contract artefact is present in /contracts/."""

    @pytest.mark.parametrize("schema_file", [
        "telemetry_event.schema.json",
        "risk_score.schema.json",
        "posture_score.schema.json",
        "policy_decision.schema.json",
        "response_action.schema.json",
    ])
    def test_schema_file_exists(self, schema_file: str) -> None:
        assert (CONTRACTS_DIR / schema_file).exists(), f"Missing: contracts/{schema_file}"

    def test_openapi_yaml_exists(self) -> None:
        assert (CONTRACTS_DIR / "openapi.yaml").exists(), "Missing: contracts/openapi.yaml"

    def test_changelog_exists(self) -> None:
        assert (CONTRACTS_DIR / "CHANGELOG.md").exists(), "Missing: contracts/CHANGELOG.md"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TelemetryEvent (M1 → M5, M4)
# ═══════════════════════════════════════════════════════════════════════════════

class TestTelemetryEventSchema:
    """Validate telemetry_event.schema.json against mock and adversarial payloads."""

    SCHEMA = "telemetry_event.schema.json"

    def test_mock_payload_is_valid(self) -> None:
        assert_valid(MOCK_TELEMETRY_EVENT, self.SCHEMA)

    def test_minimal_required_only_is_valid(self) -> None:
        """Payload with only required fields should pass."""
        minimal = {
            "session_id": "s1",
            "user_id": "u1",
            "device_id": "d1",
            "timestamp": "2024-06-01T00:00:00+00:00",
            "event_type": "login",
            "source_ip": "10.0.0.1",
        }
        assert_valid(minimal, self.SCHEMA)

    def test_missing_session_id_fails(self) -> None:
        bad = {k: v for k, v in MOCK_TELEMETRY_EVENT.items() if k != "session_id"}
        assert_invalid(bad, self.SCHEMA)

    def test_missing_user_id_fails(self) -> None:
        bad = {k: v for k, v in MOCK_TELEMETRY_EVENT.items() if k != "user_id"}
        assert_invalid(bad, self.SCHEMA)

    def test_invalid_event_type_fails(self) -> None:
        bad = {**MOCK_TELEMETRY_EVENT, "event_type": "unknown_event_xyz"}
        assert_invalid(bad, self.SCHEMA)

    def test_all_valid_event_types_pass(self) -> None:
        valid_types = [
            "login", "access_request", "file_access",
            "lateral_move_attempt", "auth_failure", "logout",
            "privilege_escalation_attempt",
        ]
        for et in valid_types:
            payload = {**MOCK_TELEMETRY_EVENT, "event_type": et}
            assert_valid(payload, self.SCHEMA)

    def test_wrong_schema_version_fails(self) -> None:
        bad = {**MOCK_TELEMETRY_EVENT, "schema_version": "2.0"}
        assert_invalid(bad, self.SCHEMA)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. RiskScore (M5 → M2, M3)
# ═══════════════════════════════════════════════════════════════════════════════

class TestRiskScoreSchema:
    """Validate risk_score.schema.json."""

    SCHEMA = "risk_score.schema.json"

    def test_mock_payload_is_valid(self) -> None:
        assert_valid(MOCK_RISK_SCORE, self.SCHEMA)

    def test_score_at_boundary_zero_valid(self) -> None:
        assert_valid({**MOCK_RISK_SCORE, "score": 0.0}, self.SCHEMA)

    def test_score_at_boundary_one_valid(self) -> None:
        assert_valid({**MOCK_RISK_SCORE, "score": 1.0}, self.SCHEMA)

    def test_score_above_one_fails(self) -> None:
        assert_invalid({**MOCK_RISK_SCORE, "score": 1.0001}, self.SCHEMA)

    def test_score_below_zero_fails(self) -> None:
        assert_invalid({**MOCK_RISK_SCORE, "score": -0.01}, self.SCHEMA)

    def test_empty_top_features_fails(self) -> None:
        """minItems: 1 must be enforced."""
        assert_invalid({**MOCK_RISK_SCORE, "top_features": []}, self.SCHEMA)

    def test_missing_model_version_fails(self) -> None:
        bad = {k: v for k, v in MOCK_RISK_SCORE.items() if k != "model_version"}
        assert_invalid(bad, self.SCHEMA)

    def test_feature_contribution_above_one_fails(self) -> None:
        bad = {
            **MOCK_RISK_SCORE,
            "top_features": [{"name": "x", "contribution": 1.5}],
        }
        assert_invalid(bad, self.SCHEMA)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. PostureScore (M4 → M5, M2)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPostureScoreSchema:
    """Validate posture_score.schema.json."""

    SCHEMA = "posture_score.schema.json"

    def test_mock_payload_is_valid(self) -> None:
        assert_valid(MOCK_POSTURE_SCORE, self.SCHEMA)

    def test_fully_compliant_device_valid(self) -> None:
        perfect = {**MOCK_POSTURE_SCORE, "patch_level": 1.0, "vuln_count": 0,
                   "critical_vuln_count": 0, "posture_score": 1.0}
        assert_valid(perfect, self.SCHEMA)

    def test_patch_level_above_one_fails(self) -> None:
        assert_invalid({**MOCK_POSTURE_SCORE, "patch_level": 1.1}, self.SCHEMA)

    def test_negative_vuln_count_fails(self) -> None:
        assert_invalid({**MOCK_POSTURE_SCORE, "vuln_count": -1}, self.SCHEMA)

    def test_negative_critical_vuln_fails(self) -> None:
        assert_invalid({**MOCK_POSTURE_SCORE, "critical_vuln_count": -1}, self.SCHEMA)

    def test_missing_os_compliant_fails(self) -> None:
        bad = {k: v for k, v in MOCK_POSTURE_SCORE.items() if k != "os_compliant"}
        assert_invalid(bad, self.SCHEMA)

    def test_posture_score_out_of_range_fails(self) -> None:
        assert_invalid({**MOCK_POSTURE_SCORE, "posture_score": 2.0}, self.SCHEMA)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. PolicyDecision (M2 → M1, M3)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyDecisionSchema:
    """Validate policy_decision.schema.json."""

    SCHEMA = "policy_decision.schema.json"

    def test_mock_payload_is_valid(self) -> None:
        assert_valid(MOCK_POLICY_DECISION, self.SCHEMA)

    @pytest.mark.parametrize("decision", ["allow", "step_up", "restrict", "deny"])
    def test_all_valid_decisions_pass(self, decision: str) -> None:
        payload = {**MOCK_POLICY_DECISION, "decision": decision}
        assert_valid(payload, self.SCHEMA)

    def test_invalid_decision_fails(self) -> None:
        assert_invalid({**MOCK_POLICY_DECISION, "decision": "maybe"}, self.SCHEMA)

    def test_ttl_below_minimum_fails(self) -> None:
        """TTL minimum is 30 s."""
        assert_invalid({**MOCK_POLICY_DECISION, "ttl_seconds": 29}, self.SCHEMA)

    def test_ttl_at_minimum_valid(self) -> None:
        assert_valid({**MOCK_POLICY_DECISION, "ttl_seconds": 30}, self.SCHEMA)

    def test_ttl_above_maximum_fails(self) -> None:
        """TTL maximum is 3600 s (1 hour)."""
        assert_invalid({**MOCK_POLICY_DECISION, "ttl_seconds": 3601}, self.SCHEMA)

    def test_ttl_at_maximum_valid(self) -> None:
        assert_valid({**MOCK_POLICY_DECISION, "ttl_seconds": 3600}, self.SCHEMA)

    def test_empty_reason_fails(self) -> None:
        assert_invalid({**MOCK_POLICY_DECISION, "reason": ""}, self.SCHEMA)

    def test_missing_ttl_fails(self) -> None:
        bad = {k: v for k, v in MOCK_POLICY_DECISION.items() if k != "ttl_seconds"}
        assert_invalid(bad, self.SCHEMA)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ResponseAction (M3 → M1, M2)
# ═══════════════════════════════════════════════════════════════════════════════

class TestResponseActionSchema:
    """Validate response_action.schema.json."""

    SCHEMA = "response_action.schema.json"

    def test_mock_payload_is_valid(self) -> None:
        assert_valid(MOCK_RESPONSE_ACTION, self.SCHEMA)

    @pytest.mark.parametrize("action_type", [
        "terminate_session", "require_mfa", "restrict_access",
        "alert_soc", "block_ip", "notify_user",
    ])
    def test_all_valid_action_types_pass(self, action_type: str) -> None:
        payload = {**MOCK_RESPONSE_ACTION, "action_type": action_type}
        assert_valid(payload, self.SCHEMA)

    def test_invalid_action_type_fails(self) -> None:
        assert_invalid({**MOCK_RESPONSE_ACTION, "action_type": "do_nothing"}, self.SCHEMA)

    @pytest.mark.parametrize("status", ["pending", "executed", "failed"])
    def test_all_valid_statuses_pass(self, status: str) -> None:
        payload = {**MOCK_RESPONSE_ACTION, "status": status}
        assert_valid(payload, self.SCHEMA)

    def test_invalid_status_fails(self) -> None:
        assert_invalid({**MOCK_RESPONSE_ACTION, "status": "unknown"}, self.SCHEMA)

    def test_missing_trigger_reason_fails(self) -> None:
        bad = {k: v for k, v in MOCK_RESPONSE_ACTION.items() if k != "trigger_reason"}
        assert_invalid(bad, self.SCHEMA)

    def test_optional_metadata_can_be_absent(self) -> None:
        """metadata is not required – payload without it should still pass."""
        payload = {k: v for k, v in MOCK_RESPONSE_ACTION.items() if k != "metadata"}
        assert_valid(payload, self.SCHEMA)

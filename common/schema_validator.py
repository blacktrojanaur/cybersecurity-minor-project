"""
common.schema_validator – Runtime JSON Schema validation helper.

Validates dict payloads against the frozen contract schemas in /contracts/.
Use this at service boundaries to catch contract drift early.

Usage:
    from common.schema_validator import validate_payload, ContractError

    try:
        validate_payload(payload, "risk_score.schema.json")
    except ContractError as e:
        log.error("contract_violation", detail=str(e))
"""

import json
from pathlib import Path
from typing import Any

import jsonschema
import jsonschema.validators

# Resolve /contracts/ relative to this file (common/ is at project root)
_CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"

# Cache loaded schemas in memory
_schema_cache: dict[str, dict] = {}


class ContractError(ValueError):
    """Raised when a payload does not conform to a contract schema."""


def _load_schema(filename: str) -> dict:
    if filename not in _schema_cache:
        path = _CONTRACTS_DIR / filename
        if not path.exists():
            raise FileNotFoundError(f"Contract schema not found: {path}")
        _schema_cache[filename] = json.loads(path.read_text(encoding="utf-8"))
    return _schema_cache[filename]


def validate_payload(payload: Any, schema_filename: str) -> None:
    """
    Validate *payload* against the named JSON schema.

    Raises:
        ContractError: if validation fails.
        FileNotFoundError: if the schema file is missing.
    """
    schema = _load_schema(schema_filename)
    try:
        jsonschema.validate(instance=payload, schema=schema)
    except jsonschema.ValidationError as exc:
        raise ContractError(
            f"Contract violation [{schema_filename}]: {exc.message} "
            f"at path {list(exc.absolute_path)}"
        ) from exc


def validate_telemetry_event(payload: dict) -> None:
    validate_payload(payload, "telemetry_event.schema.json")


def validate_risk_score(payload: dict) -> None:
    validate_payload(payload, "risk_score.schema.json")


def validate_posture_score(payload: dict) -> None:
    validate_payload(payload, "posture_score.schema.json")


def validate_policy_decision(payload: dict) -> None:
    validate_payload(payload, "policy_decision.schema.json")


def validate_response_action(payload: dict) -> None:
    validate_payload(payload, "response_action.schema.json")

# Contracts CHANGELOG

All inter-module interface changes must be recorded here.
**Rule**: Any modification to a schema or OpenAPI spec requires approval from all five team members before merging. Open a PR, tag all reviewers, and add an entry below.

---

## [1.0.0] – 2024-10-21 (Phase 1 freeze)

### Added
- `telemetry_event.schema.json` (M1 → M5, M4) — initial version
- `risk_score.schema.json` (M5 → M2, M3) — initial version
- `posture_score.schema.json` (M4 → M5, M2) — initial version
- `policy_decision.schema.json` (M2 → M1, M3) — initial version
- `response_action.schema.json` (M3 → M1, M2) — initial version
- `openapi.yaml` — aggregated REST API spec for all five services

### Notes
- All schemas are JSON Schema Draft-07.
- `schema_version: "1.0"` is the const value for this release.
- Phase 1 stubs return hardcoded mock payloads that validate against these schemas.
- Breaking changes (removing/renaming required fields, changing enum values) require a major version bump and a new PR.
- Non-breaking additions (new optional fields) require a minor version bump.

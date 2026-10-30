# 02 – Requirements Specification

**Project**: AI-Augmented Zero Trust Security Orchestration Platform
**Phase**: 1 – Research, Requirements & Design
**Version**: 1.0

---

## 1. Scope and Assumptions

**Assumption A1**: The prototype is a research demonstrator, not a production system.
Security hardening beyond what is required to demonstrate the concepts is out of scope.

**Assumption A2**: All five services run on a single laptop (≤ 16 GB RAM) via Docker Compose.

**Assumption A3**: In Phase 1, real identity providers, real vulnerability scanners, and live network
enforcement are replaced by stubs. Phase 2 integrates real data sources.

**Assumption A4**: "Detection accuracy" and "false-positive rate" will be measured against
synthetic telemetry datasets with ground-truth labels. No real user data is used.

---

## 2. Functional Requirements

### M1 – Identity & Context Engine

| ID | Requirement |
|---|---|
| M1-F1 | SHALL accept session telemetry events in the TelemetryEvent schema format (POST /telemetry/events). |
| M1-F2 | SHALL enrich events with geo-IP context (country, city, lat/lon) using a local lookup library. |
| M1-F3 | SHALL maintain a per-session context store keyed by session_id. |
| M1-F4 | SHALL forward enriched events to M5 (/score) and M4 (/posture/{device_id}) on every access request. |
| M1-F5 | SHALL enforce the policy decision received from M2, either granting or blocking access. |
| M1-F6 | SHALL trigger re-evaluation by calling M2 /policy/evaluate when a policy TTL expires. |

### M2 – Policy Enforcement & Micro-segmentation

| ID | Requirement |
|---|---|
| M2-F1 | SHALL evaluate a policy decision (allow / step_up / restrict / deny) given risk_score and posture_score inputs. |
| M2-F2 | SHALL apply a configurable rule set stored in a YAML policy file (Phase 2). |
| M2-F3 | SHALL set TTL on every decision proportional to risk (high risk → shorter TTL). |
| M2-F4 | SHALL persist every decision in an append-only audit log with session_id, timestamp, decision, and reason. |
| M2-F5 | SHALL support per-session micro-segmentation flags (read-only, no-lateral, egress-block) in Phase 2. |

### M3 – Automated Incident Response (SOAR-lite)

| ID | Requirement |
|---|---|
| M3-F1 | SHALL trigger an automated response action when called with a step_up, restrict, or deny decision. |
| M3-F2 | SHALL map decision types to action types: step_up → require_mfa; restrict → restrict_access; deny → terminate_session + alert_soc. |
| M3-F3 | SHALL log every response action with session_id, action_type, timestamp, and status. |
| M3-F4 | SHALL dispatch an escalation alert if no MFA response is received within a configurable timeout (Phase 2). |
| M3-F5 | SHALL provide a GET /response/{session_id} endpoint returning the full action history for a session. |

### M4 – Vulnerability & Posture Integration

| ID | Requirement |
|---|---|
| M4-F1 | SHALL compute a composite posture_score [0, 1] from patch_level, vuln_count, os_compliant, and antivirus_active. |
| M4-F2 | SHALL expose GET /posture/{device_id} returning a PostureScore within 500 ms (cached). |
| M4-F3 | SHALL support on-demand re-scan via POST /posture/scan. |
| M4-F4 | SHALL treat any device with critical_vuln_count > 0 as non-compliant (posture_score ≤ 0.3) regardless of other fields. |
| M4-F5 | SHALL accept vulnerability feeds from at least one external source (NVD API or Nessus CSV) in Phase 2. |

### M5 – ML Risk-Scoring Engine

| ID | Requirement |
|---|---|
| M5-F1 | SHALL accept a TelemetryEvent and optional PostureScore and return a RiskScore within 200 ms. |
| M5-F2 | SHALL produce a continuous risk score in [0.0, 1.0] with four decimal places. |
| M5-F3 | SHALL return the top 3–5 contributing features with SHAP-style contribution values for auditability. |
| M5-F4 | SHALL implement an Isolation Forest baseline as the Phase 2 primary model. |
| M5-F5 | SHALL accept ground-truth feedback labels from M3 (confirmed incidents) to support periodic re-training. |
| M5-F6 | SHALL version all trained models and allow hot-swap without service restart (Phase 2). |

---

## 3. Non-Functional Requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-1 | Performance | End-to-end latency from event receipt (M1) to policy decision (M2) SHALL be ≤ 500 ms at the p95 percentile under simulated load of 100 concurrent sessions. |
| NFR-2 | Availability | All stubs SHALL start within 30 s of `docker compose up` and remain available for 1 hour without restart. |
| NFR-3 | Auditability | Every policy decision SHALL be logged with a globally unique (session_id, timestamp) tuple. Log records SHALL be append-only. |
| NFR-4 | Schema consistency | All inter-module messages SHALL validate against the contracts/ JSON schemas (version 1.0) at runtime in Phase 2. |
| NFR-5 | Portability | The full system SHALL run on a commodity laptop (8 GB RAM, 4 cores) via `docker compose up`. |
| NFR-6 | Maintainability | All Python code SHALL use type hints and docstrings. Lint target: zero ruff errors. |
| NFR-7 | Security | No real credentials, PII, or exploit code SHALL appear in the repository. All sample data SHALL be synthetic. |

---

## 4. Measurable Success Metrics (Phase 2 Evaluation Targets)

> **Important**: The values below are *design targets and assumptions*, not experimentally verified benchmarks.
> They will be measured against synthetic datasets in Phase 2.

| Metric | Target | Measurement Method |
|---|---|---|
| **Detection Accuracy** (true positive rate) | ≥ 85% | Precision-recall on labelled synthetic dataset |
| **False-Positive Rate** | ≤ 5% | FP / (FP + TN) on normal-behaviour test set |
| **Mean Time to Respond (MTTR)** | ≤ 30 s from anomaly detection to M3 action | Timestamp delta: M5 score timestamp → M3 action timestamp |
| **Policy-Adaptation Latency** | ≤ 5 s from TTL expiry to new policy decision | Timestamp delta: TTL expiry event → M2 decision timestamp |
| **Service Availability** | 99% uptime over 1-hour demo | Docker health check pass rate |

---

## 5. Static RBAC Baseline (Comparison Reference)

The system will be compared against a **static role-based access control (RBAC) baseline** as a control condition.

| Property | Static RBAC Baseline | ZTSP (Our System) |
|---|---|---|
| Trust evaluation | Once at login | Continuously (TTL-driven) |
| Risk scoring | None | ML risk score [0, 1] |
| Posture awareness | None | Real-time patch/vuln status |
| Lateral movement detection | None | Telemetry anomaly detection |
| Response to anomaly | Manual (IT ticket) | Automated (M3 SOAR-lite) |
| Audit trail | Login logs only | Per-event, per-decision audit |
| False-positive burden | High (broad deny rules) | Targeted (score-threshold) |

**Assumption**: The baseline RBAC system grants access if the user has the required role, regardless of device posture, session behaviour, or time-of-day context.

---

*Document owner: Shared (all five team members review). Freeze before Phase 2 kickoff.*

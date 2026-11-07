# 07 – Architecture & Design Decisions Log

**Project**: AI-Augmented Zero Trust Security Orchestration Platform (ZTSP)  
**Status**: Settled for Phase 2 Prototype  
**Date**: October 2026

---

## Overview

This document records the architectural decisions settling Open Questions (OQ1–OQ7) raised during Phase 1. These decisions enable complete, unattended closed-loop Zero Trust operation at research-grade fidelity.

---

### DEC-01 (OQ1): Session State and Revocation Model
- **Decision**: Server-side stateful session IDs (`sess-<user_id>-<uuid>`) stored in M1 with instantaneous revocation support, rather than stateless JWTs.
- **Rationale**: Stateless JWTs cannot be revoked without maintaining distributed blocklists. In Zero Trust, instantaneous session termination upon anomaly detection is a core requirement (NIST SP 800-207 Tenet 5).
- **Consequence**: Session context is maintained in memory by M1, with an append-only audit trail. M2 and M3 synchronize session state via REST calls.

---

### DEC-02 (OQ2): Dual-Trigger Continuous Re-Evaluation Loop
- **Decision**: Continuous evaluation operates via dual triggers:
  1. **Event-driven**: Any new `TelemetryEvent` immediately triggers re-scoring and policy re-evaluation.
  2. **TTL-driven**: Background asyncio loop in M1 monitors expired session TTLs (inverse to risk: 30s for high risk, 300s for low risk) and forces re-evaluation with fresh posture from M4.
- **Rationale**: Telemetry alone may be sparse during idle sessions; TTL expiration ensures that degrading device posture (e.g., new CVE or disabled antivirus) is caught even without user activity.

---

### DEC-03 (OQ3): Micro-Segmentation and Policy Enforcement (PDP/PEP)
- **Decision**: Decoupled Policy Decision Point (PDP) in M2 and Policy Enforcement Point (PEP) integrated into the protected resource application (port 8090).
- **Rationale**: M2 maintains priority-ordered, versioned YAML rules (`m2_policy/config/rules.yaml`) and segment definitions (`segments.yaml`). The resource application checks every HTTP request against M2 before serving data.
- **Consequence**: Zero Trust micro-segmentation is enforced at request boundary. An attacker moving between `/code` and `/finance` is challenged or blocked regardless of network layer access.

---

### DEC-04 (OQ4): Synthetic Telemetry Generation & Limitations
- **Decision**: Seeded synthetic telemetry generator (`testbed/generate_telemetry.py`, seed=42) generating 10,000 normal events across 10 realistic employee personas, plus dedicated suites for S1–S4 attack scenarios.
- **Rationale**: Public Zero Trust enterprise telemetry datasets are nonexistent or lack unified posture/identity correlation.
- **Honest Limitations**:
  - Profiles are simulated draws from Gaussian/uniform distributions; real enterprise traffic exhibits heavier-tailed burstiness.
  - Attack sequences represent scripted threat models; actual adversaries may deploy novel evasion techniques.

---

### DEC-05 (OQ5): ML Model Ensemble & Adversarial Resilience
- **Decision**: Hybrid ensemble combining **Isolation Forest** (0.6 weight, unsupervised anomaly detection) and **Random Forest** (0.4 weight, supervised classification on known attack patterns), augmented with **SHAP TreeExplainer** feature attributions.
- **Adversarial Mitigations**:
  - Per-user Exponentially Weighted Moving Average (EWMA) tracking long-term baseline drift to defeat slow-and-low attacks (S4).
  - Feature value clipping in `m5_ml/features.py` to prevent adversarial manipulation of unbounded inputs.
  - Analyst feedback store (`m5_ml/models/feedback.jsonl`) accepting only confirmed incident labels to prevent model poisoning.

---

### DEC-06 (OQ6): Service-to-Service Authentication
- **Decision**: Shared-secret `X-Service-Token` header enforced across all inter-service endpoints via FastAPI dependency `require_service_token`.
- **Rationale**: Secures the control plane inside the Docker bridge network (`zt-net`) against unauthorized service impersonation. Token is loaded from `SERVICE_TOKEN` environment variable and never committed to version control.

---

### DEC-07 (OQ7): Externalized YAML Posture Weights
- **Decision**: Device posture scoring formula in M4 is externalized into `m4_posture/config/posture_weights.yaml`.
- **Rationale**: Security teams must be able to tune compliance priorities (e.g., weighing disk encryption vs patch age) without modifying Python code.
- **Consequence**: M4 loads weights at startup and supports dynamic hot-reload.

# 06 – Module Briefs

**Project**: AI-Augmented Zero Trust Security Orchestration Platform
**Phase**: 1 – Research, Requirements & Design

> One brief per module. Each brief is the single source of truth for the module owner.
> Interfaces reference `contracts/openapi.yaml` and the JSON schemas in `/contracts/`.

---

## M1 – Identity & Context Engine

**Owner**: Team member 1
**Service port**: 8001
**Stub**: `m1_identity/main.py`

### Inputs
| Source | Format | Transport |
|---|---|---|
| End user / access proxy | HTTP access request with credentials | Direct (simulated) |
| M2 Policy Enforcement | `PolicyDecision` JSON | REST GET `/policy/{session_id}` |
| M4 Posture | `PostureScore` JSON | REST GET `/posture/{device_id}` |
| M5 ML Scoring | `RiskScore` JSON | REST POST `/score` response |

### Outputs
| Destination | Format | Transport |
|---|---|---|
| M5 ML Scoring | `TelemetryEvent` JSON | REST POST `/score` (body) |
| M4 Posture | Device ID | REST GET `/posture/{device_id}` path param |
| M2 Policy | Evaluation request `{session_id, risk_score, posture_score}` | REST POST `/policy/evaluate` |
| M3 Response | `{session_id, decision, reason}` | REST POST `/response/trigger` |
| Protected Resource | Access grant or block | (simulated enforcement) |

### Interface Contracts
- **Produces**: `TelemetryEvent` (see `contracts/telemetry_event.schema.json`)
- **Consumes**: `RiskScore`, `PostureScore`, `PolicyDecision`, `ResponseAction`

### Definition of Done (Phase 2)
- [ ] Geo-IP enrichment via MaxMind GeoLite2 (local DB lookup, no API call per request)
- [ ] Session store (in-memory dict keyed by `session_id`) with TTL eviction
- [ ] Re-evaluation trigger fires when TTL from M2 expires
- [ ] `POST /telemetry/events` validates against schema and returns 202 with session_id
- [ ] Integration test: full access-decision loop completes in ≤ 500 ms

### Week-by-Week Tasks (Weeks 2–4)

**Week 2 – Core implementation**
- Replace stub `/session/{session_id}` with real in-memory session store
- Implement geo-IP lookup (MaxMind GeoLite2 city DB)
- Wire real calls to M4 `/posture/{device_id}` and M5 `/score`
- Wire real call to M2 `/policy/evaluate`

**Week 3 – Integration**
- Implement TTL re-evaluation loop (threading or asyncio background task)
- Wire M3 trigger on step_up / deny decisions
- Write integration test: inject event → verify policy decision received

**Week 4 – Evaluation prep**
- Connect synthetic telemetry injector (from /testbed)
- Measure end-to-end latency for 100 concurrent sessions
- Document any schema changes via contracts/CHANGELOG.md

---

## M2 – Policy Enforcement & Micro-segmentation

**Owner**: Team member 2
**Service port**: 8002
**Stub**: `m2_policy/main.py`

### Inputs
| Source | Format | Transport |
|---|---|---|
| M1 Identity | `{session_id, risk_score, posture_score}` | REST POST `/policy/evaluate` |

### Outputs
| Destination | Format | Transport |
|---|---|---|
| M1 Identity | `PolicyDecision` JSON | REST POST `/policy/evaluate` response |
| M3 Response | `{session_id, decision, reason}` | REST POST `/response/trigger` (called by M1 or M2) |

### Interface Contracts
- **Produces**: `PolicyDecision` (see `contracts/policy_decision.schema.json`)
- **Consumes**: `{session_id, risk_score, posture_score}` (inline request body, defined in openapi.yaml)

### Decision Rule Logic (Phase 2 Implementation Target)

```python
# Pseudo-code for Phase 2 rule engine (NOT implemented in Phase 1)
if risk_score < 0.40 and posture_score > 0.60:
    decision = "allow";    ttl = 300
elif risk_score < 0.70 and posture_score > 0.40:
    decision = "step_up";  ttl = 60
elif posture.critical_vuln_count > 0:
    decision = "deny";     ttl = 30
else:
    decision = "restrict"; ttl = 120
```

### Definition of Done (Phase 2)
- [ ] YAML-based policy rule file loaded at startup
- [ ] Rule engine evaluates risk + posture and applies rules in priority order
- [ ] Audit log: every decision written to `decisions.jsonl` (append-only)
- [ ] TTL proportional to risk level (see table in docs/04-architecture.md)
- [ ] Integration test: verify `deny` decision for `risk_score=0.9`

### Week-by-Week Tasks (Weeks 2–4)

**Week 2 – Rule engine**
- Design YAML policy rule schema (priority, threshold, decision, ttl)
- Implement rule engine evaluating rules in priority order
- Implement `decisions.jsonl` append-only audit log

**Week 3 – Integration**
- Wire real calls from M1 `/policy/evaluate` (stop returning mock data)
- Implement `GET /policy/{session_id}` lookup from in-memory decision cache
- Add TTL-proportional logic

**Week 4 – Evaluation prep**
- Load test rule engine with 1000 decisions/minute
- Measure policy-adaptation latency (target ≤ 5 s from TTL expiry to new decision)
- Validate audit log completeness

---

## M3 – Automated Incident Response (SOAR-lite)

**Owner**: Team member 3
**Service port**: 8003
**Stub**: `m3_response/main.py`

### Inputs
| Source | Format | Transport |
|---|---|---|
| M1 / M2 | `{session_id, decision, reason}` | REST POST `/response/trigger` |

### Outputs
| Destination | Format | Transport |
|---|---|---|
| M1 / M2 | `ResponseAction` JSON | REST POST `/response/trigger` response |
| SOC / SIEM | Alert payload | Webhook (Phase 2) |
| M5 | `{session_id, confirmed_incident}` | REST POST `/feedback` (Phase 2) |

### Interface Contracts
- **Produces**: `ResponseAction` (see `contracts/response_action.schema.json`)

### Action Mapping (Phase 2)
| Decision | Action Type | Implementation |
|---|---|---|
| `step_up` | `require_mfa` | Dispatch TOTP/email challenge |
| `restrict` | `restrict_access` | Signal M2 to apply read-only policy |
| `deny` | `terminate_session` + `alert_soc` | Revoke token; POST to SIEM webhook |

### Definition of Done (Phase 2)
- [ ] Action dispatcher maps decision → action_type correctly
- [ ] Response actions logged to `actions.jsonl` (append-only)
- [ ] SOC alert webhook configurable via environment variable
- [ ] `GET /response/{session_id}` returns chronological action history
- [ ] MFA escalation timer: alert SOC if MFA not completed within 120 s

### Week-by-Week Tasks (Weeks 2–4)

**Week 2 – Action dispatcher**
- Implement decision → action_type mapping
- Implement `actions.jsonl` audit log
- Stub SOC webhook (log to file; real HTTP call in Week 3)

**Week 3 – Integration**
- Wire real call to SOC webhook endpoint (configurable via env var)
- Implement MFA escalation timer
- Implement feedback call to M5 `/feedback` on confirmed incidents

**Week 4 – Evaluation**
- Measure MTTR: incident detection timestamp → response action timestamp
- Target: MTTR ≤ 30 s
- Tabulate action counts by type from `actions.jsonl`

---

## M4 – Vulnerability & Posture Integration

**Owner**: Team member 4
**Service port**: 8004
**Stub**: `m4_posture/main.py`

### Inputs
| Source | Format | Transport |
|---|---|---|
| Vulnerability scanner / NVD API | CVE / patch data | HTTP pull (Phase 2) |
| M1 Identity | `device_id` | REST GET `/posture/{device_id}` path param |

### Outputs
| Destination | Format | Transport |
|---|---|---|
| M1 (forwarded to M5) | `PostureScore` JSON | REST GET `/posture/{device_id}` response |
| M2 | `PostureScore` JSON | REST GET `/posture/{device_id}` response |

### Interface Contracts
- **Produces**: `PostureScore` (see `contracts/posture_score.schema.json`)

### Posture Score Formula (Phase 2 implementation target)

```
posture_score = (
    0.40 * patch_level
  + 0.30 * (1.0 if os_compliant else 0.0)
  + 0.20 * (1.0 if antivirus_active else 0.0)
  + 0.10 * max(0, 1 - vuln_count / 10)
)
# Override: if critical_vuln_count > 0 → posture_score = min(posture_score, 0.30)
```

**Assumption**: Weights above are initial guesses; calibrate against expert judgment in Phase 2.

### Definition of Done (Phase 2)
- [ ] NVD API poller fetches CVE data for registered device OS/app versions
- [ ] Posture score computed using formula above
- [ ] Score cached per device_id with 5-minute staleness TTL
- [ ] `POST /posture/scan` queues a re-scan and returns a job_id
- [ ] Integration test: verify `posture_score ≤ 0.30` when `critical_vuln_count > 0`

### Week-by-Week Tasks (Weeks 2–4)

**Week 2 – Core computation**
- Implement posture score formula with configurable weights
- Build device registry (JSON file: device_id → OS version, app list)
- Implement NVD API poller (one CVE lookup per device OS version)

**Week 3 – Integration**
- Cache posture scores in-memory with 5-minute TTL
- Wire `GET /posture/{device_id}` to return from cache or recompute
- Add `critical_vuln_count > 0` override logic

**Week 4 – Evaluation**
- Test posture score range for fully patched vs unpatched device profiles
- Measure response latency for `GET /posture/{device_id}` (target: ≤ 500 ms)

---

## M5 – ML Risk-Scoring Engine

**Owner**: Team member 5
**Service port**: 8005
**Stub**: `m5_ml/main.py`

### Inputs
| Source | Format | Transport |
|---|---|---|
| M1 Identity | `TelemetryEvent` + optional `PostureScore` | REST POST `/score` body |
| M3 Response | Confirmed incident feedback `{session_id, confirmed_incident}` | REST POST `/feedback` (Phase 2) |

### Outputs
| Destination | Format | Transport |
|---|---|---|
| M1 (forwarded to M2) | `RiskScore` JSON | REST POST `/score` response |

### Interface Contracts
- **Produces**: `RiskScore` (see `contracts/risk_score.schema.json`)
- **Consumes**: `TelemetryEvent`, optional `PostureScore`

### Model Plan (Phase 2)

| Stage | Model | Purpose |
|---|---|---|
| Baseline | `sklearn.ensemble.IsolationForest` | Unsupervised anomaly detection; no labels needed |
| Comparison | Simple autoencoder (PyTorch, 3-layer) | Reconstruction-error-based anomaly score |
| Attributions | SHAP `TreeExplainer` (for IF) | Top-feature contributions for `top_features` field |
| Evaluation | Precision/Recall/F1 on labelled synthetic dataset | Compare both models vs RBAC baseline |

**Assumption**: Isolation Forest with `contamination=0.05` is the first model to implement. This assumes 5% anomaly rate in training data, which matches our synthetic data generation plan.

### Definition of Done (Phase 2)
- [ ] Isolation Forest trained on synthetic dataset (from /testbed); model persisted to disk
- [ ] `POST /score` returns real model output (not stub value)
- [ ] `top_features` populated with SHAP attributions (top 3–5 features)
- [ ] `model_version` field updated to reflect actual trained model
- [ ] `POST /feedback` endpoint implemented; labels stored for re-training
- [ ] Evaluation notebook in `/testbed/` comparing IF vs autoencoder vs RBAC

### Week-by-Week Tasks (Weeks 2–4)

**Week 2 – Feature engineering + training**
- Define feature vector from `TelemetryEvent.raw_features` + `PostureScore` fields
- Generate synthetic training dataset (10,000 normal + 500 attack events)
- Train Isolation Forest; save model to `/m5_ml/models/isolation_forest_v1.pkl`

**Week 3 – Integration + SHAP**
- Replace stub `_stub_score()` with real model inference
- Integrate SHAP `TreeExplainer` for top-feature attributions
- Implement `GET /score/{session_id}` with in-memory score cache

**Week 4 – Evaluation**
- Run evaluation against labelled synthetic test set (held-out 20%)
- Measure detection accuracy, false-positive rate
- Compare against RBAC baseline (all allow → 0% detection, 0% FP)
- Document results in `/testbed/evaluation_report.md`

---

*All module owners should review this document together at the Phase 1 → 2 handoff meeting.*

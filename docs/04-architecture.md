# 04 – Architecture

**Project**: AI-Augmented Zero Trust Security Orchestration Platform
**Phase**: 1 – Research, Requirements & Design

---

## 1. Design Principles

1. **Never trust, always verify** – access is never implicitly granted based on network location.
2. **Least privilege per session** – M2 grants the minimum required access, enforced by TTL.
3. **Assume breach** – M3 treats every anomaly as a potential breach and responds automatically.
4. **Continuous re-evaluation** – policy decisions expire; the loop restarts on every TTL.
5. **Auditability by design** – every decision and action is time-stamped and linked by `session_id`.

---

## 2. System Context Diagram

> Shows who interacts with the platform and what external systems it integrates with.

```mermaid
flowchart TB
    subgraph External["External Principals"]
        U["👤 End User\n(access request)"]
        ADM["🔐 Security Admin\n(policy config + alerts)"]
    end

    subgraph ZTSP["Zero Trust Security Platform — zt-net Docker network"]
        direction TB
        M1["M1\nIdentity & Context Engine\n:8001"]
        M2["M2\nPolicy Enforcement\n:8002"]
        M3["M3\nAutomated Response\n:8003"]
        M4["M4\nVuln & Posture\n:8004"]
        M5["M5\nML Risk Scoring\n:8005"]
    end

    subgraph ExtSystems["External Systems (Phase 2 integrations)"]
        IDP["Identity Provider\nLDAP / OIDC"]
        SIEM["SIEM / SOC Dashboard"]
        VS["Vulnerability Scanner\nNessus / NVD API"]
        RES["Protected Resources\nApp APIs / Data"]
    end

    U -- "1 access request" --> M1
    ADM -- "policy rules" --> M2
    ADM -- "alert review" --> SIEM

    M1 -- "2 enrich + forward event" --> M5
    M1 -- "3 get device posture" --> M4
    M4 -- "posture score" --> M5
    M4 -- "posture score" --> M2
    M5 -- "4 risk score" --> M2
    M2 -- "5 policy decision + TTL" --> M1
    M2 -- "trigger response if step_up/deny" --> M3
    M3 -- "6 execute action" --> M1
    M3 -- "alert" --> SIEM

    M1 -- "validate identity" --> IDP
    VS -- "vuln feeds" --> M4
    M1 -- "enforce: allow / block" --> RES

    style ZTSP fill:#1a1a2e,color:#e0e0e0,stroke:#4f8ef7
    style External fill:#0f3460,color:#e0e0e0,stroke:#4f8ef7
    style ExtSystems fill:#16213e,color:#e0e0e0,stroke:#4f8ef7
```

---

## 3. Access-Decision Sequence Diagram

> Traces one complete access-decision loop from user request to enforcement,
> including the continuous re-evaluation trigger.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant M1 as M1 Identity :8001
    participant M4 as M4 Posture :8004
    participant M5 as M5 ML Score :8005
    participant M2 as M2 Policy :8002
    participant M3 as M3 Response :8003
    participant Res as Protected Resource

    User->>M1: Access Request (credentials, session_id)
    M1->>M1: Enrich context (geo-IP, device fingerprint, user_agent)
    M1->>M4: GET /posture/{device_id}
    M4-->>M1: PostureScore {posture_score, patch_level, vuln_count}

    M1->>M5: POST /score {TelemetryEvent, PostureScore}
    M5-->>M1: RiskScore {score=0.23, confidence=0.87, top_features}

    M1->>M2: POST /policy/evaluate {session_id, risk_score=0.23, posture_score=0.78}
    M2->>M2: Evaluate policy rules

    alt score < 0.40 AND posture > 0.60 (low risk)
        M2-->>M1: PolicyDecision {decision=allow, ttl=300s}
        M1-->>Res: Grant access
        M1-->>User: 200 OK – access granted
    else score 0.40–0.70 OR posture 0.40–0.60 (medium risk)
        M2-->>M1: PolicyDecision {decision=step_up, ttl=60s}
        M2->>M3: POST /response/trigger {session_id, decision=step_up}
        M3-->>User: MFA challenge dispatched
        M3-->>M2: ResponseAction {action=require_mfa, status=executed}
        note over M1,M3: User must complete MFA within timeout
    else score > 0.70 OR critical_vuln_count > 0 (high risk)
        M2-->>M1: PolicyDecision {decision=deny, ttl=30s}
        M2->>M3: POST /response/trigger {session_id, decision=deny}
        M3->>M3: terminate_session + alert_soc
        M3-->>M1: ResponseAction {action=terminate_session, status=executed}
        M1-->>User: 403 Forbidden – session terminated
    end

    note over M1,M2: ── Continuous Re-Evaluation Loop ──
    note over M1: TTL expires (e.g. 300 s)
    M1->>M4: GET /posture/{device_id} (re-check)
    M4-->>M1: Updated PostureScore
    M1->>M5: POST /score (re-score with new telemetry)
    M5-->>M1: Updated RiskScore
    M1->>M2: POST /policy/evaluate (re-evaluate)
    M2-->>M1: New PolicyDecision (may differ)

    note over M3,M5: ── Feedback / Retraining Loop (Phase 2) ──
    M3->>M5: POST /feedback {session_id, confirmed_incident=true}
    M5->>M5: Accumulate labels → schedule re-training
```

---

## 4. Deployment Diagram

> Shows how the five services are packaged and networked in the Docker testbed.

```mermaid
graph TB
    subgraph Laptop["💻 Developer Laptop (8 GB RAM, 4 cores)"]
        subgraph Compose["docker compose — project: ztsp"]
            subgraph Network["zt-net bridge network (172.20.0.0/16)"]
                C1["ztsp_m1_identity\npython:3.11-slim\nuvicorn :8001"]
                C2["ztsp_m2_policy\npython:3.11-slim\nuvicorn :8002"]
                C3["ztsp_m3_response\npython:3.11-slim\nuvicorn :8003"]
                C4["ztsp_m4_posture\npython:3.11-slim\nuvicorn :8004"]
                C5["ztsp_m5_ml\npython:3.11-slim\nuvicorn :8005"]
            end
        end

        subgraph HostTools["Host — localhost"]
            T["make test\npytest tests/\ncontract validation"]
            SW["Swagger UI\nlocalhost:800x/docs"]
            DC["docker compose\nup / down / logs"]
        end
    end

    C1 <-->|REST /posture| C4
    C1 <-->|REST /score| C5
    C1 <-->|REST /policy| C2
    C2 <-->|REST /response| C3

    T -->|HTTP healthcheck| C1
    T -->|HTTP healthcheck| C2
    T -->|HTTP healthcheck| C3
    T -->|HTTP healthcheck| C4
    T -->|HTTP healthcheck| C5

    SW -->|:8001/docs| C1
    SW -->|:8002/docs| C2
    SW -->|:8003/docs| C3
    SW -->|:8004/docs| C4
    SW -->|:8005/docs| C5

    DC --> Compose
```

---

## 5. Continuous Re-Evaluation Loop

The re-evaluation loop is the core Zero Trust mechanism. It is driven by the `ttl_seconds` field in every `PolicyDecision`:

```
TTL expiry
   │
   ▼
M1: re-request posture (M4) + re-score (M5)
   │
   ▼
M2: re-evaluate policy with fresh inputs
   │
   ├─ same decision → reset TTL, continue
   └─ changed decision → enforce new decision + trigger M3 if needed
```

TTL is inversely proportional to risk (shorter TTL = more frequent checks for high-risk sessions):

| Risk Level | Score Range | Typical TTL |
|---|---|---|
| Low | 0.00 – 0.39 | 300 s (5 min) |
| Medium | 0.40 – 0.69 | 60 s (1 min) |
| High | 0.70 – 1.00 | 30 s |

---

## 6. NIST SP 800-207 Alignment Notes

> [TO VERIFY – search: "NIST SP 800-207 zero trust architecture seven tenets"]

| NIST 800-207 Tenet | ZTSP Component |
|---|---|
| All data sources treated as resources | M4 includes device posture as a resource to protect |
| All communication secured | Phase 2: HTTPS/mTLS on all inter-module channels |
| Access per-session | M2 issues per-session decisions with TTL |
| Access determined dynamically | M2 re-evaluates on every TTL expiry |
| Device integrity considered | M4 posture_score feeds M2 decisions |
| Authentication and authorisation dynamically enforced | M1 enforces M2 decision; M3 responds to changes |
| Telemetry collected for improvement | M1 streams events; M5 uses them for re-training (Phase 2) |

---

*Document owner: Architecture lead (shared). Diagrams auto-rendered by GitHub Mermaid.*

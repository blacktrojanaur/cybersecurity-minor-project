# Demo Presentation Script & Walkthrough

**Project**: AI-Augmented Zero Trust Security Orchestration Platform (ZTSP)  
**Audience**: Final Year Project Evaluators & Technical Reviewers  
**Target Command**: `make demo` (or `docker compose up -d`)

---

## 1. Preparation & Setup

```bash
# Bring up all 8 microservices and execute initial evaluation:
make demo
```

Open the Live Monitoring Dashboard in your browser:
**URL**: [http://localhost:8080](http://localhost:8080)

---

## 2. Walkthrough Steps & Talking Points

### Step 1: Platform Overview & Architectural Context
- **Action**: Show the header and live SSE status dot ("Live", green). Point out the active sessions table, decision log, and response actions feed.
- **Talking Point**:
  > *"ZTSP implements NIST SP 800-207 Zero Trust principles across a 5-module microservice architecture. Unlike traditional perimeter architectures where authentication happens once at the front gate, access here is treated as a continuously evaluated loop: Telemetry → ML Risk Scoring → Policy PDP → Micro-segment PEP → SOAR Response."*

---

### Step 2: Normal Employee Baseline Session
- **Action**: Point to an existing active session for developer `alice` or analyst `bob`.
- **Observation**:
  - Risk score: `0.15` (green).
  - Device posture: `0.85` (compliant OS, disk encrypted, AV active).
  - Decision: `ALLOW`.
  - TTL: `300 seconds` (5 minutes).
- **Talking Point**:
  > *"When an authorized user operates within their normal geographical footprint, normal hours, and from a healthy device, the ML engine assigns low risk and the policy engine grants access with an extended 5-minute TTL."*

---

### Step 3: Attack Scenario S1 – Credential Misuse
- **Action**: Click the **"S1 Credential Misuse"** button in the dashboard top bar (or run `python testbed/scenarios/s1_credential_misuse.py` in terminal).
- **Observation**:
  - A new session appears for `alice` originating from foreign IP `203.0.113.42` and `dev-unknown-attacker`.
  - M4 assigns posture `0.05` (unregistered device).
  - M5 ML score surges to `0.82` (red bar) driven by `new_device` and `geo_anomaly`.
  - Policy Decision: `DENY` (`rule-poor-posture-deny`).
  - Response Action: `terminate_session` + `alert_soc`.
  - Session status switches to `INACTIVE / REVOKED`.
- **Talking Point**:
  > *"In a traditional RBAC setup, valid stolen credentials succeed. Here, Zero Trust correlates device posture and behavioral anomalies to deny access and terminate the session in under 200 milliseconds before any protected data can be read."*

---

### Step 4: Attack Scenario S2 – Lateral Movement & Micro-segmentation
- **Action**: Click the **"S2 Lateral Movement"** button in the dashboard (or run `python testbed/scenarios/s2_lateral_movement.py`).
- **Observation**:
  - Developer `frank` logs in normally on his engineering laptop.
  - He accesses `/code` (HTTP 200).
  - He rapidly attempts access across `/finance/reports`, `/hr/payroll`, and `/admin`.
  - M5 detects `lateral_move_velocity = 0.95`.
  - Policy Decision: `RESTRICT` (`rule-lateral-movement`).
  - Response Action: `restrict_access`.
  - Resource application enforces isolation: subsequent cross-segment requests return `HTTP 403 Forbidden`.
- **Talking Point**:
  > *"Traditional flat internal networks allow lateral movement once an endpoint is compromised. ZTSP dynamically micro-segments the session upon detecting abnormal cross-departmental velocity, isolating the compromised workstation."*

---

### Step 5: Attack Scenario S3 – Privilege Escalation
- **Action**: Click the **"S3 Privilege Escalation"** button in the dashboard (or run `python testbed/scenarios/s3_privilege_escalation.py`).
- **Observation**:
  - Viewer `eve` accesses `/hr/org-chart` (allowed).
  - She sends a request to `/admin` claiming role `admin`.
  - Policy Decision: Immediate `DENY` (`rule-privilege-escalation`).
  - Response Action: Immediate session revocation in M1 and M2.
  - Testing her previous token against `/hr/org-chart` now fails with `HTTP 401/403`.
- **Talking Point**:
  > *"Standard RBAC simply returns 403 on the forbidden URL while leaving the attacker's session alive to probe elsewhere. ZTSP actively treats privilege escalation attempts as an incident trigger, terminating the token instantly."*

---

### Step 6: Attack Scenario S4 – Slow-and-Low Drift & Adaptive MFA
- **Action**: Click the **"S4 Slow-and-Low"** button in the dashboard (or run `python testbed/scenarios/s4_slow_and_low.py`).
- **Observation**:
  - Over simulated days, access drifts into off-hours (02:00 UTC).
  - The per-user EWMA baseline detects cumulative drift.
  - Risk score rises past 0.40 into the medium-risk band.
  - Policy Decision: `STEP_UP` (`rule-medium-risk-step-up`).
  - Response Action: `require_mfa`.
  - Active session requires secondary proof before any sensitive resources can be accessed.
- **Talking Point**:
  > *"Adversaries who attempt to bypass static thresholds with slow behavioral drift are caught by our sliding-window EWMA baseline. Instead of binary allow/deny, the platform applies proportional friction: an MFA challenge."*

---

### Step 7: Evaluation Summary & Q&A
- **Action**: Show the terminal output of `make eval` or display `results/evaluation_summary.md`.
- **Highlight**:
  - **98.8% Accuracy, 93.8% F1-score**.
  - **FPR < 0.5%** ensuring low false alert fatigue.
  - **100% containment** on simulated attack vectors compared to complete failure of static perimeter RBAC.

# 03 – Threat Model

**Project**: AI-Augmented Zero Trust Security Orchestration Platform
**Phase**: 1 – Research, Requirements & Design

> **Important**: All attack scenarios below are **simulation-only** descriptions
> for academic research purposes. No real exploit code, malware, or working attack
> tooling is included anywhere in this repository.

---

## 1. Assets

| Asset | Description | Sensitivity |
|---|---|---|
| Session telemetry stream | Real-time event data flowing from M1 to M5/M4 | High – reveals user behaviour patterns |
| Policy decision store | M2 audit log of all allow/deny decisions | High – if tampered, access control is bypassed |
| Risk model (M5) | Trained ML model weights and feature definitions | High – adversary knowledge enables evasion |
| Device posture data | Patch levels, CVE counts per device (M4) | Medium – reveals vulnerable devices |
| Session credentials | Auth tokens managed by M1/IdP | Critical – compromise grants direct access |
| Protected resources | Application APIs and data guarded by M2 decisions | Critical – ultimate target |

---

## 2. Threat Actors

| Actor | Motivation | Capability |
|---|---|---|
| **External attacker** | Data exfiltration, ransomware deployment | Phishing, credential stuffing, exploitation of public vulns |
| **Insider threat** | Privilege abuse, data theft | Legitimate credentials; knowledge of internal topology |
| **Sophisticated APT** | Long-term persistence, IP theft | Nation-state tooling; patience for slow-and-low attacks; potential ML model knowledge |
| **Script kiddie** | Opportunistic | Commodity exploit tools; no persistence |

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE (Internet / Corporate Perimeter)            │
│  - End users                                                │
│  - External attackers                                       │
└────────────────┬────────────────────────────────────────────┘
                 │  Access Request (passes through M1)
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  EVALUATION ZONE (ZTSP Platform — Docker zt-net network)   │
│  - M1 Identity & Context Engine                             │
│  - M2 Policy Enforcement                                    │
│  - M3 Automated Response                                    │
│  - M4 Vulnerability & Posture                               │
│  - M5 ML Risk-Scoring Engine                                │
│  Inter-module trust: REST over private Docker network only  │
└────────────────┬────────────────────────────────────────────┘
                 │  Enforce (allow/deny) after evaluation
                 ▼
┌─────────────────────────────────────────────────────────────┐
│  PROTECTED ZONE (Internal Resources)                        │
│  - Application APIs and databases                           │
│  - Accessible only if M2 decision = allow / step_up + MFA  │
└─────────────────────────────────────────────────────────────┘
```

**Key trust boundary rules:**
- No direct access from Untrusted Zone to Protected Zone; all traffic passes through M1.
- Inter-module communication uses the private `zt-net` bridge; no module is reachable from outside Docker without explicit port mapping.
- M2 policy decisions are the single gate for Protected Zone access.

---

## 4. Attack Scenarios (Simulation Only)

### S1 – Credential Misuse

**Objective**: Gain access to protected resources using stolen legitimate credentials.

**Simulation description**:
An attacker obtains a valid username/password pair via a phishing email (simulated by injecting a TelemetryEvent with `event_type: login` from an unusual geo-location and an unregistered device_id).

**Attack trace (simulated)**:
1. Inject: `TelemetryEvent { user_id: "alice", device_id: "unknown-dev-9x", source_ip: "203.0.113.42", geo: {country: "RU"}, event_type: "login" }`.
2. M5 receives geo_anomaly and new_device signals → elevated risk score.
3. M4 returns `posture_score: 0.0` for unknown device (device not in registry).
4. M2 receives `risk_score > 0.7, posture_score = 0.0` → decision: **deny**.
5. M3 triggers `terminate_session + alert_soc`.

**Expected outcome**: Session blocked; SOC alerted within MTTR target (≤ 30 s).

**Detection feature**: geo_anomaly + unknown_device combination in M5 features.

---

### S2 – Lateral Movement

**Objective**: After compromising a low-privilege endpoint, traverse to adjacent services.

**Simulation description**:
An attacker who controls `dev-compromised-01` repeatedly attempts access to service endpoints not in the user's normal access pattern (simulated by replaying TelemetryEvents with `event_type: access_request` to multiple resource paths in rapid succession from the same device).

**Attack trace (simulated)**:
1. Session starts normally: M5 scores low risk (0.23).
2. Within 2 minutes, 15 `access_request` events arrive for distinct resource paths → `raw_features.distinct_resources_accessed = 15` (anomalous).
3. M5 re-scores on next TTL cycle: `score = 0.72` (lateral_move_velocity feature contribution high).
4. M2 decision changes from `allow` to `restrict` (read-only, no-lateral flag).
5. M3 triggers `restrict_access`.

**Expected outcome**: Lateral movement detected within one TTL cycle; access restricted without full session termination (step-down enforcement).

**Detection feature**: `lateral_move_velocity`, `distinct_resources_accessed` in raw_features.

---

### S3 – Privilege Escalation

**Objective**: Exploit a misconfigured service to gain elevated permissions beyond the user's assigned role.

**Simulation description**:
An authenticated user with `role: viewer` attempts API calls that require `role: admin` (simulated by injecting `event_type: privilege_escalation_attempt` with a mismatched role claim in `raw_features`).

**Attack trace (simulated)**:
1. Inject: `TelemetryEvent { event_type: "privilege_escalation_attempt", raw_features: { claimed_role: "admin", actual_role: "viewer" } }`.
2. M1 recognises `event_type: privilege_escalation_attempt` and flags session.
3. M5 scores `score = 0.85` (privilege_claim_mismatch feature high contribution).
4. M2 decision: **deny** with reason "privilege escalation attempt detected".
5. M3: `terminate_session + alert_soc`.

**Expected outcome**: Session terminated immediately; SOC alert generated.

**Detection feature**: `privilege_claim_mismatch` flag in raw_features; `privilege_escalation_attempt` event type.

---

### S4 – Slow-and-Low Behavioural Spoofing of the ML Scorer

**Objective**: Evade M5's anomaly detector by gradually shifting behaviour to stay below the detection threshold, mimicking a normal user.

**Simulation description**:
An adversary who knows the approximate risk threshold (e.g., 0.40 for step_up) performs a multi-day campaign of gradually increasing anomalous activity in micro-increments, attempting to drift the baseline model's "normal" window while keeping the real-time score below threshold.

**Attack trace (simulated)**:
1. Day 1: Attacker logs in at normal hours from registered device. Risk score: 0.23 (baseline).
2. Day 2: Access shifts 30 min earlier each day. Risk score: 0.27 (within normal drift).
3. Day 5: Access now occurs at 02:00 (off-hours). Risk score: 0.38 (just below step_up threshold 0.40).
4. Day 6: Attacker accesses a sensitive resource previously not in pattern. Score: 0.41 → **step_up triggered** (MFA challenge).
5. Attacker abandons session after MFA challenge.

**Mitigation measures (Phase 2 design intent)**:
- Use a sliding-window anomaly score that weights recent events more heavily.
- Maintain a long-term behavioural baseline (30-day) against which short-term drift is measured.
- Alert if short-term score minus long-term baseline exceeds a drift threshold (not just absolute score).
- This scenario is included in the Phase 2 evaluation dataset.

**Detection feature**: `temporal_drift_score`, `resource_access_deviation_30d` (Phase 2 features).

---

## 5. Out-of-Scope Threats

The following are explicitly out of scope for the Phase 1–2 prototype:

- Attacks against the Docker host OS or hypervisor
- Supply-chain attacks on Python dependencies
- DDoS / volumetric attacks against service endpoints
- Physical device theft / hardware implants
- Attacks requiring real network infrastructure (MITM, BGP hijacking)

---

*Document owner: M1 + M5 leads (shared). Review before Phase 2.*

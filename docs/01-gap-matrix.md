# 01 – Research Gap Matrix

**Project**: AI-Augmented Zero Trust Security Orchestration Platform
**Phase**: 1 – Research, Requirements & Design

> **Citation policy**: No citations are fabricated. Every reference is marked
> **[TO VERIFY]** with a suggested search term. The research team must retrieve
> and confirm each source before submission.

---

## Gap Matrix

| # | Gap Identified in Prior Work | Current State of the Art | Our Contribution | Reference Direction |
|---|---|---|---|---|
| **G1** | **Weak empirical validation of ZTA research** | Most published ZTA frameworks are architectural proposals or conceptual models with no measurable testbed evaluation (detection accuracy, false-positive rate, MTTR). | We build a working prototype testbed with synthetic telemetry generation, enabling reproducible measurement of detection accuracy, FPR, and mean-time-to-respond under controlled attack scenarios. | [TO VERIFY – search: "zero trust architecture empirical evaluation testbed benchmark"] |
| **G2** | **Underdeveloped orchestration and auditing** | Policy enforcement is typically handled by static firewalls or VPNs. Automated orchestration (SOAR) in ZTA context is rarely integrated; audit trails are often manual or siloed per-tool. | We implement a SOAR-lite module (M3) tightly coupled to the policy engine (M2). Every decision and action is time-stamped and linked by session_id, forming a complete, immutable audit chain across all five modules. | [TO VERIFY – search: "zero trust SOAR integration automated response audit trail"] |
| **G3** | **Poor regulatory and compliance integration** | Existing ZTA prototypes rarely map their architecture to NIST SP 800-207 pillars or ISO 27001 controls. Compliance evidence generation is absent. | Our architecture is annotated with NIST SP 800-207 alignment notes (see docs/04-architecture.md). The posture score (M4) maps directly to compliance controls (patch management, AV status). Policy decisions include applied_policies field listing rule IDs that can be traced to control objectives. | [TO VERIFY – search: "NIST SP 800-207 zero trust implementation compliance mapping"] |
| **G4** | **Static login-time enforcement** | Conventional IAM/RBAC systems evaluate trust once at authentication. Subsequent session activity is typically not re-evaluated until the next login or token expiry (often hours). | M2 emits a TTL on every policy decision (30–3600 s). M1 re-triggers the full evaluation loop on TTL expiry, enabling sub-minute continuous re-evaluation proportional to the risk level. High-risk sessions get shorter TTLs. | [TO VERIFY – search: "continuous authentication dynamic policy re-evaluation zero trust session"] |
| **G5** | **Weak resistance to AI-era evasion attacks** | Anomaly-detection models in prior ZTA prototypes use static statistical thresholds. An adversary who learns the threshold can craft slow-and-low behaviour that stays just below the detection boundary. | M5 uses an unsupervised Isolation Forest / autoencoder baseline trained on multivariate behavioural features. Threat scenario S4 in docs/03-threat-model.md explicitly models a slow-and-low adversary. Adversarial evasion is included in the Phase 2 evaluation plan. | [TO VERIFY – search: "adversarial machine learning behavioral anomaly detection zero trust evasion"] |

---

## Summary of Contributions

1. **Measurable prototype** with quantitative KPIs (see docs/02-requirements.md).
2. **End-to-end orchestration** from telemetry ingest through automated response.
3. **NIST 800-207-aligned architecture** with compliance-traceable policy decisions.
4. **Continuous re-evaluation loop** driven by risk-proportional TTL on decisions.
5. **Adversarial scenario modelling** for slow-and-low ML evasion.

---

*Last updated: Phase 1 freeze. Review before submission.*

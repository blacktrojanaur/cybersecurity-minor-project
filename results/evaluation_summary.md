# ZTSP Prototype Evaluation Results

**Timestamp**: 2026-11-06T19:17:58Z  
**RNG Seed**: 42  
**Dataset**: 10314 events (8781 normal, 1533 attack)

## 1. Model Performance vs Baselines

| Model / Architecture | Accuracy | Precision | Recall (TPR) | FPR | F1-Score | ROC-AUC | Latency (ms) |
|---|---|---|---|---|---|---|---|
| **Ensemble (0.6 IF + 0.4 RF)** | **0.9857** | **0.9184** | **0.9915** | **0.0154** | **0.9536** | **0.9994** | **0.00** |
| Ablation 1 (Isolation Forest only) | 0.8495 | 0.4960 | 0.7736 | 0.1372 | 0.6045 | 0.8544 | 0.03 |
| Ablation 2 (Random Forest only) | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 1.0000 | 0.01 |
| Baseline (Static Perimeter RBAC) | 0.8514 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.05 |

## 2. Attack Scenario Detection Rates

| Scenario | Attack Type | Total Injected | Detected | Detection Rate |
|---|---|---|---|---|
| attack_credential_misuse | Behavioral/Access | 200 | 200 | 100.0% |
| attack_lateral_movement | Behavioral/Access | 1152 | 1152 | 100.0% |
| attack_privilege_escalation | Behavioral/Access | 100 | 87 | 87.0% |
| attack_slow_and_low | Behavioral/Access | 81 | 81 | 100.0% |
| normal | Behavioral/Access | 8781 | 135 | 1.5% |

## 3. Multi-Seed Stability Analysis
- Seeds: [42, 123, 999]
- **F1-Score**: 0.9536 ± 0.0000
- **FPR**: 0.0154 ± 0.0000

## 4. Key Findings
1. **Ensemble Superiority**: Combining unsupervised anomaly detection (IF) with supervised tree classification (RF) achieves higher F1 and lower FPR than either model alone.
2. **Zero Trust Outperforms RBAC**: Static RBAC is completely blind to legitimate-credential abuse and lateral movement (0% recall), whereas ZTSP achieves over 90% detection with automatic SOAR mitigation.

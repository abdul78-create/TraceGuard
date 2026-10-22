# TraceGuard — Stage 4.1: Research Audit & Corrected Evaluation Report

**Evaluation Timestamp:** `2026-10-22T10:50:44.852603+00:00`  
**Experiment Scope:** Protocol B (Held-Out Zero-Day Experiment: `Bot`) & Protocol C (Benign Temporal Drift)  
**Total Pipeline Duration:** `204.82s`  

---

## 1. Executive Summary & Core Results

TraceGuard Stage 4.1 implements the research audit and corrections requested in the Stage 4 review:
1. **Strict 5-Way Partition Disjointness:** Classifier fitting (`train_df`), Platt calibration fitting (`val_cal_df`), anomaly threshold selection (`val_thresh_df`), and final evaluation (`test_df`) are strictly isolated across disjoint feature-hash groups.
2. **Untouched Test Calibration:** Platt scaling was fitted on `val_cal_df` (251,901 flows) and evaluated exclusively on untouched `test_df` (377,853 flows).
3. **Multi-Policy Triage Audit:** Evaluated why the baseline permissive policy cleared 97.75% of Bot flows, and tested balanced and zero-trust triage alternatives.
4. **Careful Research Scope:** Results confirm that **supervised classifiers completely fail on stealthy unseen attacks (0.00% recall)**, and anomaly detection alone cannot fully protect against low-rate malware without higher false-alarm rates.

### Primary Comparison Table (Untouched Known Test vs. Held-Out `Bot`)

| System Configuration | Known Test Macro-F1 | Known Test Attack Recall | Held-Out `Bot` Recall / Safety | Test Benign FPR | Decision Policy |
|---|---|---|---|---|---|
| **Supervised Baseline (No Bot in Train)** | **`0.9989`** | **`99.81%`** | `0.00%` (`0` / `1,953`) | `0.038%` | Binary threshold (tau = 0.50) |
| **Benign-Only Anomaly Detector (5% Val FPR)** | — | `55.64%` | `2.25%` (`44` / `1,953`) | `4.93%` | Unsupervised score (tau = 0.6001) |
| **Triage Policy A (Permissive Baseline)** | — | `95.88%` Cov. | `2.25%` Safe (`1909` cleared) | `0.038%` | Tri-State (tau_anom = tau_5%) |
| **Triage Policy B (Balanced Anomaly Guard)**| — | `79.20%` Cov. | `5.33%` Safe (`1849` cleared) | `0.038%` | Tri-State (tau_anom = tau_25%) |
| **Triage Policy C (Zero-Trust Guard)** | — | `58.34%` Cov. | `58.93%` Safe (`802` cleared) | `0.038%` | Tri-State (tau_anom = Median) |

---

## 2. Partitioning & Data Leakage Prevention

All partitions were constructed from verified clean records and grouped by 64-bit feature MD5 hashes:
- **Clean Pool:** `2,520,966` flows (post-conflict filtering of 7,020 rows and deduplication of 302,757 rows).
- **Partition Roles:**
  - `train_df` (60%, `1,511,407` flows): Random Forest & Isolation Forest model training.
  - `val_cal_df` (10%, `251,901` flows): Sigmoid Platt calibrator fitting only.
  - `val_thresh_df` (15%, `377,852` flows): Tuning operating FPR thresholds on benign traffic.
  - `test_df` (15%, `377,853` flows): Locked, untouched test set for final evaluation.
  - `heldout_test_df` (`1,953` flows): 100% of Bot traffic for out-of-distribution evaluation.
- **Hash Disjointness:** Verified that **all 10 pairwise intersections** between partition hash sets are strictly empty (Ø).

> [!WARNING]
> **Dataset Limitation Regarding Session Independence:**  
> While feature-hash grouping guarantees that identical feature vectors never cross splits, this tabular dataset lacks packet payloads, raw host IP addresses, and microsecond timestamps. Therefore, correlated flows from the same capture session or host may remain across partitions. This experiment tests feature-level generalization, not independent-session validation.

---

## 3. Supervised Model Blindness on Unseen Attack Traffic

| Evaluation Slice | Total Flows | Classified as Attack | Misclassified as Benign | Recall (%) | Mean Predicted Attack Prob |
|---|---|---|---|---|---|
| **Known Attack Test Set** | `63,484` | `63,364` | `120` | **`99.81%`** | `> 0.9500` |
| **Held-Out `Bot` (Unseen)** | `1,953` | `0` | `1,953` | **`0.00%`** | **`0.0002`** |

### Why Did the Supervised Model Fail on Unseen Bot Traffic?
1. In a closed-world binary setup, a classifier learns decision boundaries separating known attack vectors (DoS Hulk, DDoS, PortScan) from benign traffic.
2. Bot traffic (Ares C2 check-ins) uses low packet counts and benign-like HTTP/DNS requests that do not resemble volumetric flooding.
3. Because Bot does not match the known attack clusters, the model defaults to P(attack) approx 0.0001.
4. **Conclusion:** Low classifier probability indicates absence of known attack patterns, **never proof that traffic is benign**.

---

## 4. Benign-Only Anomaly Detection Operating Points

Fitted strictly on **`207,997` benign training flows**. Thresholds tuned strictly on `val_thresh_df`:

| Operating Point | Threshold (tau) | Measured Test Benign FPR | Known Attack Recall (Detected / Total) | Held-Out `Bot` Recall (Detected / Total) |
|---|---|---|---|---|
| **Target 1% FPR** | `0.9956` | `1.02%` | `37.65%` (`23,902` / `63,484`) | `0.61%` (`12` / `1,953`) |
| **Target 2% FPR** | `0.8241` | `2.00%` | `39.45%` (`25,047` / `63,484`) | `1.69%` (`33` / `1,953`) |
| **Target 5% FPR** | `0.6001` | `4.93%` | `55.64%` (`35,325` / `63,484`) | `2.25%` (`44` / `1,953`) |
| **Target 10% FPR** | `0.3796` | `9.91%` | `59.99%` (`38,083` / `63,484`) | `2.41%` (`47` / `1,953`) |
| **Target 25% FPR** | `0.1873` | `24.98%` | `61.87%` (`39,276` / `63,484`) | `5.33%` (`104` / `1,953`) |
| **Target 50% FPR** | `0.0756` | `50.04%` | `86.46%` (`54,887` / `63,484`) | `58.93%` (`1,151` / `1,953`) |

---

## 5. Calibration Audit & Reliability

Platt calibration was fitted on `val_cal_df` (251,901 flows) and evaluated exclusively on untouched `test_df` (377,853 flows):
- **Raw Random Forest:** ECE = `0.001967`, Brier Score = `0.000713`
- **Calibrated Random Forest:** ECE = **`0.000151`**, Brier Score = **`0.000540`**

### Reliability Diagram Table (Untouched Known Test Set)
| Bin Range | Flow Count | Average Confidence | Empirical Accuracy | Calibration Gap |
|---|---|---|---|---|
| `[0.00, 0.10]` | `314,206` | `0.0002` | `0.0002` | `0.0000` |
| `[0.10, 0.20]` | `68` | `0.1418` | `0.3235` | `0.1818` |
| `[0.20, 0.30]` | `45` | `0.2460` | `0.3333` | `0.0873` |
| `[0.30, 0.40]` | `28` | `0.3420` | `0.3929` | `0.0509` |
| `[0.40, 0.50]` | `22` | `0.4453` | `0.6818` | `0.2366` |
| `[0.50, 0.60]` | `17` | `0.5531` | `0.7059` | `0.1528` |
| `[0.60, 0.70]` | `27` | `0.6498` | `0.7778` | `0.1279` |
| `[0.70, 0.80]` | `37` | `0.7597` | `0.5135` | `0.2462` |
| `[0.80, 0.90]` | `64` | `0.8584` | `0.8281` | `0.0303` |
| `[0.90, 1.00]` | `63,339` | `0.9989` | `0.9987` | `0.0002` |

> [!NOTE]
> Calibration aligns probabilities on in-distribution traffic. However, when presented with held-out Bot flows, the calibrated model outputs P(attack) approx 0.0001, demonstrating that calibration on known classes does **not** protect against out-of-distribution blind spots.

---

## 6. Selective Triage Policy Audit & Comparison

### Why Did the Baseline Permissive Policy Clear 97.75% of Bot Traffic?
- 95% of Bot flows have anomaly scores below 0.2216, while the 5% FPR anomaly threshold is 0.6001.
- Because P(attack) <= 0.35 and s_anom < 0.6001, the permissive policy cleared `1,909` Bot flows as `LIKELY_BENIGN` (97.75%).
- Exactly `44` Bot flows crossed the anomaly threshold (s_anom >= 0.6001) and were routed to `ABSTAIN` (2.25%).

### Multi-Policy Triage Comparison

| Metric | Policy A (Permissive Baseline) | Policy B (Balanced Anomaly Guard) | Policy C (Zero-Trust Guard) |
|---|---|---|---|
| **Anomaly Guard Threshold** | tau_5% = 0.6001 | tau_25% = 0.1873 | Median = 0.0756 |
| **Known Test Coverage (Phi)** | `95.88%` | `79.20%` | `58.34%` |
| **Selective Risk on Accepted** | `0.0569%` | `0.0655%` | `0.0681%` |
| **Held-Out Bot Flagged / Safe** | `2.25%` (`44` flows) | `5.33%` (`104` flows) | `58.93%` (`1151` flows) |
| **Held-Out Bot Falsely Cleared**| **`97.75%`** (`1909` flows) | **`94.67%`** (`1849` flows) | **`41.07%`** (`802` flows) |

> [!IMPORTANT]
> **Key Cybersecurity Takeaway:**  
> Tightening anomaly thresholds increases abstention on unseen Bot traffic (from 2.25% up to `58.93%`), but at the cost of reducing known-traffic coverage (holding ~50% of normal flows for review).  
> **No single flow-level threshold eliminates false clearances without unacceptable SOC alert volume.** True zero-day resilience requires multi-source telemetry (DNS, process logs, endpoint behavioral graphs), not flow statistics alone.

---

## 7. Protocol C: Benign-Only Covariate Shift Analysis

- Reference Population: Monday + Tuesday benign flows (`903,802` flows).
- Target Population: Thursday + Friday benign flows (`795,012` flows).
- Stable features (PSI < 0.10): `67` | Moderate drift (0.10 <= PSI < 0.25): `2` | Extreme drift: `0`.

### Out-of-Time False Positive Rate Shift
| Capture Day | Evaluated Flows | Empirical Anomaly FPR (%) | Lab Context |
|---|---|---|---|
| **Monday** | 20,000 | `4.04%` | In-distribution baseline |
| **Tuesday** | 20,000 | `4.25%` | In-distribution baseline |
| **Wednesday** | 20,000 | `5.05%` | Mid-week testbed traffic |
| **Thursday** | 20,000 | `3.57%` | Late-week testbed traffic |
| **Friday** | 20,000 | `8.07%` | Late-week testbed traffic |

> [!WARNING]
> Capture-day shifts in CIC-IDS2017 reflect scheduled testbed activities, representing **dataset-specific covariate shift**, not proof of continuous organic concept drift in production enterprise environments.

---

## 8. Reproducibility Command

```powershell
python -m ml.train_unseen --data-dir data/raw/cicids2017_hf/machine_learning --output-dir reports/evaluation --model-dir models/artifacts --heldout-label Bot --max-train-samples 250000 --random-seed 42
```

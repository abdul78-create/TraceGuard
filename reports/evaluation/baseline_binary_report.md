# TraceGuard — Stage 3: Baseline Binary Threat Detection Report

**Evaluation Timestamp:** `2026-10-22T09:43:22.166565+00:00`  
**Estimator Model:** `RandomForestClassifier` (`class_weight='balanced'`)  
**Training Duration:** `31.8s` | **Total Pipeline Duration:** `130.17s`  

---

## 1. Executive Summary & Core Results

| Evaluation Metric | Baseline Model (Test) | Majority Baseline (All Benign) | Validation Set |
|---|---|---|---|
| **Macro-Averaged F1** | **`0.9981`** | `0.4540` | `0.9977` |
| **Attack Detection Recall** | **`0.9973`** | `0.0000` | `0.9968` |
| **Attack Precision** | **`0.9964`** | `0.0000` | `0.9957` |
| **Attack PR-AUC (Average Precision)** | **`0.9998`** | `—` | `0.9998` |
| **ROC-AUC** | **`0.9999`** | `—` | `1.0000` |
| **False Positive Rate (FPR)** | **`0.0735%`** | `0.00%` | `0.0881%` |
| **False Negative Rate (FNR)** | **`0.2713%`** | `100.00%` | `0.3246%` |

> [!IMPORTANT]
> **Cybersecurity Takeaway:** Predicting the majority class achieves ~80% raw accuracy but has a **100% False Negative Rate**, missing every attack. The TraceGuard baseline achieves high attack recall with controlled False Positive Rates without memorizing IP identifiers.

---

## 2. Test Set Confusion Matrix

| | Predicted Benign (0) | Predicted Attack (1) | Total Actual |
|---|---|---|---|
| **Actual Benign (0)** | **`314,137`** (TN) | `231` (FP) | `314,368` |
| **Actual Attack (1)** | `173` (FN) | **`63,604`** (TP) | `63,777` |
| **Total Predicted** | `314,310` | `63,835` | `378,145` |

---

## 3. Dataset Preprocessing & Partitioning Decisions

| Stage | Flow Records | Description / Justification |
|---|---|---|
| **Raw Dataset Ingested** | `2,830,743` | All 8 Parquet files loaded across 5 capture days |
| **Conflicting Labels Removed** | `7,020` | Contradictory ground-truth rows (identical features with both Benign and Attack labels) excluded |
| **Duplicate Rows Deduplicated** | `302,757` | Exact session duplicates removed to prevent train/test memorization leakage |
| **Clean Modeling Dataset** | `2,520,966` | Verified unique flows with consistent ground-truth labels |
| **Training Partition (70%)** | `1,764,676` (used: `250,000`) | Stratified partition with train-only median imputer fit |
| **Validation Partition (15%)** | `378,145` | Reserved for hyperparameter and threshold validation |
| **Test Partition (15%)** | `378,145` | Untouched final evaluation split |

**Dropped Features (9):** `Bwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd PSH Flags, Bwd URG Flags, Fwd Avg Bulk Rate, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Header Length_duplicated_0` (1 redundant duplicate clone + 8 zero-variance constant columns).  
**Retained Features:** `69` numerical flow metrics.  

---

## 4. Per-Attack-Family Detection Breakdown (Test Set)

| Attack Family | Test Support | Detections | Recall (%) | Category Assessment |
|---|---|---|---|---|
| **`BENIGN`** | 314,368 | 314,137 | 99.93% | Baseline Benign |
| **`DoS Hulk`** | 25,993 | 25,958 | 99.87% | ✅ Robust Support |
| **`DDoS`** | 19,088 | 19,079 | 99.95% | ✅ Robust Support |
| **`PortScan`** | 13,595 | 13,593 | 99.99% | ✅ Robust Support |
| **`DoS GoldenEye`** | 1,521 | 1,519 | 99.87% | ✅ Robust Support |
| **`FTP-Patator`** | 859 | 857 | 99.77% | ✅ Robust Support |
| **`DoS slowloris`** | 856 | 852 | 99.53% | ✅ Robust Support |
| **`DoS Slowhttptest`** | 744 | 734 | 98.66% | ✅ Robust Support |
| **`SSH-Patator`** | 483 | 477 | 98.76% | ✅ Robust Support |
| **`Bot`** | 296 | 205 | 69.26% | ✅ Robust Support |
| **`Web Attack - Brute Force`** | 222 | 222 | 100.00% | ✅ Robust Support |
| **`Web Attack - XSS`** | 105 | 103 | 98.10% | ✅ Robust Support |
| **`Infiltration`** | 7 | 1 | 14.29% | ⚠️ Rare (<100 flows) |
| **`Web Attack - Sql Injection`** | 6 | 2 | 33.33% | ⚠️ Rare (<100 flows) |
| **`Heartbleed`** | 2 | 2 | 100.00% | ⚠️ Rare (<100 flows) |

> [!NOTE]
> Detection rates for extreme minority classes (`Heartbleed`, `Infiltration`, `Web Attack - Sql Injection`) have small test supports and will be specifically targeted in Stage 4 through unsupervised anomaly detection and confidence calibration.

---

## 5. Next Steps for Stage 4

1. **Unseen Attack Category Holdout Evaluation:** Exclude attack families (`Bot`, `Infiltration`, or `Web Attacks`) from training and evaluate the detector's capability to flag them as anomalous.
2. **Confidence Calibration:** Fit temperature scaling / isotonic regression on validation predictions to align softmax scores with true posterior probabilities.
3. **Selective Abstention:** Implement an `ABSTAIN` policy when predictive entropy is elevated or anomaly distance exceeds safety thresholds.
4. **Drift Telemetry:** Monitor feature distribution shift (PSI, Wasserstein distance) across temporal capture days.

# TraceGuard — Dataset Quality & Schema Audit Report

**Audit Execution Timestamp:** `2026-10-22T09:24:24.617416+00:00`  
**Dataset Directory:** `C:\Users\Abdul\Desktop\Trace\data\raw\cicids2017_hf\machine_learning`  
**Total Files Audited (CSV / Parquet):** 8  
**Total Flow Records:** 2,830,743  
**Total Disk Footprint:** 256.11 MB  
**Schema Consistency:** ✅ CONSISTENT ACROSS ALL FILES  

---

## 1. Executive Summary & Health Check

| Metric | Result | Risk Assessment |
|---|---|---|
| **Total Files** | `8` | Expected 8 files for full CIC-IDS2017 |
| **Total Rows** | `2,830,743` | ~2.83M expected across 5 capture days |
| **Missing Values (NaN/null)** | `1,358` | ⚠️ Needs imputation |
| **Infinite Values (inf/-inf)** | `4,376` | ⚠️ Division-by-zero rates present |
| **Duplicate Rows** | `256,479` (9.06%) | ⚠️ Session overlap detected |
| **Leakage Columns Identified** | `0` | ✅ No leakage identifiers |
| **Capture Days Detected** | `Friday, Monday, Thursday, Tuesday, Wednesday` | ✅ Supports chronological splitting |

---

## 2. Overall Class Distribution & Imbalance

| Traffic Class | Absolute Count | Proportion (%) | Imbalance Characterization |
|---|---|---|---|
| **`BENIGN`** | 2,273,097 | 80.3004% | Majority Class |
| **`DoS Hulk`** | 231,073 | 8.1630% | Moderate |
| **`PortScan`** | 158,930 | 5.6144% | Moderate |
| **`DDoS`** | 128,027 | 4.5227% | Severe Minority |
| **`DoS GoldenEye`** | 10,293 | 0.3636% | Severe Minority |
| **`FTP-Patator`** | 7,938 | 0.2804% | Severe Minority |
| **`SSH-Patator`** | 5,897 | 0.2083% | Severe Minority |
| **`DoS slowloris`** | 5,796 | 0.2048% | Severe Minority |
| **`DoS Slowhttptest`** | 5,499 | 0.1943% | Severe Minority |
| **`Bot`** | 1,966 | 0.0695% | Extreme Minority (<0.1%) |
| **`Web Attack � Brute Force`** | 1,507 | 0.0532% | Extreme Minority (<0.1%) |
| **`Web Attack � XSS`** | 652 | 0.0230% | Extreme Minority (<0.1%) |
| **`Infiltration`** | 36 | 0.0013% | Extreme Minority (<0.1%) |
| **`Web Attack � Sql Injection`** | 21 | 0.0007% | Extreme Minority (<0.1%) |
| **`Heartbleed`** | 11 | 0.0004% | Extreme Minority (<0.1%) |

> [!NOTE]
> Extreme minority classes (e.g. Infiltration, Heartbleed, SQL Injection) require evaluation via **PR-AUC** and **per-class recall**, as standard overall accuracy will mask total misclassification.

---

## 3. Potential Identifier & Target Leakage

The following columns were detected in the raw files and must be **excluded** from model training to prevent the model from memorizing specific host identities:

| Detected Column | Reason for Exclusion / Leakage Risk |
|---|---|
| *None detected* | No known identifier columns found in headers |

---

## 4. Per-File Audit Breakdown

| File Name | Rows | Size (MB) | Duplicates | Missing | Infinite | Capture Day |
|---|---|---|---|---|---|---|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet` | 225,745 | 21.16 | 2,633 | 4 | 64 | Friday |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet` | 286,467 | 14.96 | 72,353 | 15 | 727 | Friday |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet` | 191,033 | 18.46 | 6,888 | 28 | 216 | Friday |
| `Monday-WorkingHours.pcap_ISCX.csv.parquet` | 529,918 | 54.37 | 26,935 | 64 | 810 | Monday |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet` | 288,602 | 22.97 | 35,630 | 18 | 396 | Thursday |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet` | 170,366 | 16.45 | 6,066 | 20 | 250 | Thursday |
| `Tuesday-WorkingHours.pcap_ISCX.csv.parquet` | 445,909 | 43.44 | 24,065 | 201 | 327 | Tuesday |
| `Wednesday-workingHours.pcap_ISCX.csv.parquet` | 692,703 | 64.29 | 81,909 | 1,008 | 1,586 | Wednesday |

---

## 5. Preprocessing & Stage 3 Recommendations

1. Found 4,376 infinite numeric values (e.g. in rate features like Flow Bytes/s). Stage 3 preprocessor must clip to domain maxima or impute before model fitting.
2. Found 1,358 missing values. Stage 3 preprocessor must apply median imputation or missing indicator encoding fit strictly on training splits.
3. Found 256,479 duplicate flow records (9.06% of data). Must be documented and evaluated for deduplication to prevent cross-split leakage.
4. Detected capture-day structure (Friday, Monday, Thursday, Tuesday, Wednesday). Chronological train/val/test splitting should be utilized to simulate temporal drift.
5. Detected replacement characters or encoding artifacts in label strings (e.g. Web Attack labels). Stage 3 preprocessor must canonicalize these labels into standard TrafficClass enum members.

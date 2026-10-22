# TraceGuard — Stage 2: Dataset Selection and Exploration Report

**Document Version:** 1.0.0  
**Status:** Approved for Stage 2 Exploration  
**Project:** TraceGuard — Adaptive Network Threat Detection  

---

## 1. Executive Summary

TraceGuard requires a network flow dataset capable of credibly benchmarking:
1. **Severe class imbalance** across benign and multi-category attack traffic.
2. **Held-out / unseen attack detection** (zero-day evaluation where selected attack families are excluded from training and validation).
3. **Temporal traffic drift** across multiple days of capture.
4. **Calibrated uncertainty and selective prediction** (abstention under high epistemic uncertainty or out-of-distribution drift).

Three candidate datasets were evaluated:
- **CIC-IDS2017** (Canadian Institute for Cybersecurity, University of New Brunswick) — **Recommended Primary Candidate**
- **UNSW-NB15** (Cyber Range Lab, Australian Centre for Cyber Security / UNSW Canberra) — **Designated Fallback Candidate**
- **NF-UQ-NIDS-v2** (University of Queensland / NetFlow v9 standardized benchmark) — **Investigated Alternative**

**Primary Recommendation:** **CIC-IDS2017** is selected as the primary dataset because its five-day chronological capture structure directly supports temporal drift and held-out attack category experiments. Its known data-quality limitations (infinity values, missing values, column whitespace, and duplicate flows) are well-documented in scientific literature and can be deterministically handled in TraceGuard's Stage 3 pipeline. **UNSW-NB15** is retained as an immediate fallback if storage or memory constraints arise.

---

## 2. Candidate Dataset Profiles

### 2.1 Candidate 1: CIC-IDS2017 (Primary Candidate)

- **Official Source:** Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)  
  URL: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Primary Citation:**  
  > Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"*, Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.
- **Capture Period:** Monday, July 3, 2017 9:00 AM to Friday, July 7, 2017 5:00 PM (5 full working days).
- **Environment:** Dedicated testbed featuring two isolated subnets:
  - *Victim network:* 3 servers (Web, Mail, DNS/Active Directory), firewall, switches, and 10+ Windows/Ubuntu workstations.
  - *Attack network:* External Internet-facing nodes executing automated attack scripts.
  - *Background traffic generation:* B-Profile system generating human-like HTTP, HTTPS, FTP, SSH, and email activities.
- **Distribution Formats:**
  - Raw packet captures (PCAPs): ~50 GB.
  - Pre-extracted flow CSVs (`MachineLearningCSV.zip` / `GeneratedLabelledFlows.zip`): ~430 MB compressed, ~2.83 million flow records across 8 CSV files.
- **Flow Extractor:** CICFlowMeter (extracting 80+ statistical flow features per bidirectional flow).

#### Attack Coverage & Schedule:
| Day | File Name | Attack Categories Included |
|---|---|---|
| **Monday** | `Monday-WorkingHours.pcap_ISCX.csv` | Pure Benign background traffic (baseline) |
| **Tuesday** | `Tuesday-WorkingHours.pcap_ISCX.csv` | Brute Force (FTP-Patator, SSH-Patator) |
| **Wednesday** | `Wednesday-workingHours.pcap_ISCX.csv` | DoS (Slowloris, Slowhttptest, Hulk, GoldenEye), Heartbleed |
| **Thursday** | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`<br>`Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Web Attacks (Brute Force, XSS, SQL Injection), Infiltration |
| **Friday** | `Friday-WorkingHours-Morning.pcap_ISCX.csv`<br>`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`<br>`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Botnet (ARES), PortScan, DDoS (LOIC) |

---

### 2.2 Candidate 2: UNSW-NB15 (Fallback Candidate)

- **Official Source:** Cyber Range Lab of the Australian Centre for Cyber Security (ACCS), UNSW Canberra  
  URL: [https://research.unsw.edu.au/projects/unsw-nb15-dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **Primary Citation:**  
  > Nour Moustafa and Jill Slay, *"UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)"*, Military Communications and Information Systems Conference (MilCIS), 2015, pp. 1-6.
- **Capture Period:** January 22, 2015 and February 17, 2015 (16 hours and 15 hours).
- **Environment:** IXIA PerfectStorm tool generating mixed realistic synthetic background traffic and 9 CVE-based attack categories.
- **Distribution Formats:**
  - Raw PCAP files: ~100 GB.
  - 4 large raw CSV files (`UNSW-NB15_1.csv` to `4.csv`): ~2.54 million records.
  - Standard published train/test split: `UNSW_NB15_training-set.csv` (175,341 records) and `UNSW_NB15_testing-set.csv` (82,332 records).
- **Features:** 49 features generated via Bro-IDS (Zeek) and Argus, plus 1 binary label (`label`) and 1 multi-class label (`attack_cat`).
- **Attack Categories (9):** Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms.

---

### 2.3 Candidate 3: NF-UQ-NIDS-v2 (NetFlow Benchmark Candidate)

- **Official Source:** University of Queensland (UQ), Cyber Security Group  
  URL: [https://staff.itee.uq.edu.au/marius/NIDS_datasets/](https://staff.itee.uq.edu.au/marius/NIDS_datasets/)
- **Primary Citation:**  
  > Mohanad Sarhan, Siamak Layeghy, and Marcus Portmann, *"Towards a Universal Feature Set for Network Intrusion Detection Systems"*, IEEE Transactions on Network and Service Management, 2021.
- **Design:** Standardizes heterogeneous datasets (CIC-IDS2017, UNSW-NB15, BoT-IoT, ToN-IoT) into a uniform NetFlow v9 43-feature representation with standardized binary and multi-class attack names.
- **Size & Format:** Large CSV / Parquet dumps (tens of millions of records aggregated).
- **Assessment:** While valuable for cross-dataset transfer benchmarks, its standardized NetFlow feature extraction collapses raw packet inter-arrival dynamics and flow length variances that are critical for granular temporal drift and uncertainty calibration studies.

---

## 3. Detailed Comparative Evaluation

| Evaluation Dimension | CIC-IDS2017 (Recommended) | UNSW-NB15 (Fallback) | NF-UQ-NIDS-v2 (Alternative) |
|---|---|---|---|
| **Primary Domain** | Bi-directional flow statistics | Bro/Argus connection records | NetFlow v9 standardized flows |
| **Number of Features** | 78–84 numerical flow metrics | 49 numerical/categorical features | 43 NetFlow features |
| **Total Records** | ~2,830,743 | ~2,540,044 (full) / 257,673 (subset) | ~75,000,000+ (multi-dataset) |
| **Attack Diversity** | 7 major families, 14 granular variants | 9 attack categories | Harmonized cross-dataset labels |
| **Temporal Granularity** | 5 discrete capture days (Mon–Fri) | Two separate capture days (Jan/Feb) | Aggregated NetFlow windows |
| **Suitability for Drift** | **High** (daily baseline + injected attacks) | **Moderate** (temporal gap between 2 days) | **Low–Moderate** (loss of raw timing) |
| **Suitability for Unseen Category** | **High** (isolated days for Botnet, Infiltration, Web Attacks) | **Moderate** (categories intertwined across subsets) | **Moderate** |
| **TraceGuard Schema Alignment** | **Direct match** with `TrafficClass` in `ml/schemas.py` | Requires substantial category remapping | Partial remapping |
| **Memory / CPU Overhead** | Moderate (~1.5 GB in-memory RAM) | Low–Moderate (with standard split) | High (due to volume) |

---

## 4. CIC-IDS2017 In-Depth Audit & Data Quality Findings

Extensive research and published literature (e.g., Engelen et al., 2021; Rosay et al., 2022) have cataloged specific data quality anomalies in the official `MachineLearningCSV.zip` release of CIC-IDS2017. The TraceGuard data pipeline explicitly identifies and documents these:

### 4.1 Leading and Trailing Whitespace in Column Headers
- **Phenomenon:** Several CSV headers have leading spaces, such as `" Destination Port"`, `" Flow Duration"`, or trailing spaces `"Label "`.
- **Mitigation:** Column names must be systematically stripped (`col.strip()`) upon ingestion while preserving an immutable mapping of original names for auditing.

### 4.2 Non-Finite Numeric Values (`Infinity`, `-Infinity`, `NaN`)
- **Phenomenon:** Fields computing rates (notably `Flow Bytes/s` and `Flow Packets/s`) divide by `Flow Duration`. When duration is 0, the output contains `Infinity` or `NaN`.
- **Literature estimate:** ~2,800 records across the dataset contain non-finite numbers.
- **Mitigation:** The audit tool must explicitly locate and count non-finite values without dropping rows silently. In Stage 3 preprocessing, these will be replaced with domain-safe maximum finite representations or imputed appropriately.

### 4.3 Severe Class Imbalance
- **Phenomenon:** The majority class (`BENIGN`) represents over 80% of all traffic (~2.27M records). Attack categories range from widespread (DoS/DDoS: ~380k flows, PortScan: ~158k flows) to extreme minorities:
  - *Infiltration:* ~36 records (0.001%)
  - *Heartbleed:* ~11 records (0.0004%)
  - *Web Attack - SQL Injection:* ~21 records (0.0007%)
- **Implication:** Accuracy is a meaningless metric. TraceGuard must use Macro-F1, per-class PR-AUC, and selective prediction.

### 4.4 Inconsistent Label Encodings
- **Phenomenon:** Labels contain non-breaking spaces or encoding artifacts, such as `"Web Attack  Brute Force"` or `"Web Attack \xa0 Brute Force"`.
- **Mitigation:** The audit script reads files with encoding fallbacks (`utf-8`, `latin1`, `cp1252`) and reports exact raw string values before any downstream canonicalization.

### 4.5 Exact Duplicate Flows
- **Phenomenon:** Repeated flow records exist due to multi-interface packet captures and flow meter window overlaps (~10–15% duplication rate reported in literature).
- **Mitigation:** The audit script detects and quantifies exact duplicates without altering raw files.

### 4.6 Target and Identifier Leakage Risks
- **Phenomenon:** Including raw `Source IP`, `Destination IP`, `Timestamp`, or ephemeral `Source Port` can allow tree models to memorize specific attacker machine IPs rather than learning flow behavior.
- **Mitigation:** The audit tool flags these columns. The Stage 3 feature selection protocol excludes host identity fields from model training.

---

## 5. Evaluation Suitability

### 5.1 Held-Out Unseen Attack Category Experiment
CIC-IDS2017 provides distinct, cleanly isolated attack families:
- **Candidate Holdouts:** `Infiltration`, `Botnet`, or `Web Attacks`.
- **Design:** Train and validate models exclusively on Benign traffic and a subset of known attacks (e.g., DoS, PortScan, BruteForce). Evaluate on an untouched test set containing the held-out category.
- **Success Criteria:** The system must abstained or flag the held-out flows under `ABSTAIN` (reason: `UNSEEN_ATTACK_DISTRIBUTION`) rather than misclassifying them as `BENIGN` with false high confidence.

### 5.2 Temporal Traffic Drift Experiment
- **Monday:** 100% Benign baseline traffic.
- **Tuesday–Wednesday:** Ingestion and baseline attack training.
- **Thursday–Friday:** Out-of-time evaluation for concept drift and volume shifts.

---

---

## 6. Dataset Provenance: Canonical UNB Release vs. Hugging Face Mirror

### 6.1 Canonical UNB CIC-IDS2017 Release
- **Institution:** Canadian Institute for Cybersecurity, University of New Brunswick
- **Distribution Format:** `MachineLearningCSV.zip` (~430 MB compressed), extracting 8 CSV files with 79–84 columns depending on mirror variations.
- **Original Quirks:** Known for unstripped column headers (leading/trailing whitespace), duplicate column headers (`Fwd Header Length`), and non-breaking spaces in Web Attack labels.

### 6.2 Audited Hugging Face Mirror (`bvsam/cic-ids-2017`)
- **Repository:** [`bvsam/cic-ids-2017`](https://huggingface.co/datasets/bvsam/cic-ids-2017)
- **Retrieval Method:** Downloaded programmatically via `huggingface_hub.snapshot_download`:
  ```python
  from huggingface_hub import snapshot_download
  snapshot_download(
      repo_id='bvsam/cic-ids-2017',
      repo_type='dataset',
      allow_patterns=['machine_learning/*.parquet'],
      local_dir='data/raw/cicids2017_hf'
  )
  ```
- **Local Directory:** `data/raw/cicids2017_hf/machine_learning/`
- **File Format:** Apache Parquet (Snappy-compressed column format, total 256.11 MB).
- **Files Audited:** 8 files (matching the 5-day capture schedule: Monday through Friday).

### 6.3 Verified Schema & Metric Findings (from `reports/audit/cicids2017_hf/`)
| Metric | Verified Value | Observation / Provenance Note |
|---|---|---|
| **Total Rows** | **2,830,743** | Matches canonical published row count exactly. |
| **Total Features** | **78 numerical features + 1 Label column (79 total)** | Identical across all 8 files (100% schema consistency). |
| **Header Whitespace** | **0 whitespace headers** | Column names were stripped during Parquet serialization. |
| **Duplicate Columns** | **1 serialized duplicate** | Raw duplicated header `Fwd Header Length` is serialized as `Fwd Header Length_duplicated_0`. |
| **Missing Values (NaN/null)** | **1,358 records** | Confirmed present in `Flow Bytes/s` across files (requires imputation in Stage 3). |
| **Infinite Values (inf/-inf)** | **4,376 records** | Confirmed division-by-zero rates in `Flow Bytes/s` and `Flow Packets/s` (requires domain clipping in Stage 3). |
| **Duplicate Rows** | **256,479 records (9.06%)** | Confirmed session repetitions (e.g. 81,909 in Wednesday DoS, 72,353 in Friday PortScan). |
| **Label Encodings** | **15 distinct string labels** | Web Attack labels contain the replacement character `\ufffd` (`Web Attack \ufffd Brute Force`, etc.) due to UTF-8 transcoding of non-breaking spaces. |
| **Identity Features** | **Excluded in mirror** | The `machine_learning/` parquet partition contains statistical flow features and `Destination Port`, but does not contain raw `Source IP`, `Destination IP`, or explicit `Timestamp` columns. |

### 6.4 Remaining Provenance Disclaimers
1. While row counts and class totals match canonical literature, this mirror represents a pre-converted Parquet serialization rather than the raw original UNB CSV byte stream.
2. Because host IPs and wall-clock timestamps are omitted from the `machine_learning` parquet tables, temporal evaluation relies on the day-level capture boundaries represented by the file naming hierarchy (`Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday`).

---

## 7. Decision and Readiness Status

- **Dataset Selection:** **APPROVED — CIC-IDS2017 Parquet Mirror (`data/raw/cicids2017_hf/machine_learning/`)**.
- **Audit Tooling:** Fully functional and verified for both CSV and Parquet.
- **Stage 2 Status:** **COMPLETE.** All 8 files audited, metrics validated, and data quality issues cataloged.
- **Next Stage:** Ready to begin **Stage 3: Data Cleaning, Leakage-Resistant Splits, and Baseline Classifier Training**.

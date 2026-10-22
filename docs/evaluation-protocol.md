# TraceGuard — Scientific Evaluation Protocol

**Document Version:** 1.0.0  
**Status:** Approved for Implementation  
**Project:** TraceGuard — Adaptive Network Threat Detection  

---

## 1. Problem Statement & Motivation

In production network security, machine learning models frequently suffer from catastrophic generalization failure despite reporting near-perfect accuracy (>99.5%) in academic literature. The primary causes of this divergence are:

1. **Severe Data Leakage through Naive Random Splitting:** Correlated packet flows, bidirectional session pairs, and identical IP/port combinations leak across training and test splits.
2. **False Confidence on Zero-Day / Novel Attacks:** Standard discriminative classifiers force unknown anomalous flows into closed-world output classes with artificially high softmax confidence.
3. **Temporal Concept and Covariate Drift:** Normal network traffic profiles and attack behaviors shift dynamically across hours, days, and network environments.
4. **Lack of Uncertainty Calibration:** Softmax probabilities are notoriously overconfident and do not represent true empirical likelihoods.

This document establishes the scientific evaluation framework for TraceGuard to ensure that empirical results reflect real-world threat detection capabilities rather than split artifacts.

---

## 2. Leakage Prevention & Baseline Split Strategy

### 2.1 The Perils of Naive Random Splitting

In tabular network flow datasets (such as CIC-IDS2017), randomly partitioning records into train (80%) and test (20%) causes severe data leakage for several reasons:

- **Bidirectional Session Duplication:** High-volume connections (e.g., file downloads, streaming, port scanning) produce dozens of sequential flow records sharing the exact same source IP, destination IP, service port, and inter-arrival timing patterns. A random split distributes packets from the *exact same session* into both train and test.
- **Identity Memorization:** When network identifiers (`Source IP`, `Destination IP`, `Source Port`, `Flow ID`) are included in feature matrices, tree ensembles and neural networks memorize the specific IP addresses of attack machines in the testbed rather than learning behavioral flow dynamics.
- **Overestimation of Generalization:** Under a random split, the test set tests *interpolation* across known host sessions, yielding 99.8% F1-scores that instantly collapse when evaluated against a different machine or temporal period.

### 2.2 TraceGuard Leakage-Resistant Protocol

To prevent leakage, TraceGuard enforces three mandatory rules:
1. **Identifier Exclusion:** All host identity and session tracking fields (`Flow ID`, `Source IP`, `Destination IP`, `Timestamp`, and ephemeral `Source Port`) are strictly excluded from the feature matrix $\mathbf{X}$. Only behavioral statistical metrics (packet lengths, inter-arrival times, window sizes, flag counts) are retained.
2. **Session / Group Isolation:** Splitting strategies must group flows by session or capture time rather than uniform random sampling.
3. **Temporal Partitioning:** As outlined in Section 4, evaluation splits must respect capture time boundaries.

```
+-------------------------------------------------------------------------------+
|                             RAW CAPTURE TIMELINE                              |
|   Monday (Benign)  |  Tuesday (BruteForce)  |  Wednesday (DoS)  |  Thu-Fri... |
+-------------------------------------------------------------------------------+
                                      |
         +----------------------------+----------------------------+
         v                                                         v
+-------------------------------+                         +---------------------+
|        TRAIN + VAL SET        |                         | UNTOUCHED TEST SET  |
| (Baseline Chronological Split)|                         | (Out-of-Time Eval)  |
+-------------------------------+                         +---------------------+
```

---

## 3. Held-Out Attack Category Experiment (Zero-Day Evaluation)

### 3.1 Experimental Design

The primary objective of TraceGuard is to reliably detect and abstain on **previously unseen attack categories** rather than silently misclassifying them as benign.

---

## 3. Capture-Day & Session Confounding in CIC-IDS2017

A critical observation from our empirical audit of CIC-IDS2017 is that **attack categories are strictly scheduled by capture day**:

| Capture Day | Attack Classes Present | Benign Record Count | Attack Record Count |
|---|---|---|---|
| **Monday** | *None (100% Benign baseline)* | 529,918 | 0 |
| **Tuesday** | FTP-Patator, SSH-Patator | 432,074 | 13,835 |
| **Wednesday** | DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, Heartbleed | 440,031 | 252,672 |
| **Thursday** | Web Attacks (Brute Force, XSS, SQL Injection), Infiltration | 456,752 | 2,216 |
| **Friday** | Bot (ARES), PortScan, DDoS (LOIC) | 414,322 | 288,923 |

### 3.1 The Confounding Risk
If an experiment naively splits data chronologically (e.g., train on Monday–Wednesday, test on Friday):
- The test set contains `DDoS`, `PortScan`, and `Bot`, which **never appeared** in the training set.
- A model failure on Friday cannot be attributed cleanly to *temporal drift* versus *unseen attack emergence*.
- Similarly, evaluating an "unseen attack" that only occurred on Friday conflates the attack signature with Friday's unique background traffic distribution.

### 3.2 The Three Defensible Experimental Protocols

To disentangle these confounding factors, TraceGuard defines three distinct experimental protocols:

```
+---------------------------------------------------------------------------------------------------+
|                                  CIC-IDS2017 (2.83M Flow Records)                                 |
+---------------------------------------------------------------------------------------------------+
        |                                       |                                    |
        v                                       v                                    v
+-------------------------------+   +-------------------------------+   +---------------------------+
|  PROTOCOL A: BASELINE EVAL    |   | PROTOCOL B: ZERO-DAY HOLDOUT  |   | PROTOCOL C: TEMPORAL DRIFT|
|  - Multi-class classification |   | - Explicit category withhold  |   | - Pure Benign drift eval  |
|  - Stratified session split   |   | - Anomaly + Abstention test   |   | - Mon/Tue -> Thu/Fri eval |
|  - Leakage-filtered features  |   | - Unseen rejection rate       |   | - PSI & KS covariate shift|
+-------------------------------+   +-------------------------------+   +---------------------------+
```

---

## 4. Detailed Protocol Specifications

### 4.1 Protocol A: Controlled Baseline Classification (Known Attacks)
- **Objective:** Evaluate the baseline multi-class classifier's capacity to discriminate between known attack types and benign traffic under severe class imbalance without temporal distortion.
- **Partitioning:** Stratified splitting within each class across all capture days.
- **Leakage Prevention:** Deduplication applied; all host identifiers (`Destination Port` flags, IP addresses) excluded from feature inputs.
- **Target Metrics:** Macro-F1, per-class Precision/Recall, PR-AUC for extreme minority classes (Heartbleed, SQL Injection, Infiltration).

### 4.2 Protocol B: Held-Out Attack Category Experiment (Zero-Day Evaluation)
- **Objective:** Measure the detector's ability to trigger `ABSTAIN` (reason: `UNSEEN_ATTACK_DISTRIBUTION`) when encountering novel attack families.
- **Holdout Selection:**
  - *Candidate 1: `Bot` (Friday Morning)* — 1,966 flows; compact, modern malware behavior.
  - *Candidate 2: `Infiltration` (Thursday Afternoon)* — 36 flows; stealth multi-stage compromise.
  - *Candidate 3: `Web Attack` family (Thursday Morning)* — 2,180 flows; application-layer exploits.
- **Data Partitions:**
  - $\mathcal{D}_{train}$: Benign traffic + all attack categories *except* the chosen holdout $\mathcal{C}_{unseen}$.
  - $\mathcal{D}_{val}$: Benign traffic + known attack validation slice (used strictly for tuning anomaly thresholds $\tau_{anomaly}$ and calibration parameters).
  - $\mathcal{D}_{test}$: Benign traffic + known attack test slice + **100% of $\mathcal{C}_{unseen}$**.
- **Success Criteria:** The system must abstained on $\mathcal{C}_{unseen}$ instances rather than assigning high-confidence benign or known-attack predictions.

### 4.3 Protocol C: Controlled Temporal Drift Evaluation (Covariate Shift)
- **Objective:** Quantify detector degradation resulting strictly from temporal traffic changes in normal operations, independent of novel attack emergence.
- **Partitioning:**
  - $\mathcal{D}_{drift\_train}$: Benign traffic from Monday & Tuesday.
  - $\mathcal{D}_{drift\_val}$: Benign traffic from Wednesday.
  - $\mathcal{D}_{drift\_test}$: Benign traffic from Thursday & Friday.
- **Analysis:**
  - Calculate Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) statistics across feature distributions across days.
  - Track False Positive Rate (FPR) drift on out-of-time benign flows.

---

## 5. Validation-Only Tuning and Untouched Test Set

TraceGuard enforces strict architectural separation between validation and testing:

```
                            +--------------------------+
                            |     FULL DATASET         |
                            +--------------------------+
                                         |
                     +-------------------+-------------------+
                     | (Development)                         | (Final Holdout)
                     v                                       v
         +-----------------------+              +--------------------------+
         | TRAIN + VALIDATION    |              | UNTOUCHED TEST SET       |
         +-----------------------+              +--------------------------+
                     |                                       |
          +----------+----------+                            | (Locked until
          v                     v                            |  all parameters
    +-----------+         +------------+                     |  are frozen)
    | Train Set |         | Val Set    |                     |
    | (Weights) |         | (Thresholds|                     |
    |           |         |  & Calib.) |                     |
    +-----------+         +------------+                     |
                               |                             v
                               +---------------------> [FINAL EVALUATION]
                                                      - One-shot execution
                                                      - No parameter feedback
```

### Protocol Rules:
1. **Preprocessing Pipeline Fit:** All scalers, imputers, and encoders are fit strictly on $\mathcal{D}_{train}$. Applying `fit_transform` to the whole dataset or test set is strictly prohibited.
2. **Threshold Selection:** Abstention thresholds ($\tau_{conf}$, $\tau_{anomaly}$) are optimized strictly on $\mathcal{D}_{val}$.
3. **One-Shot Evaluation:** The test set $\mathcal{D}_{test}$ is processed exactly once to record final metrics.

---

## 6. Evaluation Metrics Suite

### 6.1 Multi-Class Classification Performance
Because benign traffic accounts for >80% of records, standard accuracy is misleading. We report:
- **Macro-Averaged F1 Score:** Unweighted mean of F1 scores across all classes:
  $$\text{Macro-F1} = \frac{1}{|\mathcal{C}|} \sum_{c \in \mathcal{C}} F1_c$$
- **Per-Class Precision and Recall:** Essential for monitoring detection rates on rare attacks (e.g. Infiltration, Heartbleed).
- **Precision-Recall AUC (PR-AUC):** Evaluates trade-offs on severe minority attack classes where ROC-AUC produces inflated results.

### 6.2 Uncertainty Calibration Metrics
A model outputting a confidence of $0.80$ should be correct exactly $80\%$ of the time.

- **Expected Calibration Error (ECE):**
  Predictions are partitioned into $M$ equally spaced confidence bins $B_m \subset (0, 1]$.
  $$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$
- **Brier Score:** Mean squared difference between predicted class probabilities and one-hot ground truth vectors:
  $$\text{Brier} = \frac{1}{N} \sum_{i=1}^N \sum_{k=1}^K (p_{ik} - y_{ik})^2$$
- **Reliability Diagrams:** Plots of empirical accuracy against binned predicted confidence.

### 6.3 Selective Prediction & Abstention Metrics
TraceGuard provides selective triage via an abstention mechanism:
- **Coverage ($\Phi$):** Fraction of flows for which the model issues a definitive decision:
  $$\Phi = \frac{|\{i \mid \text{decision}_i \neq \text{ABSTAIN}\}|}{N}$$
- **Selective Risk ($\mathcal{R}_{accepted}$):** Error rate evaluated strictly over accepted flows:
  $$\mathcal{R}_{accepted} = \frac{\sum_{i: \text{decision}_i \neq \text{ABSTAIN}} \mathbb{I}(\hat{y}_i \neq y_i)}{|\{i \mid \text{decision}_i \neq \text{ABSTAIN}\}|}$$
- **Unseen Attack Rejection Rate:** Fraction of flows from $\mathcal{C}_{unseen}$ that are correctly routed to `ABSTAIN`:
  $$\text{RejectionRate}_{unseen} = \frac{|\{j \in \mathcal{D}_{unseen} \mid \text{decision}_j = \text{ABSTAIN}\}|}{|\mathcal{D}_{unseen}|}$$

---

## 7. Critical Scientific Distinctions

> [!IMPORTANT]
> **Anomaly Scores $\neq$ Calibrated Probabilities**  
> An unsupervised anomaly score (e.g., Isolation Forest path length, reconstruction error, or Mahalanobis distance) represents geometric or density distance from a training manifold. It does **not** obey the axioms of probability:
> - It does not sum to 1 over an event space.
> - It cannot be directly interpreted as the likelihood of being an attack.
>
> TraceGuard strictly treats the anomaly score as an **epistemic uncertainty / novelty signal**, not a posterior probability.

> [!CAUTION]
> **Zero-Day Detection Integrity Rule**  
> An unseen attack is **not** detected unless:
> 1. The model was trained without any instances, variants, or knowledge of that attack family.
> 2. The pipeline routes the flow to `ABSTAIN` (with reason `UNSEEN_ATTACK_DISTRIBUTION`) or flags it as an anomaly with verifiable statistical separation from benign validation traffic.
> 
> Claiming detection of unknown attacks without adhering to this protocol is scientifically invalid.

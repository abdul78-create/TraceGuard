# Data Directory

This directory houses network flow datasets for the TraceGuard project.

## Directory Structure

- `raw/`: Unmodified raw network flow data (e.g., CSV, PCAP, or Parquet exports). **Kept out of version control.**
- `processed/`: Cleaned, normalized, and encoded datasets prepared for ML training and evaluation splits. **Kept out of version control.**
- `interim/`: Intermediate transformations or sampled validation subsets.

## Stage 2 Dataset Selection Guidelines

During Stage 2, candidate datasets (such as CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, or NF-UQ-NIDS-v2) will be evaluated against:
1. Ground truth label reliability and realistic traffic proportion.
2. Attack diversity (DDoS, PortScan, BruteForce, Botnet, Infiltration).
3. Availability of flow-level features without synthetic bias or obvious target leakage.
4. Feasibility for unseen attack holdout experiments (e.g., training on known attacks and evaluating on withheld zero-day categories).
5. Drift simulation suitability (temporal splits or varied environment captures).

> **Important**: No dataset is downloaded or bundled in Stage 1.

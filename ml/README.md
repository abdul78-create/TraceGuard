# TraceGuard Machine Learning Pipeline

This module encapsulates the core research and detection architecture for TraceGuard.

## Planned Stages

- **Stage 2**: Dataset analysis, exploration, selection, and leakage prevention protocol.
- **Stage 3**: Data cleaning, leakage-resistant train/val/test splitting, baseline multi-class classifier, and class-imbalance mitigations (PR-AUC, cost-sensitive learning).
- **Stage 4**:
  - Anomaly detection (e.g., Isolation Forest / One-Class SVM / Reconstruction Error).
  - Unseen attack category holdout evaluation.
  - Prediction confidence calibration (e.g., Platt Scaling / Isotonic Regression / Temperature Scaling).
  - Abstention policy (selective prediction: abstaining when epistemic uncertainty is elevated or score falls below threshold).
  - Traffic and concept drift monitoring (e.g., Kolmogorov-Smirnov test, Wasserstein distance, Population Stability Index).

## Architecture Boundaries (Stage 1)

In Stage 1, no models are trained, and no synthetic detection values are fabricated. The classes and type signatures in `schemas.py` establish the exact data contract that the API and future training pipelines will follow.

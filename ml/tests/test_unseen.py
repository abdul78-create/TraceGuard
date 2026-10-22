"""
Unit and integration tests for TraceGuard Stage 4.1:
Research Audit & Corrected Evaluation Pipeline.
Verifies:
1. Strict 5-way disjoint partitioning (train, val_cal, val_thresh, test, heldout).
2. Platt calibration fitting on val_cal vs evaluation on untouched test.
3. Anomaly scoring and threshold tuning on val_thresh benign flows.
4. Multi-policy triage behavior (Permissive, Balanced, Conservative).
5. ECE and Brier score calibration calculations.
6. PSI population stability index calculation.
7. End-to-end integration test on synthetic Parquet data.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from ml.preprocessing import PreprocessPipeline, create_stage4_disjoint_partitions
from ml.schemas import AbstentionReason, DecisionOutcome
from ml.train_unseen import (
    AnomalyDetector,
    TriagePolicyEvaluator,
    compute_ece_and_brier,
    compute_psi,
    run_stage4_experiments,
)


@pytest.fixture
def synthetic_5way_df():
    """
    Creates a small synthetic dataset containing Benign, DoS Hulk, and Bot flows
    with unique feature hashes for testing 5-way disjoint partitioning.
    """
    np.random.seed(42)
    n_benign = 200
    n_dos = 60
    n_bot = 40
    total = n_benign + n_dos + n_bot

    features = [f"feat_{i}" for i in range(10)]
    X = np.random.randn(total, 10)

    # Shift distributions so Bot looks different
    X[n_benign + n_dos:] += 3.5

    data = {f: X[:, i] for i, f in enumerate(features)}
    labels = ["BENIGN"] * n_benign + ["DoS Hulk"] * n_dos + ["Bot"] * n_bot
    binary = [0] * n_benign + [1] * (n_dos + n_bot)
    days = ["Monday"] * 100 + ["Tuesday"] * 100 + ["Wednesday"] * n_dos + ["Friday"] * n_bot

    df = pd.DataFrame(data)
    df["clean_label"] = labels
    df["binary_label"] = binary
    df["meta_capture_day"] = days
    df["meta_source_file"] = "synthetic.parquet"
    df["f_hash"] = pd.util.hash_pandas_object(df[features], index=False)
    return df


def test_heldout_attack_exclusion(synthetic_5way_df):
    """Verifies that heldout attack class is strictly excluded from training, calibration, and threshold-tuning partitions."""
    (
        train_df,
        val_cal_df,
        val_thresh_df,
        test_df,
        heldout_test_df,
    ) = create_stage4_disjoint_partitions(
        synthetic_5way_df,
        heldout_label="Bot",
        train_frac=0.60,
        val_cal_frac=0.10,
        val_thresh_frac=0.15,
        test_frac=0.15,
        random_state=42,
    )
    for p_df in [train_df, val_cal_df, val_thresh_df, test_df]:
        assert "Bot" not in p_df["clean_label"].values
    assert len(heldout_test_df) == 40
    assert (heldout_test_df["clean_label"] == "Bot").all()


def test_5way_partition_hash_disjointness(synthetic_5way_df):
    """Verifies all 10 pairwise intersections between the 5 partition feature-hash sets are strictly empty."""
    (
        train_df,
        val_cal_df,
        val_thresh_df,
        test_df,
        heldout_test_df,
    ) = create_stage4_disjoint_partitions(
        synthetic_5way_df,
        heldout_label="Bot",
        train_frac=0.60,
        val_cal_frac=0.10,
        val_thresh_frac=0.15,
        test_frac=0.15,
        random_state=42,
    )
    assert len(train_df) > 0
    assert len(val_cal_df) > 0
    assert len(val_thresh_df) > 0
    assert len(test_df) > 0
    assert len(heldout_test_df) > 0

    hashes = {
        "train": set(train_df["f_hash"]),
        "val_cal": set(val_cal_df["f_hash"]),
        "val_thresh": set(val_thresh_df["f_hash"]),
        "test": set(test_df["f_hash"]),
        "heldout": set(heldout_test_df["f_hash"]),
    }
    names = list(hashes.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            overlap = hashes[names[i]].intersection(hashes[names[j]])
            assert len(overlap) == 0, f"Leakage detected between {names[i]} and {names[j]}!"


def test_anomaly_scoring_and_threshold_tuning():
    """Verifies that Isolation Forest produces scores in [0, 1] and tunes thresholds."""
    np.random.seed(42)
    X_train = np.random.normal(loc=0.0, scale=1.0, size=(500, 8))
    X_val = np.random.normal(loc=0.0, scale=1.0, size=(200, 8))
    X_outliers = np.random.normal(loc=8.0, scale=2.0, size=(50, 8))

    detector = AnomalyDetector(n_estimators=50, random_state=42)
    detector.fit(X_train)

    val_scores = detector.score(X_val)
    outlier_scores = detector.score(X_outliers)

    assert np.all(val_scores >= 0.0) and np.all(val_scores <= 1.0)
    assert np.all(outlier_scores >= 0.0) and np.all(outlier_scores <= 1.0)
    assert np.mean(outlier_scores) > np.mean(val_scores)

    thresh = detector.tune_thresholds_on_validation(X_val, target_fprs=[0.05, 0.10, 0.25])
    assert "5%" in thresh and "10%" in thresh and "25%" in thresh
    assert thresh["25%"] < thresh["10%"] < thresh["5%"]


def test_multi_policy_triage_behavior():
    """Verifies behavior across Permissive, Balanced, and Conservative triage policies."""
    evaluator = TriagePolicyEvaluator()

    # Flow cases:
    # Flow 0: High attack prob (0.95), normal score (0.10) -> THREAT_SUSPECTED in all policies
    # Flow 1: Low attack prob (0.01), normal score (0.05) -> LIKELY_BENIGN in all policies
    # Flow 2: Low attack prob (0.01), moderate anomaly (0.30) -> Cleared by Policy A, but ABSTAIN in B and C
    # Flow 3: Low attack prob (0.01), extreme anomaly (0.75) -> ABSTAIN in all policies
    probs = np.array([0.95, 0.01, 0.01, 0.01])
    anom_scores = np.array([0.10, 0.05, 0.30, 0.75])

    tau_5pct = 0.60
    tau_25pct = 0.20
    tau_50pct = 0.10

    # Policy A (Permissive): Clears Flow 2 because 0.30 < tau_5pct (0.60)
    d_a, _ = evaluator.evaluate_policy_a_permissive(probs, anom_scores, tau_5pct)
    assert d_a[0] == DecisionOutcome.THREAT_SUSPECTED.value
    assert d_a[1] == DecisionOutcome.LIKELY_BENIGN.value
    assert d_a[2] == DecisionOutcome.LIKELY_BENIGN.value  # Permissive flaw
    assert d_a[3] == DecisionOutcome.ABSTAIN.value

    # Policy B (Balanced): Abstains on Flow 2 because 0.30 >= tau_25pct (0.20)
    d_b, r_b = evaluator.evaluate_policy_b_balanced(probs, anom_scores, tau_5pct, tau_25pct)
    assert d_b[0] == DecisionOutcome.THREAT_SUSPECTED.value
    assert d_b[1] == DecisionOutcome.LIKELY_BENIGN.value
    assert d_b[2] == DecisionOutcome.ABSTAIN.value  # Caught by Balanced Guard
    assert r_b[2] == AbstentionReason.FEATURE_ANOMALY.value
    assert d_b[3] == DecisionOutcome.ABSTAIN.value

    # Policy C (Conservative): Requires inlier < median (0.10)
    d_c, _ = evaluator.evaluate_policy_c_conservative(probs, anom_scores, tau_50pct)
    assert d_c[0] == DecisionOutcome.THREAT_SUSPECTED.value
    assert d_c[1] == DecisionOutcome.LIKELY_BENIGN.value
    assert d_c[2] == DecisionOutcome.ABSTAIN.value
    assert d_c[3] == DecisionOutcome.ABSTAIN.value


def test_ece_and_brier_computation():
    """Verifies ECE and Brier score calculation against ground truth."""
    y_true = np.array([0, 0, 1, 1, 0, 1])
    y_prob_perfect = np.array([0.0, 0.0, 1.0, 1.0, 0.0, 1.0])
    ece_perf, brier_perf, table = compute_ece_and_brier(y_true, y_prob_perfect, n_bins=5)
    assert ece_perf == 0.0
    assert brier_perf == 0.0
    assert len(table) == 5

    y_prob_poor = np.array([0.8, 0.9, 0.1, 0.2, 0.7, 0.2])
    ece_poor, brier_poor, _ = compute_ece_and_brier(y_true, y_prob_poor, n_bins=5)
    assert ece_poor > 0.4
    assert brier_poor > 0.4


def test_psi_calculation():
    """Verifies Population Stability Index calculation on identical vs shifted arrays."""
    np.random.seed(42)
    base = np.random.normal(0, 1, 1000)
    identical = np.random.normal(0, 1, 1000)
    shifted = np.random.normal(2, 1, 1000)

    psi_stable = compute_psi(base, identical)
    psi_shifted = compute_psi(base, shifted)

    assert psi_stable < 0.1
    assert psi_shifted > 0.25


def test_end_to_end_stage4_synthetic_pipeline(tmp_path):
    """End-to-end integration test of run_stage4_experiments using synthetic Parquet files."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    out_dir = tmp_path / "reports"
    model_dir = tmp_path / "models"

    np.random.seed(42)
    n_rows = 400
    features = [f"Fwd Packet Length_{i}" for i in range(5)]
    X = np.random.randn(n_rows, 5)
    labels = ["BENIGN"] * 260 + ["DoS Hulk"] * 80 + ["Bot"] * 60

    df1 = pd.DataFrame({f: X[:200, i] for i, f in enumerate(features)})
    df1["Label"] = labels[:200]
    df1.to_parquet(data_dir / "Monday-WorkingHours.pcap_ISCX.csv.parquet")

    df2 = pd.DataFrame({f: X[200:, i] for i, f in enumerate(features)})
    df2["Label"] = labels[200:]
    df2.to_parquet(data_dir / "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet")

    metrics = run_stage4_experiments(
        data_dir=data_dir,
        output_dir=out_dir,
        model_dir=model_dir,
        heldout_label="Bot",
        max_train_samples=200,
        random_seed=42,
    )

    # Verify all artifacts exist
    assert (out_dir / "stage4_unseen_detection_metrics.json").exists()
    assert (out_dir / "stage4_unseen_detection_report.md").exists()
    assert (model_dir / "stage4_heldout_classifier.joblib").exists()
    assert (model_dir / "stage4_calibrator.joblib").exists()
    assert (model_dir / "stage4_isolation_forest.joblib").exists()
    assert (model_dir / "stage4_preprocessor.joblib").exists()
    assert (model_dir / "stage4_metadata.json").exists()

    # Validate metrics structure
    assert "protocol_b_heldout_experiment" in metrics
    p_b = metrics["protocol_b_heldout_experiment"]
    assert p_b["heldout_label"] == "Bot"
    assert "calibration_evaluation_untouched_test" in p_b
    assert "selective_prediction_triage_comparison" in p_b
    assert "policy_a_permissive" in p_b["selective_prediction_triage_comparison"]
    assert "policy_b_balanced" in p_b["selective_prediction_triage_comparison"]
    assert "policy_c_conservative" in p_b["selective_prediction_triage_comparison"]

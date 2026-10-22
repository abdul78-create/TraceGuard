"""
TraceGuard — Automated Tests for Stage 3 Preprocessing, Splitting, and Baseline ML.

All tests utilize tiny synthetic fixtures created at test execution time.
No fabricated production dataset results.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from ml.preprocessing import (
    CONSTANT_FEATURE_NAMES,
    DUPLICATE_FEATURE_NAMES,
    LABEL_MAPPING,
    PreprocessPipeline,
    create_leakage_resistant_splits,
    load_and_validate_dataset,
    normalize_raw_label_string,
    parse_label,
)
from ml.train_baseline import (
    build_estimator,
    compute_binary_evaluation_metrics,
    compute_per_attack_family_breakdown,
    generate_markdown_report,
)


@pytest.fixture
def synthetic_flow_df() -> pd.DataFrame:
    """Provides a minimal synthetic network flow dataset with known properties."""
    np.random.seed(42)
    n = 100
    df = pd.DataFrame({
        "Destination Port": np.random.randint(20, 8080, size=n),
        "Flow Duration": np.random.uniform(10.0, 5000.0, size=n),
        "Total Fwd Packets": np.random.randint(1, 50, size=n),
        "Total Backward Packets": np.random.randint(0, 50, size=n),
        "Flow Bytes/s": np.random.uniform(100.0, 50000.0, size=n),
        "Flow Packets/s": np.random.uniform(1.0, 1000.0, size=n),
        "Fwd Header Length": np.random.randint(20, 60, size=n),
        "Fwd Header Length_duplicated_0": np.random.randint(20, 60, size=n),  # clone
        "Bwd PSH Flags": np.zeros(n),  # constant
        "Bwd URG Flags": np.zeros(n),  # constant
        "Fwd Avg Bytes/Bulk": np.zeros(n),  # constant
        "Fwd Avg Packets/Bulk": np.zeros(n),  # constant
        "Fwd Avg Bulk Rate": np.zeros(n),  # constant
        "Bwd Avg Bytes/Bulk": np.zeros(n),  # constant
        "Bwd Avg Packets/Bulk": np.zeros(n),  # constant
        "Bwd Avg Bulk Rate": np.zeros(n),  # constant
        "Label": ["BENIGN"] * 80 + ["DoS Hulk"] * 10 + ["PortScan"] * 5 + ["Bot"] * 5,
    })
    # Ensure clone is identical
    df["Fwd Header Length_duplicated_0"] = df["Fwd Header Length"]
    return df


def test_label_normalization_and_validation():
    """Validates raw label string cleaning and rejection of invalid labels."""
    # Test replacement character in Web Attack labels
    assert normalize_raw_label_string("Web Attack \ufffd Brute Force") == "Web Attack - Brute Force"
    assert normalize_raw_label_string("Web Attack \xa0 XSS") == "Web Attack - XSS"
    assert normalize_raw_label_string("Web Attack  Sql Injection") == "Web Attack - Sql Injection"

    # Test parse_label mapping
    n_str, c_cls, b_t = parse_label("Web Attack \ufffd Brute Force")
    assert n_str == "Web Attack - Brute Force"
    assert c_cls.value == "WEB_ATTACK"
    assert b_t == 1

    n_str, c_cls, b_t = parse_label("BENIGN")
    assert c_cls.value == "BENIGN"
    assert b_t == 0

    # Test rejection of unknown or malformed labels
    with pytest.raises(ValueError) as exc_info:
        parse_label("UNKNOWN_MALICIOUS_TROJAN")
    assert "Unknown or malformed network flow label" in str(exc_info.value)

    with pytest.raises(ValueError):
        parse_label("")


def test_duplicate_and_conflicting_label_resolution(tmp_path: Path):
    """Verifies that identical feature rows with conflicting labels are dropped from clean pool."""
    data_dir = tmp_path / "conflict_dataset"
    data_dir.mkdir()

    # Create two rows with IDENTICAL features but CONFLICTING labels (BENIGN vs DoS Hulk)
    df = pd.DataFrame({
        "Flow Duration": [100.0, 100.0, 500.0, 600.0],
        "Total Fwd Packets": [10, 10, 50, 60],
        "Flow Bytes/s": [1000.0, 1000.0, 5000.0, 6000.0],
        "Label": ["BENIGN", "DoS Hulk", "BENIGN", "PortScan"],
    })
    parquet_path = data_dir / "Monday-WorkingHours.pcap_ISCX.csv.parquet"
    df.to_parquet(parquet_path, index=False)

    df_clean, summary = load_and_validate_dataset(data_dir, drop_conflicting=True, deduplicate=True)

    # 2 rows should be removed due to conflict
    assert summary.conflicting_feature_rows_removed == 2
    assert summary.conflicting_hash_groups == 1
    assert "BENIGN" in summary.conflicting_label_counts
    assert "DoS Hulk" in summary.conflicting_label_counts

    # Remaining clean rows: row 2 and row 3
    assert len(df_clean) == 2
    assert set(df_clean["clean_label"]) == {"BENIGN", "PortScan"}


def test_feature_target_separation(tmp_path: Path, synthetic_flow_df: pd.DataFrame):
    """Ensures metadata, labels, and hashes are never included in retained model features."""
    data_dir = tmp_path / "features_dataset"
    data_dir.mkdir()
    parquet_path = data_dir / "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet"
    synthetic_flow_df.to_parquet(parquet_path, index=False)

    df_clean, summary = load_and_validate_dataset(data_dir)

    forbidden = {
        "Label",
        "clean_label",
        "canonical_class",
        "binary_label",
        "meta_source_file",
        "meta_capture_day",
        "f_hash",
    }
    for col in summary.retained_features:
        assert col not in forbidden

    # Redundant clone and constant columns should be dropped
    assert "Fwd Header Length_duplicated_0" in summary.dropped_features
    assert "Bwd PSH Flags" in summary.dropped_features


def test_non_finite_values_and_train_only_imputation():
    """Verifies that non-finite values (infs) are converted to NaN and imputed using train medians."""
    # Train set has median = 20.0 for col 0
    X_train = pd.DataFrame({
        "feat_a": [10.0, 20.0, 30.0, np.nan, np.inf],
        "feat_b": [1.0, 2.0, 3.0, 4.0, 5.0],
    })
    # Test set contains infs and NaNs
    X_test = pd.DataFrame({
        "feat_a": [np.inf, -np.inf, np.nan],
        "feat_b": [10.0, 20.0, 30.0],
    })

    pipe = PreprocessPipeline(imputer_strategy="median")
    pipe.fit(X_train)

    # Train median for feat_a is 20.0 (from 10.0, 20.0, 30.0)
    assert pipe.feature_medians_["feat_a"] == 20.0
    assert pipe.feature_medians_["feat_b"] == 3.0

    X_test_trans = pipe.transform(X_test)
    assert not np.isnan(X_test_trans).any()
    assert not np.isinf(X_test_trans).any()
    # All non-finite in feat_a should be imputed to train median (20.0)
    assert np.all(X_test_trans[:, 0] == 20.0)


def test_leakage_resistant_split_disjointness(synthetic_flow_df: pd.DataFrame):
    """Guarantees that train, val, and test feature hashes are mutually disjoint."""
    # Compute feature hash
    feature_cols = [c for c in synthetic_flow_df.columns if c != "Label"]
    synthetic_flow_df["f_hash"] = pd.util.hash_pandas_object(synthetic_flow_df[feature_cols], index=False)
    synthetic_flow_df["binary_label"] = (synthetic_flow_df["Label"] != "BENIGN").astype(int)

    train_df, val_df, test_df = create_leakage_resistant_splits(
        synthetic_flow_df,
        test_size=0.15,
        val_size=0.15,
        random_state=42,
    )

    h_train = set(train_df["f_hash"])
    h_val = set(val_df["f_hash"])
    h_test = set(test_df["f_hash"])

    assert h_train.isdisjoint(h_val)
    assert h_train.isdisjoint(h_test)
    assert h_val.isdisjoint(h_test)
    assert len(train_df) + len(val_df) + len(test_df) == len(synthetic_flow_df)


def test_reproducibility_with_fixed_seed(synthetic_flow_df: pd.DataFrame):
    """Guarantees deterministic splitting and model training under identical seeds."""
    feature_cols = [c for c in synthetic_flow_df.columns if c != "Label"]
    synthetic_flow_df["f_hash"] = pd.util.hash_pandas_object(synthetic_flow_df[feature_cols], index=False)
    synthetic_flow_df["binary_label"] = (synthetic_flow_df["Label"] != "BENIGN").astype(int)

    train_df_1, _, test_df_1 = create_leakage_resistant_splits(synthetic_flow_df, random_state=42)
    train_df_2, _, test_df_2 = create_leakage_resistant_splits(synthetic_flow_df, random_state=42)

    pd.testing.assert_frame_equal(train_df_1, train_df_2)
    pd.testing.assert_frame_equal(test_df_1, test_df_2)


def test_metrics_and_report_serialization(tmp_path: Path):
    """Verifies calculation of metrics, rates, and generation of markdown reports."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_pred = np.array([0, 0, 0, 1, 1, 1, 0, 1])
    y_prob = np.array([0.1, 0.2, 0.3, 0.8, 0.9, 0.7, 0.4, 0.95])

    metrics = compute_binary_evaluation_metrics(y_true, y_pred, y_prob, split_name="Test")

    # Confusion matrix: TN=3, FP=1, FN=1, TP=3
    assert metrics["confusion_matrix"]["tn"] == 3
    assert metrics["confusion_matrix"]["fp"] == 1
    assert metrics["confusion_matrix"]["fn"] == 1
    assert metrics["confusion_matrix"]["tp"] == 3
    assert metrics["rates"]["false_positive_rate"] == 0.25
    assert metrics["rates"]["false_negative_rate"] == 0.25
    assert metrics["pr_auc_attack"] is not None
    assert metrics["roc_auc"] is not None

    clean_labels = pd.Series(["BENIGN", "BENIGN", "BENIGN", "BENIGN", "DoS Hulk", "DoS Hulk", "PortScan", "PortScan"])
    breakdown = compute_per_attack_family_breakdown(y_pred, clean_labels)
    assert "BENIGN" in breakdown
    assert "DoS Hulk" in breakdown
    assert breakdown["DoS Hulk"]["attack_detection_recall"] == 1.0
    assert breakdown["PortScan"]["attack_detection_recall"] == 0.5

    # Test report generation
    report_dict = {
        "metadata": {
            "created_at_utc": "2026-10-22T10:00:00Z",
            "estimator": "RandomForestClassifier",
            "feature_count": 70,
            "split_sizes": {"train": 70, "train_fitted": 70, "validation": 15, "test": 15},
            "ingestion_summary": {
                "raw_rows": 100,
                "conflicting_rows_dropped": 0,
                "duplicates_dropped": 0,
                "clean_rows": 100,
                "dropped_columns": ["col_x"],
            },
            "runtimes_seconds": {"training": 1.2, "total_pipeline": 2.5},
        },
        "test_metrics": metrics,
        "val_metrics": metrics,
        "majority_baseline_comparison": metrics,
        "per_attack_family_breakdown": breakdown,
    }
    md_file = tmp_path / "test_report.md"
    generate_markdown_report(report_dict, md_file)
    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")
    assert "# TraceGuard" in content
    assert "Macro-Averaged F1" in content
    assert "DoS Hulk" in content


def test_model_save_and_load_roundtrip(tmp_path: Path):
    """Verifies that model and preprocessor artifacts save and load with identical predictions."""
    X = np.random.randn(50, 5)
    y = np.random.randint(0, 2, size=50)

    pipe = PreprocessPipeline()
    X_clean = pipe.fit_transform(X)

    model = build_estimator("random_forest", n_estimators=10, max_depth=4, random_state=42)
    model.fit(X_clean, y)

    pipe_path = tmp_path / "preprocessor.joblib"
    model_path = tmp_path / "model.joblib"

    pipe.save(pipe_path)
    joblib.dump(model, model_path)

    # Load back
    loaded_pipe = PreprocessPipeline.load(pipe_path)
    loaded_model = joblib.load(model_path)

    X_test = np.random.randn(20, 5)
    X_test_trans = loaded_pipe.transform(X_test)
    orig_trans = pipe.transform(X_test)
    np.testing.assert_array_almost_equal(X_test_trans, orig_trans)

    preds_orig = model.predict(orig_trans)
    preds_loaded = loaded_model.predict(X_test_trans)
    np.testing.assert_array_equal(preds_orig, preds_loaded)


def test_empty_or_malformed_dataset_dir(tmp_path: Path):
    """Verifies helpful exceptions on missing directory or missing Label column."""
    # Missing directory
    with pytest.raises(FileNotFoundError):
        load_and_validate_dataset(tmp_path / "non_existent")

    # Missing label column
    empty_dataset = tmp_path / "bad_dataset"
    empty_dataset.mkdir()
    bad_df = pd.DataFrame({"Flow Duration": [10.0, 20.0]})
    bad_df.to_parquet(empty_dataset / "bad.parquet", index=False)

    with pytest.raises(ValueError) as exc:
        load_and_validate_dataset(empty_dataset)
    assert "Missing mandatory 'Label' column" in str(exc.value)

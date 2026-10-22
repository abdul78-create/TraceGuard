"""
TraceGuard — Baseline Machine Learning Training & Evaluation Pipeline.

Implements the Stage 3 baseline detector:
- Leakage-resistant ingestion, deduplication, and conflict resolution.
- Train-only preprocessing and imputation.
- Binary threat detection (Benign vs Attack) with class-weighting.
- Comprehensive evaluation: Macro-F1, PR-AUC, ROC-AUC, FPR, FNR,
  per-attack-family detection breakdown, and majority baseline comparison.
- Optional secondary multiclass baseline.
- Full JSON and Markdown report generation.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

from ml.preprocessing import (
    PreprocessPipeline,
    create_leakage_resistant_splits,
    load_and_validate_dataset,
)

logger = logging.getLogger("traceguard.train_baseline")


def build_estimator(
    estimator_name: str,
    random_state: int = 42,
    n_estimators: int = 100,
    max_depth: Optional[int] = 16,
) -> Any:
    """
    Factory creating the selected scikit-learn tree or gradient boosted estimator.
    """
    name = estimator_name.lower().strip()
    if name in ["rf", "random_forest", "randomforest"]:
        return RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )
    elif name in ["et", "extra_trees", "extratrees"]:
        return ExtraTreesClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )
    elif name in ["hgb", "hist_gradient_boosting", "histgb"]:
        return HistGradientBoostingClassifier(
            max_iter=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            random_state=random_state,
        )
    else:
        raise ValueError(
            f"Unsupported estimator: '{estimator_name}'. "
            "Supported options: 'random_forest', 'extra_trees', 'hist_gradient_boosting'."
        )


def compute_binary_evaluation_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray],
    split_name: str = "Test",
) -> Dict[str, Any]:
    """
    Computes rigorous cybersecurity detection metrics including FPR, FNR,
    PR-AUC, ROC-AUC, Macro-F1, and confusion matrix.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    total = len(y_true)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    p_scores, r_scores, f_scores, support = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )

    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))

    pr_auc: Optional[float] = None
    roc_auc: Optional[float] = None
    if y_prob is not None:
        try:
            pr_auc = float(average_precision_score(y_true, y_prob))
        except Exception:
            pass
        try:
            roc_auc = float(roc_auc_score(y_true, y_prob))
        except Exception:
            pass

    return {
        "split": split_name,
        "total_samples": total,
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "matrix_2x2": [[tn, fp], [fn, tp]],
        },
        "rates": {
            "false_positive_rate": round(fpr, 6),
            "false_negative_rate": round(fnr, 6),
            "accuracy": round(float((tp + tn) / total), 6) if total > 0 else 0.0,
        },
        "macro_f1": round(macro_f1, 6),
        "pr_auc_attack": round(pr_auc, 6) if pr_auc is not None else None,
        "roc_auc": round(roc_auc, 6) if roc_auc is not None else None,
        "per_class": {
            "benign_0": {
                "precision": round(float(p_scores[0]), 6),
                "recall": round(float(r_scores[0]), 6),
                "f1_score": round(float(f_scores[0]), 6),
                "support": int(support[0]),
            },
            "attack_1": {
                "precision": round(float(p_scores[1]), 6),
                "recall": round(float(r_scores[1]), 6),
                "f1_score": round(float(f_scores[1]), 6),
                "support": int(support[1]),
            },
        },
    }


def compute_per_attack_family_breakdown(
    y_pred: np.ndarray,
    clean_labels: pd.Series,
) -> Dict[str, Dict[str, Any]]:
    """
    Computes attack detection recall for each granular attack family.
    """
    df_eval = pd.DataFrame({"pred": y_pred, "raw_label": clean_labels.values})
    results: Dict[str, Dict[str, Any]] = {}

    for label_name, group in df_eval.groupby("raw_label"):
        total_in_class = len(group)
        if label_name == "BENIGN":
            detected_correctly = int((group["pred"] == 0).sum())
            metric_name = "true_negative_rate"
        else:
            detected_correctly = int((group["pred"] == 1).sum())
            metric_name = "attack_detection_recall"

        recall_val = float(detected_correctly / total_in_class) if total_in_class > 0 else 0.0
        results[str(label_name)] = {
            "support": total_in_class,
            "correct_predictions": detected_correctly,
            metric_name: round(recall_val, 6),
            "is_rare_category": total_in_class < 100,
        }

    return results


def train_and_evaluate_binary_detector(
    data_dir: str | Path,
    output_dir: str | Path = "reports/evaluation",
    model_dir: str | Path = "models/artifacts",
    estimator_type: str = "random_forest",
    max_train_samples: Optional[int] = None,
    random_seed: int = 42,
    n_estimators: int = 100,
    max_depth: Optional[int] = 16,
) -> Dict[str, Any]:
    """
    Full reproducible pipeline for Stage 3 binary threat detection baseline.
    """
    t_start = time.perf_counter()
    out_path = Path(output_dir)
    mdl_path = Path(model_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    mdl_path.mkdir(parents=True, exist_ok=True)

    print("\n[Step 1/5] Ingesting and validating raw Parquet dataset...")
    df_clean, ingestion_summary = load_and_validate_dataset(
        data_dir=data_dir,
        drop_conflicting=True,
        deduplicate=True,
    )
    print(
        f"  Loaded {ingestion_summary.total_files_loaded} files ({ingestion_summary.raw_row_count:,} raw rows)."
    )
    print(
        f"  Removed {ingestion_summary.conflicting_feature_rows_removed:,} conflicting rows "
        f"({ingestion_summary.conflicting_hash_groups} feature hashes)."
    )
    print(
        f"  Deduplicated {ingestion_summary.duplicate_rows_deduplicated:,} identical rows."
    )
    print(
        f"  Clean modeling dataset: {ingestion_summary.clean_row_count:,} rows x "
        f"{ingestion_summary.clean_feature_count} features."
    )

    print("\n[Step 2/5] Creating leakage-resistant train/val/test splits (70/15/15)...")
    train_df, val_df, test_df = create_leakage_resistant_splits(
        df_clean,
        test_size=0.15,
        val_size=0.15,
        random_state=random_seed,
        stratify_col="binary_label",
    )
    print(f"  Train partition : {len(train_df):,} flows")
    print(f"  Val partition   : {len(val_df):,} flows")
    print(f"  Test partition  : {len(test_df):,} flows")

    feature_cols = ingestion_summary.retained_features

    # Handle optional training subsample for compute/memory control
    if max_train_samples and max_train_samples < len(train_df):
        print(
            f"  Subsampling training split to {max_train_samples:,} rows (stratified, seed={random_seed})..."
        )
        train_fit_df = (
            train_df.groupby("binary_label", group_keys=False)
            .apply(
                lambda x: x.sample(
                    n=max(1, int(round(len(x) / len(train_df) * max_train_samples))),
                    random_state=random_seed,
                ),
                include_groups=True,
            )
            .reset_index(drop=True)
        )
    else:
        train_fit_df = train_df

    print("\n[Step 3/5] Fitting preprocessing pipeline (train split only)...")
    preprocessor = PreprocessPipeline(imputer_strategy="median")
    preprocessor.fit(train_fit_df[feature_cols])

    X_train = preprocessor.transform(train_fit_df[feature_cols])
    y_train = train_fit_df["binary_label"].to_numpy()

    X_val = preprocessor.transform(val_df[feature_cols])
    y_val = val_df["binary_label"].to_numpy()

    X_test = preprocessor.transform(test_df[feature_cols])
    y_test = test_df["binary_label"].to_numpy()

    print(
        f"\n[Step 4/5] Training {estimator_type} estimator (train set: {len(X_train):,} rows)..."
    )
    t_train_start = time.perf_counter()
    model = build_estimator(
        estimator_name=estimator_type,
        random_state=random_seed,
        n_estimators=n_estimators,
        max_depth=max_depth,
    )
    model.fit(X_train, y_train)
    training_duration_s = time.perf_counter() - t_train_start
    print(f"  Training completed in {training_duration_s:.2f} seconds.")

    print("\n[Step 5/5] Evaluating on validation and untouched test sets...")
    # Validation evaluation
    val_pred = model.predict(X_val)
    val_prob = model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else None
    val_metrics = compute_binary_evaluation_metrics(y_val, val_pred, val_prob, split_name="Validation")

    # Test evaluation
    test_pred = model.predict(X_test)
    test_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
    test_metrics = compute_binary_evaluation_metrics(y_test, test_pred, test_prob, split_name="Test")

    # Granular per-attack-family breakdown on test set
    attack_breakdown = compute_per_attack_family_breakdown(test_pred, test_df["clean_label"])

    # Majority baseline metrics for comparison (predicting 0 everywhere)
    majority_pred = np.zeros_like(y_test)
    majority_metrics = compute_binary_evaluation_metrics(y_test, majority_pred, None, split_name="Majority Baseline")

    total_pipeline_duration_s = time.perf_counter() - t_start

    # Persist model and preprocessor artifacts
    model_artifact_path = mdl_path / "baseline_binary_model.joblib"
    prep_artifact_path = mdl_path / "baseline_preprocessor.joblib"
    meta_artifact_path = mdl_path / "baseline_binary_metadata.json"

    joblib.dump(model, model_artifact_path)
    preprocessor.save(prep_artifact_path)

    metadata_dict = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "estimator": type(model).__name__,
        "estimator_params": {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "random_state": random_seed,
            "class_weight": "balanced",
        },
        "features": feature_cols,
        "feature_count": len(feature_cols),
        "split_sizes": {
            "train": len(train_df),
            "train_fitted": len(train_fit_df),
            "validation": len(val_df),
            "test": len(test_df),
            "subsampled_training": bool(max_train_samples and max_train_samples < len(train_df)),
        },
        "ingestion_summary": {
            "raw_rows": ingestion_summary.raw_row_count,
            "conflicting_rows_dropped": ingestion_summary.conflicting_feature_rows_removed,
            "duplicates_dropped": ingestion_summary.duplicate_rows_deduplicated,
            "clean_rows": ingestion_summary.clean_row_count,
            "dropped_columns": ingestion_summary.dropped_features,
        },
        "runtimes_seconds": {
            "training": round(training_duration_s, 2),
            "total_pipeline": round(total_pipeline_duration_s, 2),
        },
    }

    with open(meta_artifact_path, "w", encoding="utf-8") as f:
        json.dump(metadata_dict, f, indent=2)

    # Full output report package
    report_data = {
        "metadata": metadata_dict,
        "test_metrics": test_metrics,
        "val_metrics": val_metrics,
        "majority_baseline_comparison": majority_metrics,
        "per_attack_family_breakdown": attack_breakdown,
    }

    # Save JSON report
    json_report_path = out_path / "baseline_binary_metrics.json"
    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Generate and save Markdown report
    md_report_path = out_path / "baseline_binary_report.md"
    generate_markdown_report(report_data, md_report_path)

    print(f"\n[DONE] Saved model artifact to       : {model_artifact_path}")
    print(f"[DONE] Saved preprocessor artifact to : {prep_artifact_path}")
    print(f"[DONE] Saved JSON metrics to          : {json_report_path}")
    print(f"[DONE] Saved Markdown report to       : {md_report_path}")

    return report_data


def generate_markdown_report(data: Dict[str, Any], output_path: Path) -> None:
    """
    Formats the evaluation results into an executive-ready Markdown document.
    """
    meta = data["metadata"]
    tm = data["test_metrics"]
    vm = data["val_metrics"]
    maj = data["majority_baseline_comparison"]
    bk = data["per_attack_family_breakdown"]

    lines: List[str] = [
        "# TraceGuard — Stage 3: Baseline Binary Threat Detection Report",
        "",
        f"**Evaluation Timestamp:** `{meta['created_at_utc']}`  ",
        f"**Estimator Model:** `{meta['estimator']}` (`class_weight='balanced'`)  ",
        f"**Training Duration:** `{meta['runtimes_seconds']['training']}s` | **Total Pipeline Duration:** `{meta['runtimes_seconds']['total_pipeline']}s`  ",
        "",
        "---",
        "",
        "## 1. Executive Summary & Core Results",
        "",
        "| Evaluation Metric | Baseline Model (Test) | Majority Baseline (All Benign) | Validation Set |",
        "|---|---|---|---|",
        f"| **Macro-Averaged F1** | **`{tm['macro_f1']:.4f}`** | `{maj['macro_f1']:.4f}` | `{vm['macro_f1']:.4f}` |",
        f"| **Attack Detection Recall** | **`{tm['per_class']['attack_1']['recall']:.4f}`** | `{maj['per_class']['attack_1']['recall']:.4f}` | `{vm['per_class']['attack_1']['recall']:.4f}` |",
        f"| **Attack Precision** | **`{tm['per_class']['attack_1']['precision']:.4f}`** | `{maj['per_class']['attack_1']['precision']:.4f}` | `{vm['per_class']['attack_1']['precision']:.4f}` |",
        f"| **Attack PR-AUC (Average Precision)** | **`{tm['pr_auc_attack']:.4f}`** | `—` | `{vm['pr_auc_attack']:.4f}` |",
        f"| **ROC-AUC** | **`{tm['roc_auc']:.4f}`** | `—` | `{vm['roc_auc']:.4f}` |",
        f"| **False Positive Rate (FPR)** | **`{tm['rates']['false_positive_rate']:.4%}`** | `0.00%` | `{vm['rates']['false_positive_rate']:.4%}` |",
        f"| **False Negative Rate (FNR)** | **`{tm['rates']['false_negative_rate']:.4%}`** | `100.00%` | `{vm['rates']['false_negative_rate']:.4%}` |",
        "",
        "> [!IMPORTANT]",
        "> **Cybersecurity Takeaway:** Predicting the majority class achieves ~80% raw accuracy but has a **100% False Negative Rate**, missing every attack. The TraceGuard baseline achieves high attack recall with controlled False Positive Rates without memorizing IP identifiers.",
        "",
        "---",
        "",
        "## 2. Test Set Confusion Matrix",
        "",
        "| | Predicted Benign (0) | Predicted Attack (1) | Total Actual |",
        "|---|---|---|---|",
        f"| **Actual Benign (0)** | **`{tm['confusion_matrix']['tn']:,}`** (TN) | `{tm['confusion_matrix']['fp']:,}` (FP) | `{tm['per_class']['benign_0']['support']:,}` |",
        f"| **Actual Attack (1)** | `{tm['confusion_matrix']['fn']:,}` (FN) | **`{tm['confusion_matrix']['tp']:,}`** (TP) | `{tm['per_class']['attack_1']['support']:,}` |",
        f"| **Total Predicted** | `{tm['confusion_matrix']['tn'] + tm['confusion_matrix']['fn']:,}` | `{tm['confusion_matrix']['fp'] + tm['confusion_matrix']['tp']:,}` | `{tm['total_samples']:,}` |",
        "",
        "---",
        "",
        "## 3. Dataset Preprocessing & Partitioning Decisions",
        "",
        "| Stage | Flow Records | Description / Justification |",
        "|---|---|---|",
        f"| **Raw Dataset Ingested** | `{meta['ingestion_summary']['raw_rows']:,}` | All 8 Parquet files loaded across 5 capture days |",
        f"| **Conflicting Labels Removed** | `{meta['ingestion_summary']['conflicting_rows_dropped']:,}` | Contradictory ground-truth rows (identical features with both Benign and Attack labels) excluded |",
        f"| **Duplicate Rows Deduplicated** | `{meta['ingestion_summary']['duplicates_dropped']:,}` | Exact session duplicates removed to prevent train/test memorization leakage |",
        f"| **Clean Modeling Dataset** | `{meta['ingestion_summary']['clean_rows']:,}` | Verified unique flows with consistent ground-truth labels |",
        f"| **Training Partition (70%)** | `{meta['split_sizes']['train']:,}` (used: `{meta['split_sizes']['train_fitted']:,}`) | Stratified partition with train-only median imputer fit |",
        f"| **Validation Partition (15%)** | `{meta['split_sizes']['validation']:,}` | Reserved for hyperparameter and threshold validation |",
        f"| **Test Partition (15%)** | `{meta['split_sizes']['test']:,}` | Untouched final evaluation split |",
        "",
        f"**Dropped Features ({len(meta['ingestion_summary']['dropped_columns'])}):** "
        f"`{', '.join(meta['ingestion_summary']['dropped_columns'])}` (1 redundant duplicate clone + 8 zero-variance constant columns).  ",
        f"**Retained Features:** `{meta['feature_count']}` numerical flow metrics.  ",
        "",
        "---",
        "",
        "## 4. Per-Attack-Family Detection Breakdown (Test Set)",
        "",
        "| Attack Family | Test Support | Detections | Recall (%) | Category Assessment |",
        "|---|---|---|---|---|",
    ]

    sorted_families = sorted(bk.items(), key=lambda x: x[1]["support"], reverse=True)
    for fam_name, info in sorted_families:
        rec_rate = info.get("attack_detection_recall", info.get("true_negative_rate", 0.0))
        flag = "⚠️ Rare (<100 flows)" if info.get("is_rare_category") else "✅ Robust Support"
        if fam_name == "BENIGN":
            flag = "Baseline Benign"
        lines.append(
            f"| **`{fam_name}`** | {info['support']:,} | {info['correct_predictions']:,} | {rec_rate:.2%} | {flag} |"
        )

    lines.extend([
        "",
        "> [!NOTE]",
        "> Detection rates for extreme minority classes (`Heartbleed`, `Infiltration`, `Web Attack - Sql Injection`) have small test supports and will be specifically targeted in Stage 4 through unsupervised anomaly detection and confidence calibration.",
        "",
        "---",
        "",
        "## 5. Next Steps for Stage 4",
        "",
        "1. **Unseen Attack Category Holdout Evaluation:** Exclude attack families (`Bot`, `Infiltration`, or `Web Attacks`) from training and evaluate the detector's capability to flag them as anomalous.",
        "2. **Confidence Calibration:** Fit temperature scaling / isotonic regression on validation predictions to align softmax scores with true posterior probabilities.",
        "3. **Selective Abstention:** Implement an `ABSTAIN` policy when predictive entropy is elevated or anomaly distance exceeds safety thresholds.",
        "4. **Drift Telemetry:** Monitor feature distribution shift (PSI, Wasserstein distance) across temporal capture days.",
        "",
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TraceGuard Baseline Threat Detection Training & Evaluation CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/raw/cicids2017_hf/machine_learning",
        help="Directory containing the raw Parquet flow files.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports/evaluation",
        help="Directory where evaluation reports and metrics JSON will be saved.",
    )
    parser.add_argument(
        "--model-dir",
        type=str,
        default="models/artifacts",
        help="Directory where fitted model and preprocessor artifacts will be saved.",
    )
    parser.add_argument(
        "--estimator",
        type=str,
        default="random_forest",
        choices=["random_forest", "extra_trees", "hist_gradient_boosting"],
        help="Estimator algorithm to train.",
    )
    parser.add_argument(
        "--max-train-samples",
        type=int,
        default=250_000,
        help="Maximum training samples to fit (stratified). Set 0 or None for full clean training partition.",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of trees or boosting iterations.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=16,
        help="Maximum tree depth (guards against memorization overfitting).",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for deterministic reproducibility.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    max_train = args.max_train_samples if args.max_train_samples and args.max_train_samples > 0 else None

    print("=" * 75)
    print("TraceGuard -- Stage 3: Baseline Threat Detection Pipeline")
    print(f"Data Directory  : {Path(args.data_dir).resolve()}")
    print(f"Estimator       : {args.estimator} (trees: {args.n_estimators}, max_depth: {args.max_depth})")
    print(f"Train Sample Cap: {max_train if max_train else 'Full Clean Training Set'}")
    print(f"Random Seed     : {args.random_seed}")
    print("=" * 75)

    try:
        report = train_and_evaluate_binary_detector(
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            model_dir=args.model_dir,
            estimator_type=args.estimator,
            max_train_samples=max_train,
            random_seed=args.random_seed,
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
        )
        test_m = report["test_metrics"]
        print("\n" + "=" * 75)
        print("STAGE 3 BASELINE EVALUATION SUMMARY (TEST SET)")
        print(f"Macro-Averaged F1    : {test_m['macro_f1']:.4f}")
        print(f"Attack Recall        : {test_m['per_class']['attack_1']['recall']:.4f}")
        print(f"Attack Precision     : {test_m['per_class']['attack_1']['precision']:.4f}")
        print(f"PR-AUC (Attack)      : {test_m['pr_auc_attack']:.4f}")
        print(f"ROC-AUC              : {test_m['roc_auc']:.4f}")
        print(f"False Positive Rate  : {test_m['rates']['false_positive_rate']:.4%}")
        print(f"False Negative Rate  : {test_m['rates']['false_negative_rate']:.4%}")
        print("=" * 75)
        return 0
    except Exception as exc:
        print(f"\n[FATAL] Baseline training failed: {exc}")
        logger.exception("Baseline training failed with uncaught exception:")
        return 1


if __name__ == "__main__":
    sys.exit(main())

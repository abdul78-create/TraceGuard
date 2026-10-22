"""
TraceGuard — Leakage-Resistant Data Preprocessing and Validation Pipeline.

Provides memory-conscious ingestion, label canonicalization, duplicate/conflict
resolution, and train-only median imputation for network flow datasets.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split

from ml.schemas import TrafficClass

logger = logging.getLogger("traceguard.preprocessing")

# Known redundant and constant columns in CIC-IDS2017
DUPLICATE_FEATURE_NAMES = ["Fwd Header Length_duplicated_0"]

CONSTANT_FEATURE_NAMES = [
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]

# Standard label mapping for raw CIC-IDS2017 strings
# Maps normalized raw string to: (canonical TrafficClass, binary target 0=benign 1=attack)
LABEL_MAPPING: Dict[str, Tuple[TrafficClass, int]] = {
    "BENIGN": (TrafficClass.BENIGN, 0),
    "DoS Hulk": (TrafficClass.DOS, 1),
    "PortScan": (TrafficClass.PORT_SCAN, 1),
    "DDoS": (TrafficClass.DDOS, 1),
    "DoS GoldenEye": (TrafficClass.DOS, 1),
    "FTP-Patator": (TrafficClass.BRUTE_FORCE, 1),
    "SSH-Patator": (TrafficClass.BRUTE_FORCE, 1),
    "DoS slowloris": (TrafficClass.DOS, 1),
    "DoS Slowhttptest": (TrafficClass.DOS, 1),
    "Bot": (TrafficClass.BOTNET, 1),
    "Web Attack - Brute Force": (TrafficClass.WEB_ATTACK, 1),
    "Web Attack - XSS": (TrafficClass.WEB_ATTACK, 1),
    "Infiltration": (TrafficClass.INFILTRATION, 1),
    "Web Attack - Sql Injection": (TrafficClass.WEB_ATTACK, 1),
    "Heartbleed": (TrafficClass.DOS, 1),
}


def normalize_raw_label_string(raw: str) -> str:
    """
    Cleans label string encoding artifacts:
    - Replaces Unicode replacement char \ufffd or \xa0 with a hyphen for Web Attacks.
    - Normalizes double whitespace to single hyphen.
    - Strips whitespace.
    """
    s = str(raw).strip()
    # Normalize Web Attack replacement characters and multi-spaces
    if "Web Attack" in s:
        s = s.replace("\ufffd", "-").replace("\xa0", "-")
        # Handle "Web Attack  Brute Force" -> "Web Attack - Brute Force"
        while "  " in s:
            s = s.replace("  ", " - ")
        if " - " not in s and "Web Attack" in s and not s.endswith("Attack"):
            s = s.replace("Web Attack", "Web Attack -")
        # Collapse any multiple hyphens or spaces
        while "--" in s:
            s = s.replace("--", "-")
        parts = [p.strip() for p in s.split("-")]
        s = " - ".join(parts)
    return s


def parse_label(raw: str) -> Tuple[str, TrafficClass, int]:
    """
    Parses and validates a raw label.
    Returns: (normalized_string, canonical_TrafficClass, binary_int)
    Raises ValueError on unknown or malformed labels.
    """
    normalized = normalize_raw_label_string(raw)
    if normalized not in LABEL_MAPPING:
        raise ValueError(
            f"Unknown or malformed network flow label: '{raw}' (normalized: '{normalized}'). "
            f"Allowed labels: {sorted(LABEL_MAPPING.keys())}"
        )
    traffic_cls, binary_target = LABEL_MAPPING[normalized]
    return normalized, traffic_cls, binary_target


@dataclass
class DatasetIngestionSummary:
    total_files_loaded: int
    raw_row_count: int
    raw_feature_count: int
    conflicting_feature_rows_removed: int
    conflicting_hash_groups: int
    conflicting_label_counts: Dict[str, int]
    duplicate_rows_deduplicated: int
    clean_row_count: int
    clean_feature_count: int
    retained_features: List[str]
    dropped_features: List[str]
    binary_class_counts: Dict[str, int]
    multiclass_counts: Dict[str, int]


class PreprocessPipeline(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible preprocessor for network flow features.
    - Converts +inf, -inf to NaN.
    - Imputes missing values strictly using training set medians.
    - Preserves column ordering.
    """

    def __init__(self, imputer_strategy: str = "median"):
        self.imputer_strategy = imputer_strategy
        self.imputer: Optional[SimpleImputer] = None
        self.feature_names_: List[str] = []
        self.feature_medians_: Dict[str, float] = {}

    def fit(self, X: np.ndarray | pd.DataFrame, y: Optional[Any] = None) -> PreprocessPipeline:
        if isinstance(X, pd.DataFrame):
            self.feature_names_ = list(X.columns)
            X_arr = X.to_numpy(dtype=np.float64, copy=True)
        else:
            X_arr = np.array(X, dtype=np.float64, copy=True)
            self.feature_names_ = [f"feature_{i}" for i in range(X_arr.shape[1])]

        # Replace non-finite values (+inf, -inf) with NaN
        X_arr[np.isinf(X_arr)] = np.nan

        self.imputer = SimpleImputer(strategy=self.imputer_strategy)
        self.imputer.fit(X_arr)

        if hasattr(self.imputer, "statistics_"):
            for fname, val in zip(self.feature_names_, self.imputer.statistics_):
                self.feature_medians_[fname] = float(val)

        return self

    def transform(self, X: np.ndarray | pd.DataFrame) -> np.ndarray:
        if self.imputer is None:
            raise RuntimeError("PreprocessPipeline must be fitted before calling transform.")

        if isinstance(X, pd.DataFrame):
            X_arr = X[self.feature_names_].to_numpy(dtype=np.float64, copy=True)
        else:
            X_arr = np.array(X, dtype=np.float64, copy=True)

        # Replace non-finite values (+inf, -inf) with NaN
        X_arr[np.isinf(X_arr)] = np.nan

        return self.imputer.transform(X_arr)

    def save(self, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        logger.info(f"Saved PreprocessPipeline to {path}")

    @classmethod
    def load(cls, input_path: str | Path) -> PreprocessPipeline:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Pipeline artifact not found: '{path}'")
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not a {cls.__name__}: {type(obj)}")
        return obj


def load_and_validate_dataset(
    data_dir: str | Path,
    drop_conflicting: bool = True,
    deduplicate: bool = True,
) -> Tuple[pd.DataFrame, DatasetIngestionSummary]:
    """
    Loads all Parquet files in data_dir, normalizes labels, validates schemas,
    resolves conflicting duplicate feature rows, and returns a clean DataFrame
    alongside a full ingestion audit summary.
    """
    path = Path(data_dir)
    parquet_files = sorted([
        f for f in path.glob("*.parquet")
        if f.is_file() and not f.name.startswith(".")
    ])

    if not parquet_files:
        # Check subdirectories
        parquet_files = sorted([
            f for f in path.rglob("*.parquet")
            if f.is_file() and not f.name.startswith(".")
        ])

    if not parquet_files:
        raise FileNotFoundError(f"No Parquet files found in dataset path: '{path}'")

    dfs: List[pd.DataFrame] = []
    raw_total_rows = 0

    for f in parquet_files:
        df_chunk = pd.read_parquet(f)
        raw_total_rows += len(df_chunk)

        # Clean column whitespace
        df_chunk.columns = [c.strip() for c in df_chunk.columns]

        # Extract capture day from filename as metadata
        filename_lower = f.name.lower()
        capture_day = "Unknown"
        for day in ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]:
            if day in filename_lower:
                capture_day = day.capitalize()
                break

        # Record metadata columns (strictly excluded from model features)
        df_chunk["meta_source_file"] = f.name
        df_chunk["meta_capture_day"] = capture_day

        dfs.append(df_chunk)

    df_full = pd.concat(dfs, ignore_index=True)

    # Validate Label column presence
    if "Label" not in df_full.columns:
        raise ValueError("Missing mandatory 'Label' column across ingested data.")

    # Drop serialized duplicate columns
    dropped_cols = []
    for dup_col in DUPLICATE_FEATURE_NAMES:
        if dup_col in df_full.columns:
            df_full.drop(columns=[dup_col], inplace=True)
            dropped_cols.append(dup_col)

    # Drop constant zero-variance columns
    for const_col in CONSTANT_FEATURE_NAMES:
        if const_col in df_full.columns:
            df_full.drop(columns=[const_col], inplace=True)
            dropped_cols.append(const_col)

    # Parse and normalize labels
    norm_labels: List[str] = []
    canonical_classes: List[str] = []
    binary_targets: List[int] = []

    for raw_val in df_full["Label"]:
        n_str, c_cls, b_t = parse_label(raw_val)
        norm_labels.append(n_str)
        canonical_classes.append(c_cls.value)
        binary_targets.append(b_t)

    df_full["clean_label"] = norm_labels
    df_full["canonical_class"] = canonical_classes
    df_full["binary_label"] = binary_targets

    # Identify feature columns
    metadata_cols = {"Label", "clean_label", "canonical_class", "binary_label", "meta_source_file", "meta_capture_day"}
    feature_cols = [c for c in df_full.columns if c not in metadata_cols]

    # Compute 64-bit feature hash for duplicate and conflict resolution
    feature_hashes = pd.util.hash_pandas_object(df_full[feature_cols], index=False)
    df_full["f_hash"] = feature_hashes

    # Inspect conflicting labels
    dup_feature_mask = df_full["f_hash"].duplicated(keep=False)
    dup_df = df_full[dup_feature_mask]

    # Group by feature hash and check unique labels
    conflict_hashes = dup_df.groupby("f_hash")["clean_label"].nunique().loc[lambda x: x > 1].index
    conflicting_rows_mask = df_full["f_hash"].isin(conflict_hashes)
    conflicting_row_count = int(conflicting_rows_mask.sum())
    conflicting_hash_count = len(conflict_hashes)

    conflicting_counts: Dict[str, int] = {}
    if conflicting_row_count > 0:
        conflicting_counts = df_full.loc[conflicting_rows_mask, "clean_label"].value_counts().to_dict()

    # Apply duplicate/conflict resolution
    if drop_conflicting and conflicting_row_count > 0:
        logger.info(
            f"Excluding {conflicting_row_count:,} conflicting rows across {conflicting_hash_count} feature hashes."
        )
        df_clean = df_full[~conflicting_rows_mask].copy()
    else:
        df_clean = df_full.copy()

    # Deduplicate exact feature records
    rows_before_dedup = len(df_clean)
    if deduplicate:
        df_clean.drop_duplicates(subset=["f_hash"], keep="first", inplace=True)
    dedup_count = rows_before_dedup - len(df_clean)

    summary = DatasetIngestionSummary(
        total_files_loaded=len(parquet_files),
        raw_row_count=raw_total_rows,
        raw_feature_count=len(feature_cols) + len(dropped_cols),
        conflicting_feature_rows_removed=conflicting_row_count,
        conflicting_hash_groups=conflicting_hash_count,
        conflicting_label_counts=conflicting_counts,
        duplicate_rows_deduplicated=dedup_count,
        clean_row_count=len(df_clean),
        clean_feature_count=len(feature_cols),
        retained_features=sorted(feature_cols),
        dropped_features=sorted(dropped_cols),
        binary_class_counts=df_clean["binary_label"].value_counts().to_dict(),
        multiclass_counts=df_clean["canonical_class"].value_counts().to_dict(),
    )

    return df_clean, summary


def create_leakage_resistant_splits(
    df: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
    stratify_col: str = "binary_label",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Splits DataFrame into train (1 - test_size - val_size), val (val_size), and test (test_size).
    Guarantees that no identical feature hash crosses the train/val/test boundary.
    """
    total_val_test = test_size + val_size
    relative_val_size = val_size / total_val_test

    # First split: Train vs (Val + Test)
    train_df, val_test_df = train_test_split(
        df,
        test_size=total_val_test,
        random_state=random_state,
        stratify=df[stratify_col],
    )

    # Second split: Val vs Test
    val_df, test_df = train_test_split(
        val_test_df,
        test_size=1.0 - relative_val_size,
        random_state=random_state,
        stratify=val_test_df[stratify_col],
    )

    # Verify complete partition disjointness by feature hash
    train_hashes = set(train_df["f_hash"])
    val_hashes = set(val_df["f_hash"])
    test_hashes = set(test_df["f_hash"])

    leakage_train_val = train_hashes.intersection(val_hashes)
    leakage_train_test = train_hashes.intersection(test_hashes)
    leakage_val_test = val_hashes.intersection(test_hashes)

    if leakage_train_val or leakage_train_test or leakage_val_test:
        raise RuntimeError(
            f"Leakage detected across splits! "
            f"Train/Val overlap: {len(leakage_train_val)}, "
            f"Train/Test overlap: {len(leakage_train_test)}, "
            f"Val/Test overlap: {len(leakage_val_test)}"
        )

    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def create_heldout_splits(
    df: pd.DataFrame,
    heldout_label: str = "Bot",
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
    stratify_col: str = "binary_label",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Splits dataset with an entire attack family held out for zero-day evaluation (Protocol B).
    Requirements:
    - Exclude all rows with clean_label == heldout_label from train and val.
    - Retain 100% of heldout_label rows in heldout_test_df.
    - Split remaining known data into train, val, and test partitions.
    - Assert zero feature-hash leakage across ANY partition pair.

    Returns:
        (train_df, val_df, test_df, heldout_test_df)
    """
    heldout_mask = df["clean_label"] == heldout_label
    if not heldout_mask.any():
        raise ValueError(
            f"Held-out attack label '{heldout_label}' not found in dataset. "
            f"Available classes: {sorted(df['clean_label'].unique())}"
        )

    heldout_test_df = df[heldout_mask].copy().reset_index(drop=True)
    known_df = df[~heldout_mask].copy().reset_index(drop=True)

    train_df, val_df, test_df = create_leakage_resistant_splits(
        known_df,
        test_size=test_size,
        val_size=val_size,
        random_state=random_state,
        stratify_col=stratify_col,
    )

    # Verify complete partition disjointness including heldout set
    train_hashes = set(train_df["f_hash"])
    val_hashes = set(val_df["f_hash"])
    test_hashes = set(test_df["f_hash"])
    heldout_hashes = set(heldout_test_df["f_hash"])

    leakage_heldout_train = train_hashes.intersection(heldout_hashes)
    leakage_heldout_val = val_hashes.intersection(heldout_hashes)
    leakage_heldout_test = test_hashes.intersection(heldout_hashes)

    if leakage_heldout_train or leakage_heldout_val or leakage_heldout_test:
        raise RuntimeError(
            f"Held-out leakage detected! "
            f"Train/Heldout overlap: {len(leakage_heldout_train)}, "
            f"Val/Heldout overlap: {len(leakage_heldout_val)}, "
            f"Test/Heldout overlap: {len(leakage_heldout_test)}"
        )

    return train_df, val_df, test_df, heldout_test_df


def create_stage4_disjoint_partitions(
    df: pd.DataFrame,
    heldout_label: str = "Bot",
    train_frac: float = 0.60,
    val_cal_frac: float = 0.10,
    val_thresh_frac: float = 0.15,
    test_frac: float = 0.15,
    random_state: int = 42,
    stratify_col: str = "binary_label",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Creates a rigorous 5-way disjoint partition for Stage 4:
    1. heldout_test_df: 100% of held-out attack family (e.g. 'Bot').
    2. train_df: 60% of known data (used strictly for model fitting).
    3. val_cal_df: 10% of known data (used strictly for Platt calibration fitting).
    4. val_thresh_df: 15% of known data (used strictly for anomaly threshold & triage selection).
    5. test_df: 15% of known data (locked, untouched test partition for final evaluation).

    Guarantees:
    - Zero rows of heldout_label in train, val_cal, val_thresh, or test.
    - Zero feature hash overlap across ANY pair among the 5 partitions.

    Returns:
        (train_df, val_cal_df, val_thresh_df, test_df, heldout_test_df)
    """
    total_frac = train_frac + val_cal_frac + val_thresh_frac + test_frac
    if not np.isclose(total_frac, 1.0):
        raise ValueError(f"Partition fractions must sum to 1.0; got {total_frac:.4f}")

    heldout_mask = df["clean_label"] == heldout_label
    if not heldout_mask.any():
        raise ValueError(
            f"Held-out attack label '{heldout_label}' not found in dataset. "
            f"Available classes: {sorted(df['clean_label'].unique())}"
        )

    heldout_test_df = df[heldout_mask].copy().reset_index(drop=True)
    known_df = df[~heldout_mask].copy().reset_index(drop=True)

    # Split 1: Train vs Eval Pool
    eval_frac = val_cal_frac + val_thresh_frac + test_frac
    train_df, eval_pool_df = train_test_split(
        known_df,
        test_size=eval_frac,
        random_state=random_state,
        stratify=known_df[stratify_col],
    )

    # Split 2: Test vs Val Pool (within Eval Pool)
    test_rel_frac = test_frac / eval_frac
    val_pool_df, test_df = train_test_split(
        eval_pool_df,
        test_size=test_rel_frac,
        random_state=random_state,
        stratify=eval_pool_df[stratify_col],
    )

    # Split 3: Val-Cal vs Val-Thresh (within Val Pool)
    val_thresh_rel_frac = val_thresh_frac / (val_cal_frac + val_thresh_frac)
    val_cal_df, val_thresh_df = train_test_split(
        val_pool_df,
        test_size=val_thresh_rel_frac,
        random_state=random_state,
        stratify=val_pool_df[stratify_col],
    )

    # Verify complete pairwise disjointness across all 5 partitions
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
            n1, n2 = names[i], names[j]
            overlap = hashes[n1].intersection(hashes[n2])
            if overlap:
                raise RuntimeError(
                    f"Leakage detected between {n1} and {n2}! Overlapping hashes: {len(overlap)}"
                )

    return (
        train_df.reset_index(drop=True),
        val_cal_df.reset_index(drop=True),
        val_thresh_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
        heldout_test_df.reset_index(drop=True),
    )

"""
TraceGuard — Reproducible Dataset Audit and Inspection Tool.

Audits network intrusion detection datasets (e.g. CIC-IDS2017, UNSW-NB15)
for schema consistency, data quality anomalies, class imbalance, identifier
leakage, and temporal structure without modifying or deleting raw data.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger("traceguard.data_audit")


# Known identifiers that pose leakage risks if used in model training
LEAKAGE_COLUMNS = {
    "flow id": "Unique flow identifier (trivial memorization artifact)",
    "source ip": "Host IP address (causes model to memorize attack machine identity rather than flow behavior)",
    "src ip": "Host IP address (causes model to memorize attack machine identity rather than flow behavior)",
    "destination ip": "Host IP address (causes model to memorize victim machine identity rather than flow behavior)",
    "dst ip": "Host IP address (causes model to memorize victim machine identity rather than flow behavior)",
    "source port": "Ephemeral source port (randomly assigned by OS, risks spurious correlation)",
    "src port": "Ephemeral source port (randomly assigned by OS, risks spurious correlation)",
    "timestamp": "Exact wall-clock timestamp (leaks temporal sequence into non-temporal models)",
    "time": "Exact wall-clock timestamp (leaks temporal sequence into non-temporal models)",
}

COMMON_ENCODINGS = ["utf-8", "latin1", "cp1252", "iso-8859-1"]

CANDIDATE_LABEL_COLUMNS = ["label", "attack", "attack_cat", "class", "traffic_class"]


@dataclass
class ColumnAudit:
    name: str
    original_header: str
    has_whitespace: bool
    dtype: str
    missing_count: int
    missing_pct: float
    infinite_count: int
    infinite_pct: float


@dataclass
class FileAuditReport:
    filename: str
    filepath: str
    file_size_bytes: int
    encoding_used: str
    row_count: int
    column_count: int
    duplicate_row_count: int
    duplicate_row_pct: float
    raw_headers: List[str]
    stripped_headers: List[str]
    duplicate_column_headers: List[str]
    columns_with_whitespace: List[str]
    columns: Dict[str, ColumnAudit]
    label_column: Optional[str]
    class_distribution: Dict[str, int]
    minority_classes: Dict[str, float]
    detected_leakage_columns: Dict[str, str]
    temporal_coverage: Dict[str, Any]


@dataclass
class DatasetAuditSummary:
    timestamp_utc: str
    data_dir: str
    total_files: int
    total_rows: int
    total_size_bytes: int
    schema_consistent: bool
    schema_discrepancies: List[str]
    shared_columns: List[str]
    detected_leakage_columns: Dict[str, str]
    overall_class_distribution: Dict[str, int]
    overall_minority_proportions: Dict[str, float]
    total_missing_values: int
    total_infinite_values: int
    total_duplicate_rows: int
    capture_days_detected: List[str]
    recommendations: List[str]
    files: List[FileAuditReport] = field(default_factory=list)


def discover_dataset_files(dataset_dir: Path) -> List[Path]:
    """
    Discovers all CSV and Parquet files within the dataset directory (including top-level and 1-level subdirectories).
    Sorts deterministically.
    """
    if not dataset_dir.exists():
        raise FileNotFoundError(
            f"Dataset directory not found: '{dataset_dir}'. "
            "Please ensure the target directory exists and contains CSV or Parquet files."
        )

    valid_exts = {".csv", ".parquet"}
    data_files: List[Path] = []
    for item in sorted(dataset_dir.iterdir()):
        if item.is_file() and (item.suffix.lower() in valid_exts or item.name.lower().endswith(".csv.parquet")):
            data_files.append(item)
        elif item.is_dir():
            for sub_item in sorted(item.iterdir()):
                if sub_item.is_file() and (sub_item.suffix.lower() in valid_exts or sub_item.name.lower().endswith(".csv.parquet")):
                    data_files.append(sub_item)

    return sorted(data_files)


# Backwards compatibility alias
discover_csv_files = discover_dataset_files


def read_raw_header_line(file_path: Path) -> Tuple[List[str], str]:
    """
    Reads the first line of the CSV file to inspect raw column headers and determine encoding.
    """
    for enc in COMMON_ENCODINGS:
        try:
            with open(file_path, "r", encoding=enc, errors="strict") as f:
                reader = csv.reader(f)
                header = next(reader)
                return header, enc
        except (UnicodeDecodeError, StopIteration):
            continue

    # Fallback with replacement
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        return header, "utf-8-replaced"


def inspect_file_headers(file_path: Path) -> Tuple[List[str], str]:
    """
    Inspects raw column headers and format/encoding for CSV or Parquet files.
    """
    is_parquet = file_path.suffix.lower() == ".parquet" or file_path.name.lower().endswith(".parquet")
    if is_parquet:
        try:
            import pyarrow.parquet as pq
            pf = pq.ParquetFile(file_path)
            return list(pf.schema.names), "parquet-binary"
        except ImportError:
            raise RuntimeError(
                "pyarrow is required to read Parquet files. "
                "Please run: pip install pyarrow"
            )
    return read_raw_header_line(file_path)


def find_label_column(headers: List[str]) -> Optional[str]:
    """
    Finds the candidate label column name based on common intrusion detection naming conventions.
    """
    for h in headers:
        cleaned = h.strip().lower()
        if cleaned in CANDIDATE_LABEL_COLUMNS:
            return h
    # Secondary check: ends with 'label' or 'class'
    for h in headers:
        cleaned = h.strip().lower()
        if cleaned.endswith("label") or cleaned.endswith("class"):
            return h
    return None


def audit_file(
    file_path: Path,
    chunksize: int = 50_000,
    max_rows: Optional[int] = None,
) -> FileAuditReport:
    """
    Performs a streaming, memory-safe audit of a single CSV or Parquet file.
    """
    raw_headers, encoding = inspect_file_headers(file_path)
    file_size = file_path.stat().st_size
    is_parquet = file_path.suffix.lower() == ".parquet" or file_path.name.lower().endswith(".parquet")

    # Check for whitespace in headers
    columns_with_whitespace = [h for h in raw_headers if h != h.strip()]
    stripped_headers = [h.strip() for h in raw_headers]

    # Check for duplicate headers in the raw schema or serialized duplicates (e.g., _duplicated_0)
    header_counts = Counter(stripped_headers)
    duplicate_column_headers = [h for h, count in header_counts.items() if count > 1]
    for h in stripped_headers:
        if "_duplicated_" in h and h not in duplicate_column_headers:
            duplicate_column_headers.append(h)

    # Detect leakage columns
    detected_leakage: Dict[str, str] = {}
    for raw_h, stripped_h in zip(raw_headers, stripped_headers):
        lower_h = stripped_h.lower()
        if lower_h in LEAKAGE_COLUMNS:
            detected_leakage[stripped_h] = LEAKAGE_COLUMNS[lower_h]

    # Detect label column
    label_col_raw = find_label_column(raw_headers)
    label_col_stripped = label_col_raw.strip() if label_col_raw else None

    # Temporal detection from filename
    temporal_coverage: Dict[str, Any] = {
        "filename_day": None,
        "has_timestamp_column": any("time" in h.lower() for h in stripped_headers),
        "min_timestamp": None,
        "max_timestamp": None,
    }
    filename_lower = file_path.name.lower()
    for day in ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]:
        if day in filename_lower:
            temporal_coverage["filename_day"] = day.capitalize()
            break

    # Initialize streaming metric counters
    total_rows = 0
    missing_by_col: Counter[str] = Counter()
    infinite_by_col: Counter[str] = Counter()
    class_distribution: Counter[str] = Counter()
    seen_row_hashes: Set[int] = set()
    duplicate_rows_count = 0
    dtypes_map: Dict[str, str] = {}
    timestamps_sample: List[str] = []

    try:
        if is_parquet:
            import pyarrow.parquet as pq
            pf = pq.ParquetFile(file_path)
            # Stream in record batches for memory safety
            chunk_iterator = (batch.to_pandas() for batch in pf.iter_batches(batch_size=chunksize))
        else:
            chunk_iterator = pd.read_csv(
                file_path,
                chunksize=chunksize,
                encoding=encoding,
                low_memory=False,
                na_values=["", "NA", "N/A", "null", "NaN"],
                keep_default_na=True,
            )

        for chunk in chunk_iterator:
            if max_rows and total_rows >= max_rows:
                break

            current_chunk = chunk
            if max_rows and (total_rows + len(current_chunk) > max_rows):
                current_chunk = current_chunk.iloc[: max_rows - total_rows]

            chunk_len = len(current_chunk)
            total_rows += chunk_len

            # Standardize chunk column names (strip whitespace) for uniform metrics
            clean_cols = [c.strip() for c in current_chunk.columns]
            current_chunk.columns = clean_cols

            # Record dtypes from first chunk
            if not dtypes_map:
                for c in current_chunk.columns:
                    dtypes_map[c] = str(current_chunk[c].dtype)

            # Check missing values
            for c in current_chunk.columns:
                n_miss = int(current_chunk[c].isna().sum())
                if n_miss > 0:
                    missing_by_col[c] += n_miss

                # Check infinite values for numeric columns
                if pd.api.types.is_numeric_dtype(current_chunk[c]):
                    values = current_chunk[c].to_numpy()
                    n_inf = int(np.isinf(values).sum())
                    if n_inf > 0:
                        infinite_by_col[c] += n_inf

            # Record label counts
            if label_col_stripped and label_col_stripped in current_chunk.columns:
                labels_series = current_chunk[label_col_stripped].dropna().astype(str).str.strip()
                for lbl, cnt in labels_series.value_counts().items():
                    class_distribution[str(lbl)] += int(cnt)

            # Record timestamps sample if time column present
            timestamp_col = next((c for c in current_chunk.columns if "time" in c.lower()), None)
            if timestamp_col and len(timestamps_sample) < 1000:
                sample_vals = current_chunk[timestamp_col].dropna().astype(str).tolist()
                timestamps_sample.extend(sample_vals[: 1000 - len(timestamps_sample)])

            # Memory-safe hash-based duplicate row check
            row_hashes = pd.util.hash_pandas_object(current_chunk, index=False).to_numpy()
            for h in row_hashes:
                int_h = int(h)
                if int_h in seen_row_hashes:
                    duplicate_rows_count += 1
                else:
                    seen_row_hashes.add(int_h)

    except Exception as exc:
        logger.warning(f"Error processing {file_path.name}: {exc}")
        if total_rows == 0:
            raise RuntimeError(f"Failed to read file '{file_path.name}': {exc}") from exc

    # Parse timestamps if collected
    if timestamps_sample:
        try:
            parsed_times = pd.to_datetime(timestamps_sample, errors="coerce").dropna()
            if not parsed_times.empty:
                temporal_coverage["min_timestamp"] = str(parsed_times.min())
                temporal_coverage["max_timestamp"] = str(parsed_times.max())
        except Exception:
            pass

    # Build ColumnAudit map
    columns_audit: Dict[str, ColumnAudit] = {}
    for raw_h, stripped_h in zip(raw_headers, stripped_headers):
        m_count = missing_by_col.get(stripped_h, 0)
        inf_count = infinite_by_col.get(stripped_h, 0)
        columns_audit[stripped_h] = ColumnAudit(
            name=stripped_h,
            original_header=raw_h,
            has_whitespace=(raw_h != stripped_h),
            dtype=dtypes_map.get(stripped_h, "unknown"),
            missing_count=m_count,
            missing_pct=round((m_count / total_rows * 100.0), 4) if total_rows > 0 else 0.0,
            infinite_count=inf_count,
            infinite_pct=round((inf_count / total_rows * 100.0), 4) if total_rows > 0 else 0.0,
        )

    # Calculate minority-class proportions
    minority_classes: Dict[str, float] = {}
    if total_rows > 0 and class_distribution:
        for cls_name, cnt in class_distribution.items():
            pct = round((cnt / total_rows) * 100.0, 4)
            minority_classes[cls_name] = pct

    dup_pct = round((duplicate_rows_count / total_rows * 100.0), 4) if total_rows > 0 else 0.0

    return FileAuditReport(
        filename=file_path.name,
        filepath=str(file_path.resolve()),
        file_size_bytes=file_size,
        encoding_used=encoding,
        row_count=total_rows,
        column_count=len(raw_headers),
        duplicate_row_count=duplicate_rows_count,
        duplicate_row_pct=dup_pct,
        raw_headers=raw_headers,
        stripped_headers=stripped_headers,
        duplicate_column_headers=duplicate_column_headers,
        columns_with_whitespace=columns_with_whitespace,
        columns=columns_audit,
        label_column=label_col_stripped,
        class_distribution=dict(class_distribution),
        minority_classes=minority_classes,
        detected_leakage_columns=detected_leakage,
        temporal_coverage=temporal_coverage,
    )


# Backwards compatibility alias
audit_csv_file = audit_file


def audit_dataset(
    dataset_dir: str | Path,
    chunksize: int = 50_000,
    max_rows_per_file: Optional[int] = None,
) -> DatasetAuditSummary:
    """
    Audits a complete directory of network flow CSV or Parquet files.
    """
    path = Path(dataset_dir)
    data_files = discover_dataset_files(path)

    if not data_files:
        raise ValueError(
            f"No CSV or Parquet files found in '{path}'. "
            "Please download the dataset (e.g. CIC-IDS2017 MachineLearningCSV.zip or Hugging Face Parquet mirror) "
            f"and place the extracted files into '{path}'."
        )

    file_reports: List[FileAuditReport] = []
    overall_classes: Counter[str] = Counter()
    total_missing = 0
    total_infinite = 0
    total_duplicates = 0
    total_rows = 0
    total_bytes = 0
    all_leakage: Dict[str, str] = {}
    capture_days: Set[str] = set()

    for file_path in data_files:
        report = audit_file(file_path, chunksize=chunksize, max_rows=max_rows_per_file)
        file_reports.append(report)

        total_rows += report.row_count
        total_bytes += report.file_size_bytes
        total_duplicates += report.duplicate_row_count

        for cls_name, count in report.class_distribution.items():
            overall_classes[cls_name] += count

        for col_aud in report.columns.values():
            total_missing += col_aud.missing_count
            total_infinite += col_aud.infinite_count

        all_leakage.update(report.detected_leakage_columns)

        if report.temporal_coverage.get("filename_day"):
            capture_days.add(report.temporal_coverage["filename_day"])

    # Schema consistency across files
    schema_discrepancies: List[str] = []
    first_file_headers = file_reports[0].stripped_headers
    shared_columns = set(first_file_headers)

    for r in file_reports[1:]:
        shared_columns = shared_columns.intersection(set(r.stripped_headers))
        if r.stripped_headers != first_file_headers:
            diff_missing = set(first_file_headers) - set(r.stripped_headers)
            diff_extra = set(r.stripped_headers) - set(first_file_headers)
            msg = f"{r.filename} header mismatch against {file_reports[0].filename}."
            if diff_missing:
                msg += f" Missing: {sorted(diff_missing)}."
            if diff_extra:
                msg += f" Extra: {sorted(diff_extra)}."
            schema_discrepancies.append(msg)

    schema_consistent = len(schema_discrepancies) == 0

    # Overall minority proportions
    overall_minority: Dict[str, float] = {}
    if total_rows > 0:
        for cls_name, cnt in overall_classes.items():
            overall_minority[cls_name] = round((cnt / total_rows) * 100.0, 4)

    # Preprocessing recommendations based on audit findings
    recommendations: List[str] = []
    if total_infinite > 0:
        recommendations.append(
            f"Found {total_infinite:,} infinite numeric values (e.g. in rate features like Flow Bytes/s). "
            "Stage 3 preprocessor must clip to domain maxima or impute before model fitting."
        )
    if total_missing > 0:
        recommendations.append(
            f"Found {total_missing:,} missing values. Stage 3 preprocessor must apply median imputation "
            "or missing indicator encoding fit strictly on training splits."
        )
    if total_duplicates > 0:
        recommendations.append(
            f"Found {total_duplicates:,} duplicate flow records ({round(total_duplicates/total_rows*100, 2)}% of data). "
            "Must be documented and evaluated for deduplication to prevent cross-split leakage."
        )
    if all_leakage:
        recommendations.append(
            f"Detected identifier leakage columns ({', '.join(sorted(all_leakage.keys()))}). "
            "All host identifiers must be excluded from feature matrices to prevent identity memorization."
        )
    any_whitespace = any(len(r.columns_with_whitespace) > 0 for r in file_reports)
    if any_whitespace:
        recommendations.append(
            "Column headers contain leading/trailing whitespace. Stage 3 loader must call "
            "`col.strip()` uniformly."
        )
    if capture_days:
        recommendations.append(
            f"Detected capture-day structure ({', '.join(sorted(capture_days))}). Chronological "
            "train/val/test splitting should be utilized to simulate temporal drift."
        )

    # Check for replacement characters or encoding anomalies in labels
    any_replacement_labels = any(
        "\\ufffd" in repr(lbl) or "\ufffd" in lbl for lbl in overall_classes.keys()
    )
    if any_replacement_labels:
        recommendations.append(
            "Detected replacement characters or encoding artifacts in label strings (e.g. Web Attack labels). "
            "Stage 3 preprocessor must canonicalize these labels into standard TrafficClass enum members."
        )

    return DatasetAuditSummary(
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        data_dir=str(path.resolve()),
        total_files=len(file_reports),
        total_rows=total_rows,
        total_size_bytes=total_bytes,
        schema_consistent=schema_consistent,
        schema_discrepancies=schema_discrepancies,
        shared_columns=sorted(shared_columns),
        detected_leakage_columns=all_leakage,
        overall_class_distribution=dict(overall_classes),
        overall_minority_proportions=overall_minority,
        total_missing_values=total_missing,
        total_infinite_values=total_infinite,
        total_duplicate_rows=total_duplicates,
        capture_days_detected=sorted(capture_days),
        recommendations=recommendations,
        files=file_reports,
    )


def export_json_report(summary: DatasetAuditSummary, output_path: Path) -> None:
    """
    Exports a clean, structured JSON audit report.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(asdict(summary), f, indent=2)


def export_markdown_report(summary: DatasetAuditSummary, output_path: Path) -> None:
    """
    Exports a comprehensive GitHub-flavored Markdown audit report.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    size_mb = summary.total_size_bytes / (1024 * 1024)
    lines: List[str] = [
        "# TraceGuard — Dataset Quality & Schema Audit Report",
        "",
        f"**Audit Execution Timestamp:** `{summary.timestamp_utc}`  ",
        f"**Dataset Directory:** `{summary.data_dir}`  ",
        f"**Total Files Audited (CSV / Parquet):** {summary.total_files}  ",
        f"**Total Flow Records:** {summary.total_rows:,}  ",
        f"**Total Disk Footprint:** {size_mb:.2f} MB  ",
        f"**Schema Consistency:** {'✅ CONSISTENT ACROSS ALL FILES' if summary.schema_consistent else '⚠️ INCONSISTENCIES DETECTED'}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary & Health Check",
        "",
        "| Metric | Result | Risk Assessment |",
        "|---|---|---|",
        f"| **Total Files** | `{summary.total_files}` | Expected 8 files for full CIC-IDS2017 |",
        f"| **Total Rows** | `{summary.total_rows:,}` | ~2.83M expected across 5 capture days |",
        f"| **Missing Values (NaN/null)** | `{summary.total_missing_values:,}` | {'⚠️ Needs imputation' if summary.total_missing_values > 0 else '✅ Clean'} |",
        f"| **Infinite Values (inf/-inf)** | `{summary.total_infinite_values:,}` | {'⚠️ Division-by-zero rates present' if summary.total_infinite_values > 0 else '✅ Clean'} |",
        f"| **Duplicate Rows** | `{summary.total_duplicate_rows:,}` ({round(summary.total_duplicate_rows/max(1, summary.total_rows)*100, 2)}%) | {'⚠️ Session overlap detected' if summary.total_duplicate_rows > 0 else '✅ No duplicates'} |",
        f"| **Leakage Columns Identified** | `{len(summary.detected_leakage_columns)}` | {'⚠️ Must exclude from feature matrix' if summary.detected_leakage_columns else '✅ No leakage identifiers'} |",
        f"| **Capture Days Detected** | `{', '.join(summary.capture_days_detected) or 'None'}` | {'✅ Supports chronological splitting' if summary.capture_days_detected else '⚠️ No day metadata in filenames'} |",
        "",
        "---",
        "",
        "## 2. Overall Class Distribution & Imbalance",
        "",
        "| Traffic Class | Absolute Count | Proportion (%) | Imbalance Characterization |",
        "|---|---|---|---|",
    ]

    # Sort classes by count descending
    sorted_classes = sorted(summary.overall_class_distribution.items(), key=lambda x: x[1], reverse=True)
    for cls_name, count in sorted_classes:
        pct = summary.overall_minority_proportions.get(cls_name, 0.0)
        imbalance_desc = "Majority Class" if pct > 50 else ("Moderate" if pct > 5 else ("Severe Minority" if pct > 0.1 else "Extreme Minority (<0.1%)"))
        lines.append(f"| **`{cls_name}`** | {count:,} | {pct:.4f}% | {imbalance_desc} |")

    lines.extend([
        "",
        "> [!NOTE]",
        "> Extreme minority classes (e.g. Infiltration, Heartbleed, SQL Injection) require evaluation via **PR-AUC** and **per-class recall**, as standard overall accuracy will mask total misclassification.",
        "",
        "---",
        "",
        "## 3. Potential Identifier & Target Leakage",
        "",
        "The following columns were detected in the raw files and must be **excluded** from model training to prevent the model from memorizing specific host identities:",
        "",
        "| Detected Column | Reason for Exclusion / Leakage Risk |",
        "|---|---|",
    ])

    if summary.detected_leakage_columns:
        for col_name, reason in sorted(summary.detected_leakage_columns.items()):
            lines.append(f"| **`{col_name}`** | {reason} |")
    else:
        lines.append("| *None detected* | No known identifier columns found in headers |")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Per-File Audit Breakdown",
        "",
        "| File Name | Rows | Size (MB) | Duplicates | Missing | Infinite | Capture Day |",
        "|---|---|---|---|---|---|---|",
    ])

    for f_rep in summary.files:
        f_mb = f_rep.file_size_bytes / (1024 * 1024)
        n_miss = sum(c.missing_count for c in f_rep.columns.values())
        n_inf = sum(c.infinite_count for c in f_rep.columns.values())
        day = f_rep.temporal_coverage.get("filename_day") or "—"
        lines.append(
            f"| `{f_rep.filename}` | {f_rep.row_count:,} | {f_mb:.2f} | {f_rep.duplicate_row_count:,} | {n_miss:,} | {n_inf:,} | {day} |"
        )

    if summary.schema_discrepancies:
        lines.extend([
            "",
            "### Schema Discrepancies Detected",
            "",
            "The following column mismatches were detected across files:",
            "",
        ])
        for disc in summary.schema_discrepancies:
            lines.append(f"- ⚠️ {disc}")

    lines.extend([
        "",
        "---",
        "",
        "## 5. Preprocessing & Stage 3 Recommendations",
        "",
    ])

    for i, rec in enumerate(summary.recommendations, 1):
        lines.append(f"{i}. {rec}")

    lines.append("")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TraceGuard Dataset Quality & Schema Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data/raw/cicids2017",
        help="Path to directory containing dataset CSV files to audit.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports/audit",
        help="Directory where JSON and Markdown reports will be written.",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Custom filename/path for JSON report (defaults to <output-dir>/audit_report.json).",
    )
    parser.add_argument(
        "--markdown-out",
        type=str,
        default=None,
        help="Custom filename/path for Markdown report (defaults to <output-dir>/audit_report.md).",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=50_000,
        help="Number of rows per chunk for streaming large CSV files safely.",
    )
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=None,
        help="Optional row limit per file (useful for fast smoke test audits).",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)

    print("=" * 70)
    print("TraceGuard -- Network Flow Dataset Auditor")
    print(f"Target Directory : {data_dir.resolve()}")
    print(f"Output Directory : {output_dir.resolve()}")
    print("=" * 70)

    # Validate directory existence with actionable instructions
    if not data_dir.exists():
        print(f"\n[ERROR] Dataset directory does not exist: '{data_dir}'")
        print("\nAction Required:")
        print("1. Download 'MachineLearningCSV.zip' from the official CIC-IDS2017 page:")
        print("   https://www.unb.ca/cic/datasets/ids-2017.html")
        print(f"2. Extract the CSV files into: '{data_dir.resolve()}'")
        print("3. Re-run this audit command:\n")
        print(f"   .venv\\Scripts\\python -m ml.data_audit --data-dir {args.data_dir}\n")
        return 1

    try:
        print("\nScanning for CSV and Parquet files...")
        summary = audit_dataset(
            dataset_dir=data_dir,
            chunksize=args.chunksize,
            max_rows_per_file=args.max_rows_per_file,
        )
    except ValueError as val_err:
        print(f"\n[ERROR] {val_err}")
        print("\nAction Required:")
        print(f"Ensure that at least one .csv or .parquet file is present in '{data_dir.resolve()}'.")
        return 1
    except Exception as exc:
        print(f"\n[FATAL] Failed to audit dataset: {exc}")
        return 1

    json_path = Path(args.json_out) if args.json_out else output_dir / "audit_report.json"
    md_path = Path(args.markdown_out) if args.markdown_out else output_dir / "audit_report.md"

    print(f"\nExporting machine-readable audit: {json_path}")
    export_json_report(summary, json_path)

    print(f"Exporting human-readable report:  {md_path}")
    export_markdown_report(summary, md_path)

    print("\n" + "=" * 70)
    print("AUDIT COMPLETE")
    print(f"Total Files Audited : {summary.total_files}")
    print(f"Total Flow Records  : {summary.total_rows:,}")
    print(f"Missing Values      : {summary.total_missing_values:,}")
    print(f"Infinite Values     : {summary.total_infinite_values:,}")
    print(f"Duplicate Rows      : {summary.total_duplicate_rows:,}")
    print(f"Schema Consistent   : {'YES' if summary.schema_consistent else 'NO (see report)'}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

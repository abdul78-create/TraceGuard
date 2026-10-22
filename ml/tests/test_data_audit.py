"""
TraceGuard — Automated Tests for Dataset Audit and Quality Inspection Tool.

All tests utilize small, deterministic in-memory/temporary fixtures created
at test execution time. No fabricated production datasets or external downloads.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml.data_audit import (
    audit_file,
    audit_csv_file,
    audit_dataset,
    discover_csv_files,
    discover_dataset_files,
    export_json_report,
    export_markdown_report,
)


@pytest.fixture
def clean_synthetic_df() -> pd.DataFrame:
    """Fixture providing a well-formed minimal synthetic flow DataFrame."""
    return pd.DataFrame({
        "Flow Duration": [100.0, 200.0, 300.0, 400.0, 500.0],
        "Total Fwd Packets": [10, 20, 30, 40, 50],
        "Total Backward Packets": [5, 10, 15, 20, 25],
        "Flow Bytes/s": [1000.0, 2000.0, 1500.0, 3000.0, 500.0],
        "Flow Packets/s": [150.0, 150.0, 150.0, 150.0, 150.0],
        "Label": ["BENIGN", "BENIGN", "BENIGN", "DOS", "INFILTRATION"],
    })


def test_missing_dataset_directory(tmp_path: Path):
    """Auditor must fail with clear FileNotFoundError when directory does not exist."""
    non_existent = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError) as exc_info:
        discover_csv_files(non_existent)
    assert "Dataset directory not found" in str(exc_info.value)


def test_empty_dataset_directory(tmp_path: Path):
    """Auditor must fail with clear ValueError when directory exists but has no CSV or Parquet files."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    with pytest.raises(ValueError) as exc_info:
        audit_dataset(empty_dir)
    assert "No CSV or Parquet files found in" in str(exc_info.value)
    assert "MachineLearningCSV.zip" in str(exc_info.value)


def test_missing_or_unexpected_label_column(tmp_path: Path):
    """Auditor must safely handle CSVs lacking a recognizable label column without crashing."""
    csv_file = tmp_path / "unlabeled_traffic.csv"
    df = pd.DataFrame({
        "Flow Duration": [100.0, 200.0],
        "Total Packets": [10, 20],
        "Metric_X": [1.5, 2.5],
    })
    df.to_csv(csv_file, index=False)

    report = audit_csv_file(csv_file)
    assert report.label_column is None
    assert report.class_distribution == {}
    assert report.minority_classes == {}
    assert report.row_count == 2


def test_duplicate_columns_and_inconsistent_schemas(tmp_path: Path):
    """Auditor must detect duplicate column headers within a file and schema differences across files."""
    dataset_dir = tmp_path / "schema_test"
    dataset_dir.mkdir()

    # File 1 with duplicate raw header "Fwd Header Length"
    file1 = dataset_dir / "Monday-WorkingHours.pcap_ISCX.csv"
    with open(file1, "w", encoding="utf-8") as f:
        f.write("Flow Duration,Fwd Header Length,Fwd Header Length,Label\n")
        f.write("100,20,20,BENIGN\n")
        f.write("200,40,40,BENIGN\n")

    # File 2 with missing column compared to File 1
    file2 = dataset_dir / "Tuesday-WorkingHours.pcap_ISCX.csv"
    with open(file2, "w", encoding="utf-8") as f:
        f.write("Flow Duration,Label\n")
        f.write("300,FTP-Patator\n")

    summary = audit_dataset(dataset_dir)

    # File 1 should have duplicate column flagged
    assert "Fwd Header Length" in summary.files[0].duplicate_column_headers

    # Overall dataset should detect inconsistent schema across files
    assert summary.schema_consistent is False
    assert len(summary.schema_discrepancies) > 0
    assert "mismatch against" in summary.schema_discrepancies[0]


def test_missing_and_infinite_values(tmp_path: Path):
    """Auditor must correctly identify and quantify nulls and infinite values without dropping rows."""
    csv_file = tmp_path / "Wednesday-workingHours.pcap_ISCX.csv"
    df = pd.DataFrame({
        "Flow Duration": [100.0, 200.0, 0.0, 400.0],
        "Flow Bytes/s": [1000.0, np.nan, np.inf, -np.inf],
        "Total Fwd Packets": [10, np.nan, 30, 40],
        "Label": ["BENIGN", "BENIGN", "DOS", "DOS"],
    })
    df.to_csv(csv_file, index=False)

    report = audit_csv_file(csv_file)
    assert report.row_count == 4

    bytes_col = report.columns["Flow Bytes/s"]
    assert bytes_col.missing_count == 1
    assert bytes_col.missing_pct == 25.0
    assert bytes_col.infinite_count == 2  # np.inf and -np.inf
    assert bytes_col.infinite_pct == 50.0

    pkts_col = report.columns["Total Fwd Packets"]
    assert pkts_col.missing_count == 1
    assert pkts_col.missing_pct == 25.0
    assert pkts_col.infinite_count == 0


def test_class_distribution_and_minority_proportions(tmp_path: Path, clean_synthetic_df: pd.DataFrame):
    """Auditor must accurately compute class frequencies and minority class proportions."""
    csv_file = tmp_path / "traffic_sample.csv"
    clean_synthetic_df.to_csv(csv_file, index=False)

    report = audit_csv_file(csv_file)
    assert report.class_distribution == {
        "BENIGN": 3,
        "DOS": 1,
        "INFILTRATION": 1,
    }
    assert report.minority_classes["BENIGN"] == 60.0
    assert report.minority_classes["DOS"] == 20.0
    assert report.minority_classes["INFILTRATION"] == 20.0


def test_leakage_columns_detection(tmp_path: Path):
    """Auditor must flag known identity leakage columns like IP and ephemeral ports."""
    csv_file = tmp_path / "leakage_check.csv"
    df = pd.DataFrame({
        "Flow ID": ["flow-1", "flow-2"],
        "Source IP": ["192.168.1.10", "192.168.1.11"],
        "Destination IP": ["10.0.0.1", "10.0.0.2"],
        "Source Port": [54321, 54322],
        "Flow Duration": [150.0, 250.0],
        "Label": ["BENIGN", "DOS"],
    })
    df.to_csv(csv_file, index=False)

    report = audit_csv_file(csv_file)
    leakage_keys = set(report.detected_leakage_columns.keys())
    assert "Flow ID" in leakage_keys
    assert "Source IP" in leakage_keys
    assert "Destination IP" in leakage_keys
    assert "Source Port" in leakage_keys


def test_safe_handling_of_absent_timestamps(tmp_path: Path, clean_synthetic_df: pd.DataFrame):
    """Auditor must handle missing timestamps and absence of day in filenames gracefully."""
    csv_file = tmp_path / "no_temporal_data.csv"
    clean_synthetic_df.to_csv(csv_file, index=False)

    report = audit_csv_file(csv_file)
    assert report.temporal_coverage["filename_day"] is None
    assert report.temporal_coverage["has_timestamp_column"] is False
    assert report.temporal_coverage["min_timestamp"] is None
    assert report.temporal_coverage["max_timestamp"] is None


def test_header_whitespace_handling(tmp_path: Path):
    """Auditor must detect leading/trailing whitespace in column headers and track them."""
    csv_file = tmp_path / "whitespace_headers.csv"
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write(" Flow Duration , Total Fwd Packets,Label \n")
        f.write("100,10,BENIGN\n")
        f.write("200,20,BENIGN\n")

    report = audit_csv_file(csv_file)
    assert " Flow Duration " in report.columns_with_whitespace
    assert "Label " in report.columns_with_whitespace
    assert "Total Fwd Packets" not in report.columns_with_whitespace
    # Cleaned header keys should still be indexed properly
    assert "Flow Duration" in report.columns
    assert report.columns["Flow Duration"].has_whitespace is True
    assert report.label_column == "Label"


def test_report_generation_json_and_markdown(tmp_path: Path, clean_synthetic_df: pd.DataFrame):
    """Auditor must successfully write both machine-readable JSON and human-readable Markdown reports."""
    data_dir = tmp_path / "dataset"
    data_dir.mkdir()
    csv_file = data_dir / "Monday-WorkingHours.pcap_ISCX.csv"
    clean_synthetic_df.to_csv(csv_file, index=False)

    output_dir = tmp_path / "reports"
    output_dir.mkdir()
    json_out = output_dir / "audit_report.json"
    md_out = output_dir / "audit_report.md"

    summary = audit_dataset(data_dir)
    export_json_report(summary, json_out)
    export_markdown_report(summary, md_out)

    assert json_out.exists()
    assert md_out.exists()

    # Validate JSON content
    with open(json_out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_files"] == 1
    assert data["total_rows"] == 5
    assert data["capture_days_detected"] == ["Monday"]
    assert "BENIGN" in data["overall_class_distribution"]

    # Validate Markdown content
    with open(md_out, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "# TraceGuard" in md_text
    assert "Executive Summary & Health Check" in md_text
    assert "Overall Class Distribution & Imbalance" in md_text
    assert "BENIGN" in md_text


def test_parquet_audit_end_to_end(tmp_path: Path, clean_synthetic_df: pd.DataFrame):
    """Auditor must seamlessly stream, inspect, and report on Parquet datasets."""
    data_dir = tmp_path / "parquet_dataset"
    data_dir.mkdir()
    parquet_file = data_dir / "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet"
    clean_synthetic_df.to_parquet(parquet_file, engine="pyarrow", index=False)

    report = audit_file(parquet_file)
    assert report.encoding_used == "parquet-binary"
    assert report.row_count == 5
    assert report.column_count == 6
    assert report.label_column == "Label"
    assert report.class_distribution == {"BENIGN": 3, "DOS": 1, "INFILTRATION": 1}
    assert report.temporal_coverage["filename_day"] == "Friday"

    summary = audit_dataset(data_dir)
    assert summary.total_files == 1
    assert summary.total_rows == 5
    assert summary.capture_days_detected == ["Friday"]


def test_parquet_missing_and_infinite_values(tmp_path: Path):
    """Auditor must detect nulls and infinite values in Parquet files."""
    data_dir = tmp_path / "parquet_inf"
    data_dir.mkdir()
    parquet_file = data_dir / "Wednesday-workingHours.pcap_ISCX.csv.parquet"

    df = pd.DataFrame({
        "Flow Duration": [100.0, 200.0, 0.0, 400.0],
        "Flow Bytes/s": [1000.0, np.nan, np.inf, -np.inf],
        "Label": ["BENIGN", "BENIGN", "DOS", "DOS"],
    })
    df.to_parquet(parquet_file, engine="pyarrow", index=False)

    report = audit_file(parquet_file)
    bytes_col = report.columns["Flow Bytes/s"]
    assert bytes_col.missing_count == 1
    assert bytes_col.infinite_count == 2
    assert bytes_col.infinite_pct == 50.0


def test_parquet_serialized_duplicate_columns(tmp_path: Path):
    """Auditor must detect serialized duplicate column names in Parquet (e.g. _duplicated_0)."""
    data_dir = tmp_path / "parquet_dups"
    data_dir.mkdir()
    parquet_file = data_dir / "dups.parquet"

    df = pd.DataFrame({
        "Fwd Header Length": [20, 40],
        "Fwd Header Length_duplicated_0": [20, 40],
        "Label": ["BENIGN", "BENIGN"],
    })
    df.to_parquet(parquet_file, engine="pyarrow", index=False)

    report = audit_file(parquet_file)
    assert "Fwd Header Length_duplicated_0" in report.duplicate_column_headers


def test_parquet_replacement_characters_in_label(tmp_path: Path):
    """Auditor must detect non-ASCII/replacement characters in labels and issue recommendations."""
    data_dir = tmp_path / "parquet_labels"
    data_dir.mkdir()
    parquet_file = data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet"

    df = pd.DataFrame({
        "Flow Duration": [100.0, 200.0],
        "Label": ["BENIGN", "Web Attack \ufffd Brute Force"],
    })
    df.to_parquet(parquet_file, engine="pyarrow", index=False)

    summary = audit_dataset(data_dir)
    assert any("replacement characters" in rec for rec in summary.recommendations)


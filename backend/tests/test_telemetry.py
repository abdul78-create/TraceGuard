"""
Tests for telemetry, drift, evaluation metrics, and sample flow endpoints in Stage 5.
"""

import json
import unittest
from unittest.mock import patch
import pytest


@pytest.mark.asyncio
async def test_drift_telemetry_stage5(client):
    """Verifies that drift telemetry returns real Stage 4.1 historical covariate shift analysis."""
    response = await client.get("/api/telemetry/drift")
    assert response.status_code == 200
    data = response.json()
    assert data["monitoring_active"] is False  # Honestly reports no live streaming tap
    assert data["historical_analysis_available"] is True
    assert data["baseline_window_size"] == 903802
    assert "Max Packet Length" in data["drifted_features"]
    assert data["psi_summary"] is not None
    assert "Monday" in data["daily_fpr_drift"]
    assert "Continuous real-time drift streaming is currently inactive" in data["offline_disclaimer"]


@pytest.mark.asyncio
async def test_evaluation_metrics_stage5(client):
    """Verifies that evaluation metrics return real Stage 4.1 benchmark results."""
    response = await client.get("/api/telemetry/evaluation")
    assert response.status_code == 200
    data = response.json()
    assert data["evaluation_available"] is True
    assert "CIC-IDS2017" in data["dataset_name"]
    assert abs(data["metrics"]["macro_f1"] - 0.998864) < 1e-4
    assert abs(data["metrics"]["attack_recall"] - 0.99811) < 1e-4
    assert data["unseen_attack_metrics"]["heldout_family"] == "Bot"
    assert data["unseen_attack_metrics"]["supervised_recall"] == 0.0
    assert data["unseen_attack_metrics"]["total_bot_flows"] == 1953
    assert data["calibration_error"] < 0.001
    assert len(data["operating_points"]) == 6
    assert "policy_a_permissive" in data["triage_policies"]
    assert "policy_b_balanced" in data["triage_policies"]
    assert "policy_c_conservative" in data["triage_policies"]


@pytest.mark.asyncio
async def test_telemetry_unconfigured_fallback(client):
    """Verifies safe fallback when evaluation report file is absent."""
    with patch("backend.app.api.routes.telemetry._load_stage4_metrics", return_value={}):
        drift_res = await client.get("/api/telemetry/drift")
        assert drift_res.status_code == 200
        drift_data = drift_res.json()
        assert drift_data["monitoring_active"] is False
        assert drift_data["baseline_window_size"] == 0

        eval_res = await client.get("/api/telemetry/evaluation")
        assert eval_res.status_code == 200
        eval_data = eval_res.json()
        assert eval_data["evaluation_available"] is False


@pytest.mark.asyncio
async def test_get_sample_flows(client):
    """Verifies that /api/model/sample-flows returns valid synthetic demonstration flows."""
    response = await client.get("/api/model/sample-flows")
    assert response.status_code == 200
    flows = response.json()
    assert len(flows) >= 4
    ids = [f["id"] for f in flows]
    assert "sample-benign-web" in ids
    assert "sample-dos-hulk" in ids
    assert "sample-heldout-bot" in ids
    assert "sample-anomalous-outlier" in ids

    # Verify each flow contains record with 69 features
    for f in flows:
        assert "features" in f["record"]
        assert len(f["record"]["features"]) == 69


@pytest.mark.asyncio
async def test_predict_batch_size_limit_rejection(client):
    """Verifies that batches exceeding max limit (500) are rejected with 422."""
    oversized_records = [{"protocol": 6, "flow_duration_ms": 10.0}] * 501
    response = await client.post("/api/model/predict-batch", json={"records": oversized_records})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_telemetry_deep_validation_missing_nested_fields(client):
    """
    Verifies that a partially malformed JSON file missing nested policy fields
    returns a clean unavailable response (HTTP 200 with evaluation_available=False)
    instead of throwing a 500 error or returning invalid metrics.
    """
    # Malformed payload: has top-level sections but missing nested policy fields
    malformed_payload = {
        "protocol_b_heldout_experiment": {
            "supervised_model_known_test": {"macro_f1": 0.99},
            # missing supervised_model_on_heldout_bot, calibration, triage policies
        },
        "protocol_c_temporal_drift_experiment": {
            "psi_summary": {}
        }
    }
    with patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps(malformed_payload))):
        with patch("pathlib.Path.is_file", return_value=True):
            eval_res = await client.get("/api/telemetry/evaluation")
            assert eval_res.status_code == 200
            eval_data = eval_res.json()
            assert eval_data["evaluation_available"] is False
            assert "No verified model evaluation benchmark" in eval_data["message"]

            drift_res = await client.get("/api/telemetry/drift")
            assert drift_res.status_code == 200
            drift_data = drift_res.json()
            assert drift_data["historical_analysis_available"] is False


@pytest.mark.asyncio
async def test_telemetry_deep_validation_non_numeric_values(client):
    """
    Verifies that a JSON file containing non-numeric values for metric fields
    is rejected and produces a clean unavailable state.
    """
    non_numeric_payload = {
        "protocol_b_heldout_experiment": {
            "supervised_model_known_test": {"macro_f1": "NOT_A_NUMBER"},
            "supervised_model_on_heldout_bot": {"total_bot_flows": 1953},
            "calibration_evaluation_untouched_test": {"calibrated_ece": 0.00015},
            "selective_prediction_triage_comparison": {
                "policy_a_permissive": {"heldout_bot_safety_rate": 0.0225},
                "policy_b_balanced": {"heldout_bot_safety_rate": 0.0533},
                "policy_c_conservative": {"heldout_bot_safety_rate": 0.5893},
            }
        },
        "protocol_c_temporal_drift_experiment": {
            "psi_summary": {"stable_count_psi_under_0_1": 67}
        }
    }
    with patch("builtins.open", unittest.mock.mock_open(read_data=json.dumps(non_numeric_payload))):
        with patch("pathlib.Path.is_file", return_value=True):
            eval_res = await client.get("/api/telemetry/evaluation")
            assert eval_res.status_code == 200
            eval_data = eval_res.json()
            assert eval_data["evaluation_available"] is False



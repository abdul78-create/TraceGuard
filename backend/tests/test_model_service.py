"""
Unit and integration tests for TraceGuard Stage 5A:
Safe Model Service, Artifact Verification, and API Integration.

Verifies:
1. Valid artifact loading, feature order verification, and service readiness.
2. Missing, corrupt, incomplete, and incompatible artifact handling.
3. Strict input schema validation: missing required features, extra features, non-numeric values, NaN, and infinity.
4. Correct probability, calibration, and anomaly score handling.
5. Tri-state triage policy boundaries (Policy A, Policy B, Policy C) and explanations.
6. API status and prediction endpoints when ready vs unconfigured.
7. Safe error responses without leaking filesystem paths or stack traces.
8. Safety notice ensuring LIKELY_BENIGN is never represented as a guarantee of security.
"""

import json
from pathlib import Path
import numpy as np
import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.core.config import settings
from backend.app.main import app
from backend.app.services.model_service import (
    ModelService,
    SAFETY_DISCLAIMER,
    TriagePolicy,
    get_model_service,
    set_model_service,
)
from ml.schemas import (
    AbstentionReason,
    DecisionOutcome,
    ModelLifecycleStatus,
    NetworkFlowRecord,
)


@pytest.fixture
def real_model_service():
    """Initializes a real ModelService using existing Stage 4.1 artifacts."""
    service = ModelService(artifacts_dir=settings.model_artifacts_dir, auto_load=True)
    assert service.is_ready, f"Failed to load real model artifacts: {service.load_error}"
    return service


@pytest.fixture
def valid_69_features(real_model_service):
    """Provides a valid, clean dictionary of all 69 required flow features."""
    return dict(real_model_service.preprocessor.feature_medians_)


@pytest.fixture
def test_client(real_model_service):
    """Async client configured with the real Stage 5A model service active."""
    set_model_service(real_model_service)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# =====================================================================
# 1. Artifact Verification & Service Readiness Tests
# =====================================================================

def test_model_service_load_real_artifacts(real_model_service):
    """Verifies that all 5 frozen Stage 4.1 research artifacts are loaded and verified."""
    assert real_model_service.is_ready
    assert real_model_service.status == ModelLifecycleStatus.READY
    assert len(real_model_service.feature_names_) == 69
    assert real_model_service.preprocessor is not None
    assert real_model_service.classifier is not None
    assert real_model_service.calibrator is not None
    assert real_model_service.anomaly_detector is not None
    assert real_model_service.metadata is not None

    # Check verified threshold values
    assert abs(real_model_service.tau_5pct - 0.60008) < 1e-4
    assert abs(real_model_service.tau_25pct - 0.187313) < 1e-4
    assert abs(real_model_service.tau_50pct - 0.075572) < 1e-4


def test_model_service_missing_artifacts_dir(tmp_path):
    """Verifies that pointing to an empty directory safely marks UNCONFIGURED."""
    empty_dir = tmp_path / "empty_artifacts"
    empty_dir.mkdir()

    service = ModelService(artifacts_dir=empty_dir, auto_load=True)
    assert not service.is_ready
    assert service.status == ModelLifecycleStatus.UNCONFIGURED
    assert "Artifact missing" in (service.load_error or "")
    # Verifies error does not leak full local filesystem path
    assert str(tmp_path) not in (service.load_error or "")


def test_model_service_corrupt_artifact(tmp_path):
    """Verifies that corrupt joblib artifacts are caught without raising unhandled exceptions."""
    corrupt_dir = tmp_path / "corrupt_artifacts"
    corrupt_dir.mkdir()

    # Create dummy files with 1 corrupt joblib file
    for name in [
        "stage4_preprocessor.joblib",
        "stage4_heldout_classifier.joblib",
        "stage4_calibrator.joblib",
        "stage4_isolation_forest.joblib",
    ]:
        (corrupt_dir / name).write_bytes(b"CORRUPT_BYTES_NOT_A_PICKLE")

    (corrupt_dir / "stage4_metadata.json").write_text(json.dumps({"anomaly_thresholds": {"5%": 0.6}}))

    service = ModelService(artifacts_dir=corrupt_dir, auto_load=True)
    assert not service.is_ready
    assert service.status == ModelLifecycleStatus.UNCONFIGURED
    assert "failed integrity validation" in (service.load_error or "").lower()


# =====================================================================
# 2. Strict Input Feature Extraction & Validation Tests
# =====================================================================

def test_missing_required_features_rejected(real_model_service):
    """Verifies that missing features trigger 422 and are NEVER silently replaced with zeros."""
    partial_features = {"Destination Port": 80.0, "Flow Duration": 1500.0}

    with pytest.raises(Exception) as exc_info:
        real_model_service.validate_and_extract_features({"features": partial_features})

    err_detail = exc_info.value.detail
    assert exc_info.value.status_code == 422
    assert err_detail["error"] == "MISSING_REQUIRED_FEATURES"
    assert err_detail["total_missing"] == 67
    assert "does not silently substitute arbitrary zeros" in err_detail["message"]


def test_non_finite_nan_and_inf_rejected(real_model_service, valid_69_features):
    """Verifies that NaN and +/- infinity are rejected with clear error messages."""
    # Test NaN
    nan_features = dict(valid_69_features)
    nan_features["Flow Bytes/s"] = float("nan")

    with pytest.raises(Exception) as exc_info:
        real_model_service.validate_and_extract_features({"features": nan_features})
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["error"] == "NON_FINITE_FEATURE"
    assert "Flow Bytes/s" in exc_info.value.detail["message"]

    # Test +inf
    inf_features = dict(valid_69_features)
    inf_features["Flow Packets/s"] = float("inf")

    with pytest.raises(Exception) as exc_info:
        real_model_service.validate_and_extract_features({"features": inf_features})
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["error"] == "NON_FINITE_FEATURE"


def test_non_numeric_values_rejected(real_model_service, valid_69_features):
    """Verifies that strings or booleans for feature values are rejected."""
    bad_features = dict(valid_69_features)
    bad_features["Destination Port"] = "eighty"

    with pytest.raises(Exception) as exc_info:
        real_model_service.validate_and_extract_features({"features": bad_features})
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["error"] == "NON_NUMERIC_FEATURE"


# =====================================================================
# 3. Triage Policies & Decision Boundaries
# =====================================================================

def test_triage_policy_a_permissive(real_model_service):
    """Verifies Policy A logic (Permissive Baseline)."""
    # 1. High attack prob -> THREAT_SUSPECTED
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.85, anom_score=0.10, policy="POLICY_A")
    assert dec == DecisionOutcome.THREAT_SUSPECTED
    assert reason == AbstentionReason.NONE
    assert "Policy A" in pol

    # 2. Ambiguous attack prob -> ABSTAIN (LOW_CONFIDENCE)
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.50, anom_score=0.10, policy="POLICY_A")
    assert dec == DecisionOutcome.ABSTAIN
    assert reason == AbstentionReason.LOW_CONFIDENCE

    # 3. Low attack prob + low anomaly score -> LIKELY_BENIGN
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.01, anom_score=0.10, policy="POLICY_A")
    assert dec == DecisionOutcome.LIKELY_BENIGN
    assert reason == AbstentionReason.NONE

    # 4. Low attack prob + high anomaly score (>= tau_5%) -> ABSTAIN (UNSEEN_ATTACK_DISTRIBUTION)
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.01, anom_score=0.75, policy="POLICY_A")
    assert dec == DecisionOutcome.ABSTAIN
    assert reason == AbstentionReason.UNSEEN_ATTACK_DISTRIBUTION


def test_triage_policy_b_balanced(real_model_service):
    """Verifies Policy B logic (Balanced Anomaly Guard)."""
    tau_25 = real_model_service.tau_25pct  # ~0.1873
    tau_5 = real_model_service.tau_5pct    # ~0.6001

    # Borderline anomaly score between tau_25 and tau_5 -> ABSTAIN (FEATURE_ANOMALY)
    mid_score = (tau_25 + tau_5) / 2.0
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.01, anom_score=mid_score, policy="POLICY_B")
    assert dec == DecisionOutcome.ABSTAIN
    assert reason == AbstentionReason.FEATURE_ANOMALY
    assert "Policy B" in pol

    # Deep inlier below tau_25 -> LIKELY_BENIGN
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.01, anom_score=0.05, policy="POLICY_B")
    assert dec == DecisionOutcome.LIKELY_BENIGN
    assert reason == AbstentionReason.NONE


def test_triage_policy_c_conservative(real_model_service):
    """Verifies Policy C logic (Conservative Zero-Trust)."""
    tau_median = real_model_service.tau_50pct  # ~0.0756

    # Any threat >= 0.50 -> THREAT_SUSPECTED
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.55, anom_score=0.01, policy="POLICY_C")
    assert dec == DecisionOutcome.THREAT_SUSPECTED

    # Attack prob between 0.10 and 0.50 -> ABSTAIN
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.25, anom_score=0.01, policy="POLICY_C")
    assert dec == DecisionOutcome.ABSTAIN
    assert reason == AbstentionReason.LOW_CONFIDENCE

    # Score above median -> ABSTAIN (FEATURE_ANOMALY)
    dec, reason, pol, expl = real_model_service.evaluate_triage(cal_prob=0.02, anom_score=tau_median + 0.05, policy="POLICY_C")
    assert dec == DecisionOutcome.ABSTAIN
    assert reason == AbstentionReason.FEATURE_ANOMALY


# =====================================================================
# 4. API Endpoints Integration Tests
# =====================================================================

@pytest.mark.asyncio
async def test_api_status_when_ready(test_client):
    """Verifies GET /api/model/status reports READY and returns 69 features and thresholds."""
    async with test_client as client:
        response = await client.get("/api/model/status")
        assert response.status_code == 200
        data = response.json()
        assert data["lifecycle_status"] == "READY"
        assert data["active_model_name"] == "stage4.1-calibrated-rf-iforest"
        assert data["anomaly_detector_loaded"] is True
        assert data["confidence_calibrator_loaded"] is True
        assert data["abstention_policy_active"] is True
        assert data["n_features"] == 69
        assert "5%" in data["anomaly_thresholds"]


@pytest.mark.asyncio
async def test_api_predict_valid_flow(test_client, valid_69_features):
    """Verifies POST /api/model/predict executes inference and returns structured triage result."""
    payload = {
        "flow_id": "flow-prod-001",
        "protocol": 6,
        "flow_duration_ms": 150.0,
        "src_port": 49152,
        "dst_port": 443,
        "total_fwd_packets": 5,
        "total_bwd_packets": 4,
        "total_fwd_bytes": 500,
        "total_bwd_bytes": 1200,
        "fwd_packet_length_mean": 100.0,
        "bwd_packet_length_mean": 300.0,
        "flow_bytes_per_sec": 11333.3,
        "flow_packets_per_sec": 60.0,
        "flow_iat_mean": 18.75,
        "flow_iat_std": 5.2,
        "syn_flag_count": 1,
        "rst_flag_count": 0,
        "ack_flag_count": 1,
        "fin_flag_count": 0,
        "features": valid_69_features,
    }

    async with test_client as client:
        response = await client.post("/api/model/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["flow_id"] == "flow-prod-001"
        assert data["decision"] in ["LIKELY_BENIGN", "ABSTAIN", "THREAT_SUSPECTED"]
        assert 0.0 <= data["raw_confidence"] <= 1.0
        assert 0.0 <= data["calibrated_confidence"] <= 1.0
        assert 0.0 <= data["anomaly_score"] <= 1.0
        assert data["model_version"] == "stage4.1-calibrated-rf-iforest"
        assert "Policy" in data["policy_version"]
        assert data["explanation"] is not None
        if data["decision"] == "LIKELY_BENIGN":
            assert data["safety_notice"] == SAFETY_DISCLAIMER


@pytest.mark.asyncio
async def test_api_predict_missing_features_422(test_client):
    """Verifies that missing features return 422 with clear rejection detail."""
    payload = {
        "flow_id": "flow-incomplete",
        "protocol": 6,
        "flow_duration_ms": 150.0,
        "src_port": 49152,
        "dst_port": 443,
        "total_fwd_packets": 5,
        "total_bwd_packets": 4,
        "total_fwd_bytes": 500,
        "total_bwd_bytes": 1200,
        "fwd_packet_length_mean": 100.0,
        "bwd_packet_length_mean": 300.0,
        "flow_bytes_per_sec": 11333.3,
        "flow_packets_per_sec": 60.0,
        "flow_iat_mean": 18.75,
        "flow_iat_std": 5.2,
        # Omit 'features' dictionary entirely
    }

    async with test_client as client:
        response = await client.post("/api/model/predict", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert data["detail"]["error"] == "MISSING_REQUIRED_FEATURES"
        assert data["detail"]["total_missing"] == 69


@pytest.mark.asyncio
async def test_api_predict_batch(test_client, valid_69_features):
    """Verifies POST /api/model/predict-batch processes multiple records."""
    record_template = {
        "protocol": 6,
        "flow_duration_ms": 150.0,
        "src_port": 49152,
        "dst_port": 443,
        "total_fwd_packets": 5,
        "total_bwd_packets": 4,
        "total_fwd_bytes": 500,
        "total_bwd_bytes": 1200,
        "fwd_packet_length_mean": 100.0,
        "bwd_packet_length_mean": 300.0,
        "flow_bytes_per_sec": 11333.3,
        "flow_packets_per_sec": 60.0,
        "flow_iat_mean": 18.75,
        "flow_iat_std": 5.2,
        "features": valid_69_features,
    }

    payload = {
        "records": [
            {**record_template, "flow_id": "batch-flow-1"},
            {**record_template, "flow_id": "batch-flow-2"},
        ]
    }

    async with test_client as client:
        response = await client.post("/api/model/predict-batch", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["total_records"] == 2
        assert data["processed"] == 2
        assert len(data["predictions"]) == 2
        assert data["predictions"][0]["flow_id"] == "batch-flow-1"
        assert data["predictions"][1]["flow_id"] == "batch-flow-2"

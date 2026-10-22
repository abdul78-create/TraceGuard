"""
Tests for model lifecycle status and prediction safety constraints.
"""

import pytest
from backend.app.services.model_service import ModelService, set_model_service


@pytest.fixture(autouse=True)
def unconfigured_model_fixture():
    """Ensures unconfigured model service for unconfigured lifecycle constraint tests."""
    unconfigured_service = ModelService(auto_load=False)
    set_model_service(unconfigured_service)
    yield
    # Restore loaded service for subsequent tests
    from backend.app.core.config import settings
    set_model_service(ModelService(artifacts_dir=settings.model_artifacts_dir, auto_load=True))


@pytest.mark.asyncio
async def test_model_status_unconfigured(client):
    """Verifies that model status reports UNCONFIGURED in Stage 1."""
    response = await client.get("/api/model/status")
    assert response.status_code == 200
    data = response.json()
    assert data["lifecycle_status"] == "UNCONFIGURED"
    assert data["active_model_name"] is None
    assert data["anomaly_detector_loaded"] is False
    assert data["confidence_calibrator_loaded"] is False
    assert "Stage 1" in data["stage"]


@pytest.mark.asyncio
async def test_prediction_returns_503_when_unconfigured(client):
    """
    Verifies that valid flow schema is accepted but returns 503 Service Unavailable
    to prevent pretend or fabricated predictions before Stage 3-4 models exist.
    """
    payload = {
        "flow_id": "test-flow-001",
        "timestamp": "2026-10-22T00:00:00Z",
        "protocol": 6,
        "flow_duration_ms": 1500.0,
        "src_port": 44320,
        "dst_port": 80,
        "total_fwd_packets": 10,
        "total_bwd_packets": 8,
        "total_fwd_bytes": 1200,
        "total_bwd_bytes": 4500,
        "fwd_packet_length_mean": 120.0,
        "bwd_packet_length_mean": 562.5,
        "flow_bytes_per_sec": 3800.0,
        "flow_packets_per_sec": 12.0,
        "flow_iat_mean": 150.0,
        "flow_iat_std": 20.0,
        "syn_flag_count": 1,
        "rst_flag_count": 0,
        "ack_flag_count": 1,
        "fin_flag_count": 0,
    }
    response = await client.post("/api/model/predict", json=payload)
    assert response.status_code == 503
    data = response.json()
    assert "detail" in data
    assert data["detail"]["error"] == "MODEL_UNCONFIGURED"
    assert "Stage 1" in data["detail"]["stage"]


@pytest.mark.asyncio
async def test_prediction_schema_validation_error(client):
    """Verifies that invalid flow input is caught by Pydantic validation."""
    invalid_payload = {
        "protocol": 9999,  # invalid protocol (>255)
        "flow_duration_ms": -50.0,  # invalid negative duration
    }
    response = await client.post("/api/model/predict", json=invalid_payload)
    assert response.status_code == 422

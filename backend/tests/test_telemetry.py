"""
Tests for telemetry, drift, and evaluation metrics endpoints.
"""

import pytest


@pytest.mark.asyncio
async def test_drift_telemetry_unconfigured(client):
    response = await client.get("/api/telemetry/drift")
    assert response.status_code == 200
    data = response.json()
    assert data["monitoring_active"] is False
    assert data["baseline_window_size"] == 0
    assert data["drift_detected"] is False


@pytest.mark.asyncio
async def test_evaluation_metrics_empty(client):
    response = await client.get("/api/telemetry/evaluation")
    assert response.status_code == 200
    data = response.json()
    assert data["evaluation_available"] is False
    assert data["metrics"] == {}

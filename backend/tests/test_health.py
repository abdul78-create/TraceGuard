"""
Tests for health check endpoints.
"""

import pytest


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "app" in data
    assert "version" in data
    assert "timestamp" in data
    assert data["services"]["api_server"]["status"] == "up"
    assert data["services"]["detection_engine"]["status"] == "unconfigured"


@pytest.mark.asyncio
async def test_readiness_probe(client):
    response = await client.get("/api/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["ready"] is True
    assert data["model_ready"] is False
    assert "Stage 1" in data["message"]


@pytest.mark.asyncio
async def test_root_endpoint(client):
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "/api/health" in data["health_url"]

"""
Health check and readiness schemas.
"""

from typing import Dict
from pydantic import BaseModel, Field


class ServiceStatus(BaseModel):
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str = Field(..., description="Overall service status ('healthy', 'degraded', 'unhealthy')")
    app: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
    environment: str = Field(..., description="Active environment name")
    timestamp: str = Field(..., description="Server timestamp (ISO format)")
    services: Dict[str, ServiceStatus] = Field(..., description="Subsystem health status breakdown")


class ReadinessResponse(BaseModel):
    ready: bool = Field(..., description="Whether API is accepting client traffic")
    model_ready: bool = Field(..., description="Whether ML inference engine is active and loaded")
    message: str = Field(..., description="Readiness description or pending actions")

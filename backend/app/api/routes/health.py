"""
System health and readiness endpoints.
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.schemas.health import HealthResponse, ReadinessResponse, ServiceStatus

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse, summary="System Health Status")
async def get_health() -> HealthResponse:
    """
    Returns overall service health and operational status of subcomponents.
    Clearly indicates that the ML detection engine is unconfigured in Stage 1.
    """
    return HealthResponse(
        status="healthy",
        app=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc).isoformat(),
        services={
            "api_server": ServiceStatus(status="up", message="FastAPI asynchronous core is operational"),
            "detection_engine": ServiceStatus(
                status="unconfigured",
                message="ML models unconfigured (Stage 1 foundation phase)"
            ),
            "telemetry_stream": ServiceStatus(
                status="idle",
                message="Awaiting network flow ingestion or dataset connection"
            ),
        },
    )


@router.get("/ready", response_model=ReadinessResponse, summary="Readiness Check")
async def get_readiness() -> ReadinessResponse:
    """
    Readiness probe indicating whether the server is up and whether
    the ML inference pipeline is loaded and ready for predictions.
    """
    return ReadinessResponse(
        ready=True,
        model_ready=False,
        message="Backend API is accepting connections. Machine learning detection models are unconfigured (Stage 1)."
    )

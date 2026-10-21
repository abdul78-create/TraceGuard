"""
Main API router aggregating sub-routers.
"""

from fastapi import APIRouter
from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.model import router as model_router
from backend.app.api.routes.telemetry import router as telemetry_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(model_router)
api_router.include_router(telemetry_router)

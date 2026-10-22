"""
TraceGuard FastAPI Application Entrypoint.
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.api.router import api_router
from backend.app.core.config import settings
from backend.app.core.logging import setup_logging

# Initialize structured logging
setup_logging()
logger = logging.getLogger("traceguard.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(f"Starting {settings.app_name} v{settings.app_version} [{settings.environment}]")
    logger.info(f"API Prefix: {settings.api_prefix} | Debug: {settings.debug}")

    # Initialize model service once during startup
    from backend.app.services.model_service import get_model_service
    model_service = get_model_service()
    if settings.auto_load_model and not model_service.is_ready and settings.model_artifacts_dir:
        model_service.load_artifacts(settings.model_artifacts_dir)

    yield
    logger.info("Shutting down TraceGuard API service.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Adaptive Network Threat Detection with Calibration, Anomaly Scoring, and Abstention",
    docs_url=f"{settings.api_prefix}/docs",
    redoc_url=f"{settings.api_prefix}/redoc",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Logs incoming HTTP requests and their processing duration."""
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    logger.info(
        f"{request.method} {request.url.path} "
        f"status={response.status_code} "
        f"duration={duration_ms:.2f}ms"
    )
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catches unhandled errors and returns safe, structured JSON responses."""
    logger.error(f"Unhandled exception during request {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred processing your request. Please check server logs.",
            "path": request.url.path,
        },
    )


from backend.app.api.routes.health import router as health_router

# Mount API routes
app.include_router(api_router, prefix=settings.api_prefix)
# Support root /health and /health/ready in addition to /api/health
app.include_router(health_router, prefix="")


@app.get("/", summary="Root Index")
async def root():
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "docs_url": f"{settings.api_prefix}/docs",
        "health_url": f"{settings.api_prefix}/health",
    }

"""
Backend Services Package.
"""

from backend.app.services.model_service import ModelService, get_model_service, set_model_service

__all__ = ["ModelService", "get_model_service", "set_model_service"]

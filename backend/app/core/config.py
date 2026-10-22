"""
Configuration settings for TraceGuard API, parsed from environment variables.
"""

from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General App Settings
    app_name: str = "TraceGuard Threat Detection API"
    app_version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True
    log_level: str = "INFO"

    # Server Settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_prefix: str = "/api"

    # CORS Configuration
    cors_origins: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    # File and Model Paths
    model_artifacts_dir: str = "models/artifacts"
    data_dir: str = "data"

    # Detection & Abstention Settings
    enable_abstention: bool = True
    default_abstention_threshold: float = 0.65
    drift_detection_window: int = 1000
    auto_load_model: bool = True
    active_triage_policy: str = "POLICY_A"
    model_version: str = "stage4.1-calibrated-rf-iforest"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:5173", "http://127.0.0.1:5173"]


settings = Settings()

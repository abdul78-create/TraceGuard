"""
Telemetry, drift metrics, and evaluation reporting schemas.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class DriftStatusResponse(BaseModel):
    monitoring_active: bool = Field(False, description="Whether continuous drift monitor is streaming")
    baseline_window_size: int = Field(0, description="Number of baseline samples indexed")
    current_window_size: int = Field(0, description="Number of real-time samples in current buffer")
    drift_detected: bool = Field(False, description="Whether KS-test or PSI exceeded threshold")
    drifted_features: List[str] = Field(default_factory=list, description="Features exhibiting statistical drift")
    feature_drift_pvalues: Dict[str, float] = Field(default_factory=dict, description="P-values from 2-sample tests")
    concept_drift_score: Optional[float] = Field(None, description="Wasserstein / PSI drift metric")
    message: str = Field("Drift monitor inactive. Awaiting baseline traffic dataset selection in Stage 2.")


class EvaluationMetricsResponse(BaseModel):
    evaluation_available: bool = Field(False, description="Whether verified evaluation results exist")
    dataset_name: Optional[str] = Field(None)
    metrics: Dict[str, float] = Field(default_factory=dict)
    unseen_attack_metrics: Dict[str, float] = Field(default_factory=dict)
    calibration_error: Optional[float] = Field(None)
    confusion_matrix: Optional[List[List[int]]] = Field(None)
    message: str = Field("No evaluation benchmarks available. Stage 1 in progress.")

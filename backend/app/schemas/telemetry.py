"""
Telemetry, drift metrics, and evaluation reporting schemas.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DriftStatusResponse(BaseModel):
    monitoring_active: bool = Field(False, description="Whether continuous real-time drift monitor is streaming")
    historical_analysis_available: bool = Field(False, description="Whether offline dataset drift research analysis is available")
    baseline_window_size: int = Field(0, description="Number of baseline samples indexed")
    current_window_size: int = Field(0, description="Number of real-time samples in current buffer")
    drift_detected: bool = Field(False, description="Whether KS-test or PSI exceeded threshold")
    drifted_features: List[str] = Field(default_factory=list, description="Features exhibiting statistical drift")
    feature_drift_pvalues: Dict[str, float] = Field(default_factory=dict, description="P-values from 2-sample tests")
    concept_drift_score: Optional[float] = Field(None, description="Wasserstein / PSI drift metric")
    psi_summary: Optional[Dict[str, Any]] = Field(None, description="Population Stability Index feature distribution summary")
    daily_fpr_drift: Optional[Dict[str, float]] = Field(None, description="Daily variation in false-positive rates")
    offline_disclaimer: str = Field(
        "Historical dataset-specific covariate shift analysis across CIC-IDS2017 recording days. "
        "Continuous real-time drift streaming is currently inactive."
    )
    message: str = Field("Drift monitor inactive.")


class EvaluationMetricsResponse(BaseModel):
    evaluation_available: bool = Field(False, description="Whether verified evaluation results exist")
    dataset_name: Optional[str] = Field(None, description="Name of evaluation dataset")
    metrics: Dict[str, float] = Field(default_factory=dict, description="Primary performance metrics on known traffic")
    unseen_attack_metrics: Dict[str, Any] = Field(default_factory=dict, description="Metrics on held-out attack family (Bot)")
    calibration_error: Optional[float] = Field(None, description="Expected Calibration Error (ECE)")
    calibration_summary: Optional[Dict[str, Any]] = Field(None, description="Pre/post calibration ECE, Brier score, and reliability diagram")
    operating_points: Optional[List[Dict[str, Any]]] = Field(None, description="Anomaly detector operating points (FPR vs Recall)")
    triage_policies: Optional[Dict[str, Any]] = Field(None, description="Selective prediction comparison across Policies A, B, and C")
    confusion_matrix: Optional[Dict[str, int]] = Field(None, description="Known test confusion matrix")
    offline_disclaimer: str = Field(
        "These metrics reflect offline research experiments on CIC-IDS2017 partitions and do not represent live production performance."
    )
    message: str = Field("No evaluation benchmarks available.")


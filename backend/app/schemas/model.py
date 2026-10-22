"""
Model metadata, prediction schemas, and status contracts.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from ml.schemas import DecisionOutcome, AbstentionReason, ModelLifecycleStatus, NetworkFlowRecord


class ModelStatusResponse(BaseModel):
    """
    Reflects the current lifecycle of the detection engine.
    In Stage 1, this honestly and transparently reports UNCONFIGURED.
    """
    lifecycle_status: ModelLifecycleStatus = Field(
        default=ModelLifecycleStatus.UNCONFIGURED,
        description="Current engine state: UNCONFIGURED, TRAINING, READY, or DEGRADED"
    )
    stage: str = Field(
        default="Stage 1: Project Foundation",
        description="Current engineering stage of TraceGuard"
    )
    active_model_name: Optional[str] = Field(
        default=None,
        description="Identifier of the currently loaded classifier artifact"
    )
    baseline_algorithm: Optional[str] = Field(
        default=None,
        description="Underlying baseline model architecture"
    )
    anomaly_detector_loaded: bool = Field(
        default=False,
        description="Whether an out-of-distribution / anomaly detector is active"
    )
    confidence_calibrator_loaded: bool = Field(
        default=False,
        description="Whether Platt/Isotonic calibration is applied"
    )
    abstention_policy_active: bool = Field(
        default=False,
        description="Whether abstention triage rule is enforcing uncertainty thresholds"
    )
    training_dataset_id: Optional[str] = Field(
        default=None,
        description="Dataset identifier used for model training"
    )
    supported_classes: List[str] = Field(
        default_factory=list,
        description="Known attack categories the model was trained on"
    )
    active_policy_name: Optional[str] = Field(
        default=None,
        description="Active triage policy name (e.g., POLICY_A, POLICY_B, POLICY_C)"
    )
    anomaly_thresholds: Optional[Dict[str, float]] = Field(
        default=None,
        description="Operating anomaly detection thresholds"
    )
    n_features: Optional[int] = Field(
        default=None,
        description="Expected number of flow features"
    )
    message: str = Field(
        default="Detection engine is unconfigured."
    )


class ModelErrorDetail(BaseModel):
    error: str
    message: str
    status_code: int
    resolution: str


class PredictBatchRequest(BaseModel):
    records: List[NetworkFlowRecord] = Field(..., min_length=1, max_length=500)


class PredictBatchResponse(BaseModel):
    total_records: int
    processed: int
    predictions: List[Dict] = Field(default_factory=list)

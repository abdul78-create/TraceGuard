"""
Model lifecycle status and inference endpoints.
"""

from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.model import (
    ModelStatusResponse,
    PredictBatchRequest,
)
from ml.schemas import (
    ModelLifecycleStatus,
    NetworkFlowRecord,
    PredictionResult,
)

router = APIRouter(prefix="/model", tags=["Model"])


@router.get("/status", response_model=ModelStatusResponse, summary="Get Model Lifecycle Status")
async def get_model_status() -> ModelStatusResponse:
    """
    Returns the real lifecycle status of the threat detection models.
    In Stage 1, this honestly declares UNCONFIGURED to prevent premature or fabricated evaluations.
    """
    return ModelStatusResponse(
        lifecycle_status=ModelLifecycleStatus.UNCONFIGURED,
        stage="Stage 1: Project Foundation",
        active_model_name=None,
        baseline_algorithm=None,
        anomaly_detector_loaded=False,
        confidence_calibrator_loaded=False,
        abstention_policy_active=False,
        training_dataset_id=None,
        supported_classes=[],
        message=(
            "Detection engine is currently unconfigured. In Stage 1, architecture, schemas, and API "
            "contracts are established. Training of baseline classifier, anomaly detection, calibration, "
            "and abstention mechanisms will occur in Stages 3-4 after dataset selection in Stage 2."
        ),
    )


@router.post(
    "/predict",
    response_model=PredictionResult,
    summary="Predict Network Flow Threat (Awaiting Stage 3-4 Model Training)",
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
)
async def predict_flow(flow: NetworkFlowRecord):
    """
    Inference endpoint. Validates network flow features using the standard schema.
    In Stage 1, returns HTTP 503 Service Unavailable because no trained model weights are loaded.
    Prevents fabricated predictions.
    """
    # Flow record has already passed strict Pydantic validation
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "MODEL_UNCONFIGURED",
            "message": (
                "Cannot perform inference: No trained detection model is loaded. "
                "TraceGuard is in Stage 1 (Foundation). Flow record schema validation succeeded, "
                "but model training and weight artifacts are scheduled for Stages 3-4."
            ),
            "flow_id": flow.flow_id,
            "stage": "Stage 1: Project Foundation",
            "resolution": "Complete Stage 2 dataset selection, then proceed to Stage 3 baseline training.",
        },
    )


@router.post(
    "/predict-batch",
    summary="Batch Inference (Awaiting Stage 3-4 Model Training)",
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
)
async def predict_batch(batch: PredictBatchRequest):
    """
    Batch inference endpoint. Validates batch records against standard schema.
    In Stage 1, returns HTTP 503 Service Unavailable because no trained model weights are loaded.
    """
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "MODEL_UNCONFIGURED",
            "message": f"Batch of {len(batch.records)} records validated successfully, but detection engine is unconfigured in Stage 1.",
            "stage": "Stage 1: Project Foundation",
        },
    )

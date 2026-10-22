"""
Model lifecycle status and inference endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from backend.app.schemas.model import (
    ModelStatusResponse,
    PredictBatchRequest,
    PredictBatchResponse,
)
from backend.app.services.model_service import ModelService, get_model_service
from ml.schemas import (
    ModelLifecycleStatus,
    NetworkFlowRecord,
    PredictionResult,
)

router = APIRouter(prefix="/model", tags=["Model"])


@router.get("/status", response_model=ModelStatusResponse, summary="Get Model Lifecycle Status")
async def get_model_status(
    service: ModelService = Depends(get_model_service),
) -> ModelStatusResponse:
    """
    Returns the real lifecycle status of the threat detection models.
    Reports READY when Stage 4.1 artifacts are loaded, or UNCONFIGURED if absent/incomplete.
    """
    return service.get_status()


@router.post(
    "/predict",
    response_model=PredictionResult,
    summary="Predict Network Flow Threat with Calibration and Abstention",
)
async def predict_flow(
    flow: NetworkFlowRecord,
    policy: Optional[str] = Query(None, description="Optional triage policy override (POLICY_A, POLICY_B, POLICY_C)"),
    service: ModelService = Depends(get_model_service),
):
    """
    Inference endpoint. Validates network flow features against the learned 69-feature schema.
    Returns THREAT_SUSPECTED, ABSTAIN, or LIKELY_BENIGN with calibrated probability and anomaly score.
    Returns HTTP 503 if models are unconfigured.
    """
    if not service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "MODEL_UNCONFIGURED",
                "message": (
                    "Cannot perform inference: No trained detection model is loaded. "
                    "Flow record schema validation succeeded, but detection engine is unconfigured."
                ),
                "flow_id": flow.flow_id,
                "stage": "Stage 1: Project Foundation (Model Unconfigured)",
                "resolution": "Verify model artifacts are present and valid in the configured directory.",
            },
        )

    return service.predict(flow, policy=policy)


@router.post(
    "/predict-batch",
    response_model=PredictBatchResponse,
    summary="Batch Inference with Calibration and Abstention",
)
async def predict_batch(
    batch: PredictBatchRequest,
    policy: Optional[str] = Query(None, description="Optional triage policy override (POLICY_A, POLICY_B, POLICY_C)"),
    service: ModelService = Depends(get_model_service),
):
    """
    Batch inference endpoint. Validates batch records against standard schema.
    Returns HTTP 503 if models are unconfigured.
    """
    if not service.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "MODEL_UNCONFIGURED",
                "message": f"Batch of {len(batch.records)} records validated successfully, but detection engine is unconfigured in Stage 1.",
                "stage": "Stage 1: Project Foundation",
            },
        )

    results = service.predict_batch(batch.records, policy=policy)
    return PredictBatchResponse(
        total_records=len(batch.records),
        processed=len(results),
        predictions=[r.model_dump() for r in results],
    )


@router.get("/sample-flows", summary="Get Synthetic Demonstration Flows for Interactive Triage Testing")
async def get_sample_flows():
    """
    Returns authentic, schema-validated synthetic demonstration flows representing:
    1. Normal Benign HTTPS Browsing (cleared to LIKELY_BENIGN)
    2. Known DoS Hulk Attack (detected as THREAT_SUSPECTED)
    3. Known DDoS Attack (detected as THREAT_SUSPECTED)
    4. Held-Out Botnet Attack (demonstrating unseen threat evasion in Policy A vs abstention in Policy B)
    5. Atypical Feature Outlier (triggering Isolation Forest ABSTAIN)

    These flows are explicitly marked as synthetic demonstration flows.
    """
    import json
    from pathlib import Path

    sample_path = Path(__file__).resolve().parent.parent / "sample_flows.json"
    if sample_path.is_file():
        try:
            with open(sample_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


# Expose evaluation and drift under /api/model/ as well for direct discovery
from backend.app.api.routes.telemetry import (
    get_drift_telemetry,
    get_evaluation_metrics,
)
from backend.app.schemas.telemetry import DriftStatusResponse, EvaluationMetricsResponse

router.add_api_route(
    "/evaluation",
    get_evaluation_metrics,
    methods=["GET"],
    response_model=EvaluationMetricsResponse,
    summary="Get Evaluation Benchmark Metrics",
)

router.add_api_route(
    "/drift",
    get_drift_telemetry,
    methods=["GET"],
    response_model=DriftStatusResponse,
    summary="Get Traffic Drift Telemetry",
)


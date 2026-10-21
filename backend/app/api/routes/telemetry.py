"""
Telemetry, drift metrics, and model evaluation reporting endpoints.
"""

from fastapi import APIRouter
from backend.app.schemas.telemetry import DriftStatusResponse, EvaluationMetricsResponse

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.get("/drift", response_model=DriftStatusResponse, summary="Traffic Drift Telemetry")
async def get_drift_telemetry() -> DriftStatusResponse:
    """
    Returns data distribution drift telemetry.
    In Stage 1, indicates that baseline reference distribution has not been configured.
    """
    return DriftStatusResponse(
        monitoring_active=False,
        baseline_window_size=0,
        current_window_size=0,
        drift_detected=False,
        drifted_features=[],
        feature_drift_pvalues={},
        concept_drift_score=None,
        message="Traffic drift monitor is currently inactive. Awaiting baseline training distribution in Stage 2-4.",
    )


@router.get("/evaluation", response_model=EvaluationMetricsResponse, summary="Evaluation Benchmark Metrics")
async def get_evaluation_metrics() -> EvaluationMetricsResponse:
    """
    Returns empirical evaluation results (Precision, Recall, Macro-F1, PR-AUC, Calibration, Unseen Attacks).
    In Stage 1, transparently reports that no benchmark run has been completed.
    """
    return EvaluationMetricsResponse(
        evaluation_available=False,
        dataset_name=None,
        metrics={},
        unseen_attack_metrics={},
        calibration_error=None,
        confusion_matrix=None,
        message="No verified model evaluation benchmark has been executed. Stage 1 in progress.",
    )

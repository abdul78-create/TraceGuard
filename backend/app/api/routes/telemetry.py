import json
import logging
from pathlib import Path
from fastapi import APIRouter
from backend.app.schemas.telemetry import DriftStatusResponse, EvaluationMetricsResponse

logger = logging.getLogger("traceguard.telemetry")

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


def _load_stage4_metrics() -> dict:
    """
    Loads and deeply validates the frozen Stage 4.1 evaluation metrics from disk.
    Ensures that the JSON file exists, is valid, and contains expected experiment schemas
    with valid numerical metric values.
    """
    root = Path(__file__).resolve().parents[4]
    metrics_path = root / "reports" / "evaluation" / "stage4_unseen_detection_metrics.json"
    if not metrics_path.is_file():
        logger.warning(f"Evaluation metrics file not found at {metrics_path}")
        return {}

    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            logger.warning(f"Corrupt evaluation metrics format in {metrics_path}: expected JSON object")
            return {}

        # 1. Validate top-level required sections
        required_sections = ["protocol_b_heldout_experiment", "protocol_c_temporal_drift_experiment"]
        for section in required_sections:
            if section not in data or not isinstance(data[section], dict):
                logger.warning(f"Missing or invalid required section '{section}' in {metrics_path}")
                return {}

        # 2. Deep validation of protocol_b_heldout_experiment
        b_exp = data["protocol_b_heldout_experiment"]
        known = b_exp.get("supervised_model_known_test")
        if not isinstance(known, dict) or not isinstance(known.get("macro_f1"), (int, float)):
            logger.warning(f"Invalid or missing 'supervised_model_known_test.macro_f1' in {metrics_path}")
            return {}

        bot = b_exp.get("supervised_model_on_heldout_bot")
        if not isinstance(bot, dict) or not isinstance(bot.get("total_bot_flows"), (int, float)):
            logger.warning(f"Invalid or missing 'supervised_model_on_heldout_bot.total_bot_flows' in {metrics_path}")
            return {}

        calib = b_exp.get("calibration_evaluation_untouched_test")
        if not isinstance(calib, dict) or not isinstance(calib.get("calibrated_ece"), (int, float)):
            logger.warning(f"Invalid or missing 'calibration_evaluation_untouched_test.calibrated_ece' in {metrics_path}")
            return {}

        triage = b_exp.get("selective_prediction_triage_comparison")
        if not isinstance(triage, dict):
            logger.warning(f"Missing 'selective_prediction_triage_comparison' in {metrics_path}")
            return {}

        for pol_key in ["policy_a_permissive", "policy_b_balanced", "policy_c_conservative"]:
            pol = triage.get(pol_key)
            if not isinstance(pol, dict) or not isinstance(pol.get("heldout_bot_safety_rate"), (int, float)):
                logger.warning(f"Missing or invalid policy entry '{pol_key}' in {metrics_path}")
                return {}

        # 3. Deep validation of protocol_c_temporal_drift_experiment
        c_exp = data["protocol_c_temporal_drift_experiment"]
        psi = c_exp.get("psi_summary")
        if not isinstance(psi, dict) or not isinstance(psi.get("stable_count_psi_under_0_1"), (int, float)):
            logger.warning(f"Missing or invalid 'psi_summary' in {metrics_path}")
            return {}

        return data
    except Exception as e:
        logger.warning(f"Failed to load or validate evaluation metrics from {metrics_path}: {e}")
        return {}


@router.get("/drift", response_model=DriftStatusResponse, summary="Traffic Drift Telemetry")
async def get_drift_telemetry() -> DriftStatusResponse:
    """
    Returns data distribution drift telemetry.
    Reports offline historical covariate shift metrics across CIC-IDS2017 capture days.
    Honestly states that real-time live streaming drift monitor is currently inactive.
    """
    data = _load_stage4_metrics()
    if not data or "protocol_c_temporal_drift_experiment" not in data:
        return DriftStatusResponse(
            monitoring_active=False,
            historical_analysis_available=False,
            baseline_window_size=0,
            current_window_size=0,
            drift_detected=False,
            drifted_features=[],
            feature_drift_pvalues={},
            concept_drift_score=None,
            psi_summary=None,
            daily_fpr_drift=None,
            message="Traffic drift monitor is currently inactive. No historical or live drift analysis available.",
        )

    drift_data = data["protocol_c_temporal_drift_experiment"]
    psi_summary = drift_data.get("psi_summary", {})
    daily_fpr = drift_data.get("daily_anomaly_fpr_drift", {})

    top_drifted = [
        item["feature"]
        for item in psi_summary.get("top_10_drifted_features", [])
        if item.get("psi", 0) >= 0.1
    ]

    return DriftStatusResponse(
        monitoring_active=False,
        historical_analysis_available=True,
        baseline_window_size=drift_data.get("early_train_flows", 903802),
        current_window_size=0,
        drift_detected=len(top_drifted) > 0,
        drifted_features=top_drifted,
        feature_drift_pvalues={},
        concept_drift_score=None,  # Protocol C evaluates covariate shift via PSI, not concept drift
        psi_summary=psi_summary,
        daily_fpr_drift=daily_fpr,
        message="Historical dataset-specific covariate shift analysis available. Continuous real-time stream is inactive.",
    )


@router.get("/evaluation", response_model=EvaluationMetricsResponse, summary="Evaluation Benchmark Metrics")
async def get_evaluation_metrics() -> EvaluationMetricsResponse:
    """
    Returns empirical evaluation results (Precision, Recall, Macro-F1, PR-AUC, Calibration, Unseen Attacks).
    Sourced directly from the verified Stage 4.1 held-out Bot benchmark report.
    """
    data = _load_stage4_metrics()
    if not data or "protocol_b_heldout_experiment" not in data:
        return EvaluationMetricsResponse(
            evaluation_available=False,
            message="No verified model evaluation benchmark has been executed.",
        )

    heldout = data["protocol_b_heldout_experiment"]
    known = heldout.get("supervised_model_known_test", {})
    bot = heldout.get("supervised_model_on_heldout_bot", {})
    calib = heldout.get("calibration_evaluation_untouched_test", {})
    ops = heldout.get("benign_only_anomaly_detection_operating_points", [])
    triage = heldout.get("selective_prediction_triage_comparison", {})

    metrics = {
        "macro_f1": known.get("macro_f1", 0.0),
        "attack_precision": known.get("attack_precision", 0.0),
        "attack_recall": known.get("attack_recall", 0.0),
        "pr_auc": known.get("pr_auc", 0.0),
        "roc_auc": known.get("roc_auc", 0.0),
        "fpr": known.get("fpr", 0.0),
        "fnr": known.get("fnr", 0.0),
    }

    return EvaluationMetricsResponse(
        evaluation_available=True,
        dataset_name="CIC-IDS2017 (Held-out Bot Benchmark, 5-Fold Partition)",
        metrics=metrics,
        unseen_attack_metrics={
            "heldout_family": heldout.get("heldout_label", "Bot"),
            "total_bot_flows": bot.get("total_bot_flows", 0),
            "detected_as_attack_count": bot.get("detected_as_attack_count", 0),
            "missed_as_benign_count": bot.get("missed_as_benign_count", 0),
            "supervised_recall": bot.get("supervised_recall", 0.0),
            "mean_predicted_attack_prob": bot.get("mean_predicted_attack_prob", 0.0),
        },
        calibration_error=calib.get("calibrated_ece"),
        calibration_summary={
            "raw_ece": calib.get("raw_ece"),
            "raw_brier": calib.get("raw_brier"),
            "calibrated_ece": calib.get("calibrated_ece"),
            "calibrated_brier": calib.get("calibrated_brier"),
            "reliability_diagram_bins": calib.get("reliability_diagram_bins", []),
        },
        operating_points=ops,
        triage_policies=triage,
        confusion_matrix=known.get("confusion_matrix"),
        message="Stage 4.1 empirical benchmark results verified across 5 leakage-free partitions.",
    )


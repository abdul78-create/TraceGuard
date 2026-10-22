"""
Model loading and inference service for TraceGuard Stage 5A.
Safely integrates frozen Stage 4.1 research artifacts into the FastAPI backend.

Key Invariants:
1. Validates artifacts existence, compatibility, feature order, and metadata before marking READY.
2. Loads artifacts once during application lifecycle.
3. Strict server-side feature validation: rejects missing features, NaN, infinity, non-numeric values without silent zero-imputation.
4. Uses exact training-time preprocessing and 69-feature ordering.
5. Implements explicit, versioned triage policies (Policy A Permissive, Policy B Balanced, Policy C Zero-Trust).
6. Returns clear safety limitations: LIKELY_BENIGN is never a guarantee of security; no claims of zero-day detection.
7. Preserves HTTP 503 MODEL_UNCONFIGURED if artifacts are absent, incomplete, or corrupt without leaking system paths.
"""

from __future__ import annotations

import json
import logging
import math
import sys
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from fastapi import HTTPException, status
from pydantic import BaseModel

import ml.train_unseen
from ml.preprocessing import PreprocessPipeline
from ml.schemas import (
    AbstentionReason,
    DecisionOutcome,
    ModelLifecycleStatus,
    NetworkFlowRecord,
    PredictionResult,
    TrafficClass,
)
from backend.app.schemas.model import ModelStatusResponse

# Ensure AnomalyDetector unpickling works if artifact was pickled in __main__
if "__main__" in sys.modules and not hasattr(sys.modules["__main__"], "AnomalyDetector"):
    setattr(sys.modules["__main__"], "AnomalyDetector", ml.train_unseen.AnomalyDetector)

logger = logging.getLogger("traceguard.model_service")


class TriagePolicy(str, Enum):
    POLICY_A = "POLICY_A"  # Permissive Baseline (tau_anom = tau_5%)
    POLICY_B = "POLICY_B"  # Balanced Anomaly Guard (tau_anom = tau_25%)
    POLICY_C = "POLICY_C"  # Conservative Zero-Trust (tau_anom = tau_median, P <= 0.10)


POLICY_DESCRIPTIONS: Dict[str, str] = {
    TriagePolicy.POLICY_A.value: "Policy A: Permissive (Stage 4 Baseline)",
    TriagePolicy.POLICY_B.value: "Policy B: Balanced Anomaly Guard (75% Inlier)",
    TriagePolicy.POLICY_C.value: "Policy C: Conservative Zero-Trust (50% Inlier)",
}

SAFETY_DISCLAIMER: str = (
    "LIKELY_BENIGN indicates statistical resemblance to known benign baseline traffic, NOT a guarantee of security. "
    "Stealthy, low-rate, or held-out zero-day attacks (e.g. Ares botnet C2 check-ins) mimic normal browsing and "
    "may not trigger flow-level statistical thresholds. Multi-source defense-in-depth telemetry is required."
)


class ModelService:
    """
    Controlled model-loading and inference service for TraceGuard.
    """

    def __init__(
        self,
        artifacts_dir: Optional[str | Path] = None,
        default_policy: str = TriagePolicy.POLICY_A.value,
        auto_load: bool = True,
    ):
        self.artifacts_dir: Optional[Path] = Path(artifacts_dir) if artifacts_dir else None
        self.default_policy: str = default_policy
        self.status: ModelLifecycleStatus = ModelLifecycleStatus.UNCONFIGURED
        self.load_error: Optional[str] = None

        self.preprocessor: Optional[PreprocessPipeline] = None
        self.classifier: Optional[Any] = None
        self.calibrator: Optional[Any] = None
        self.anomaly_detector: Optional[Any] = None
        self.metadata: Optional[Dict[str, Any]] = None

        self.feature_names_: List[str] = []
        self.anomaly_thresholds: Dict[str, float] = {}
        self.tau_5pct: float = 0.6001
        self.tau_25pct: float = 0.1873
        self.tau_50pct: float = 0.0756
        self.model_version: str = "stage4.1-calibrated-rf-iforest"

        if auto_load and self.artifacts_dir:
            self.load_artifacts(self.artifacts_dir)

    @property
    def is_ready(self) -> bool:
        return self.status == ModelLifecycleStatus.READY

    def reset(self) -> None:
        """Resets the model service back to unconfigured state (useful for testing)."""
        self.status = ModelLifecycleStatus.UNCONFIGURED
        self.load_error = None
        self.preprocessor = None
        self.classifier = None
        self.calibrator = None
        self.anomaly_detector = None
        self.metadata = None
        self.feature_names_ = []
        self.anomaly_thresholds = {}

    def load_artifacts(self, artifacts_dir: str | Path) -> bool:
        """
        Loads and validates all 5 Stage 4.1 research artifacts:
        1. stage4_preprocessor.joblib
        2. stage4_heldout_classifier.joblib
        3. stage4_calibrator.joblib
        4. stage4_isolation_forest.joblib
        5. stage4_metadata.json

        Validates feature counts, schema consistency, and compatibility before marking READY.
        """
        path = Path(artifacts_dir)
        self.artifacts_dir = path

        required_files = {
            "preprocessor": path / "stage4_preprocessor.joblib",
            "classifier": path / "stage4_heldout_classifier.joblib",
            "calibrator": path / "stage4_calibrator.joblib",
            "anomaly_detector": path / "stage4_isolation_forest.joblib",
            "metadata": path / "stage4_metadata.json",
        }

        # 1. Verify existence of all required artifact files
        for name, fpath in required_files.items():
            if not fpath.exists():
                msg = f"Artifact missing: '{fpath.name}'"
                logger.warning(f"Cannot load model service: {msg}")
                self.status = ModelLifecycleStatus.UNCONFIGURED
                self.load_error = msg
                return False

        try:
            # 2. Ensure __main__.AnomalyDetector alias is set before unpickling
            if "__main__" in sys.modules and not hasattr(sys.modules["__main__"], "AnomalyDetector"):
                setattr(sys.modules["__main__"], "AnomalyDetector", ml.train_unseen.AnomalyDetector)

            # 3. Load preprocessor
            prep = joblib.load(required_files["preprocessor"])
            if not hasattr(prep, "feature_names_") or not hasattr(prep, "transform"):
                raise TypeError("Preprocessor artifact lacks required feature_names_ or transform interface")
            if len(prep.feature_names_) != 69:
                raise ValueError(f"Preprocessor feature count mismatch: expected 69, found {len(prep.feature_names_)}")

            # 4. Load supervised classifier
            clf = joblib.load(required_files["classifier"])
            if not hasattr(clf, "predict_proba") or not hasattr(clf, "n_features_in_"):
                raise TypeError("Supervised classifier artifact lacks predict_proba or n_features_in_")
            if clf.n_features_in_ != 69:
                raise ValueError(f"Classifier n_features_in_ mismatch: expected 69, found {clf.n_features_in_}")

            # 5. Load Platt calibrator
            cal = joblib.load(required_files["calibrator"])
            if not hasattr(cal, "predict_proba"):
                raise TypeError("Platt calibrator artifact lacks predict_proba interface")

            # 6. Load Isolation Forest anomaly detector
            anom = joblib.load(required_files["anomaly_detector"])
            if not hasattr(anom, "score"):
                raise TypeError("Anomaly detector artifact lacks score method")

            # 7. Load and validate metadata JSON
            with open(required_files["metadata"], "r", encoding="utf-8") as f:
                meta = json.load(f)

            if "anomaly_thresholds" not in meta or "5%" not in meta["anomaly_thresholds"]:
                raise ValueError("Metadata lacks required anomaly_thresholds mapping with 5% threshold")

            # 8. All validations passed; commit to service state
            self.preprocessor = prep
            self.classifier = clf
            self.calibrator = cal
            self.anomaly_detector = anom
            self.metadata = meta
            self.feature_names_ = list(prep.feature_names_)
            self.anomaly_thresholds = meta.get("anomaly_thresholds", {})

            self.tau_5pct = float(self.anomaly_thresholds.get("5%", 0.60008))
            self.tau_25pct = float(self.anomaly_thresholds.get("25%", 0.187313))
            self.tau_50pct = float(self.anomaly_thresholds.get("50%", 0.075572))

            self.status = ModelLifecycleStatus.READY
            self.load_error = None
            logger.info(
                f"ModelService successfully initialized and READY: 69 features, "
                f"calibrator, anomaly detector (tau_5%={self.tau_5pct:.4f})."
            )
            return True

        except Exception as e:
            err_msg = f"Failed to initialize model artifacts: {type(e).__name__}: {str(e)}"
            logger.error(err_msg, exc_info=True)
            self.status = ModelLifecycleStatus.UNCONFIGURED
            self.load_error = "Model artifacts failed integrity validation."
            return False

    def validate_and_extract_features(self, record: NetworkFlowRecord | Dict[str, Any]) -> np.ndarray:
        """
        Extracts, validates, and orders features strictly according to the 69-feature training schema.
        - Rejects missing required features with HTTP 422 (never silently fabricates zeros).
        - Rejects non-numeric, NaN, and +/-infinity with HTTP 422.
        - Transforms features using the learned training-time preprocessing pipeline.
        """
        if not self.is_ready or self.preprocessor is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "MODEL_UNCONFIGURED",
                    "message": "Detection engine is unconfigured. Cannot perform feature validation or inference.",
                },
            )

        # 1. Collate feature dictionary from input
        feature_dict: Dict[str, Any] = {}
        if isinstance(record, NetworkFlowRecord):
            # Check if record has explicit features dict
            if record.features and isinstance(record.features, dict):
                feature_dict.update(record.features)
            # Also inspect extra attributes if present
            extra = getattr(record, "__pydantic_extra__", None) or {}
            feature_dict.update(extra)
        elif isinstance(record, dict):
            if "features" in record and isinstance(record["features"], dict):
                feature_dict.update(record["features"])
            else:
                feature_dict.update(record)
        else:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "INVALID_INPUT_SCHEMA",
                    "message": f"Expected NetworkFlowRecord or dict, received {type(record).__name__}.",
                },
            )

        # 2. Check for missing required features
        missing_features: List[str] = [
            f for f in self.feature_names_ if f not in feature_dict
        ]
        if missing_features:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "MISSING_REQUIRED_FEATURES",
                    "message": (
                        f"Input flow is missing {len(missing_features)} required model features. "
                        f"Expected all 69 standardized flow features. Client supplied {len(feature_dict)}. "
                        f"TraceGuard does not silently substitute arbitrary zeros or fabricated traffic."
                    ),
                    "total_expected": len(self.feature_names_),
                    "total_missing": len(missing_features),
                    "missing_sample": missing_features[:10],
                },
            )

        # 3. Validate feature values: finite numbers only (no strings, booleans, NaN, or infinity)
        ordered_values: List[float] = []
        for feat_name in self.feature_names_:
            val = feature_dict[feat_name]
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "NON_NUMERIC_FEATURE",
                        "message": f"Feature '{feat_name}' must be numeric (int/float), received {type(val).__name__}.",
                        "feature": feat_name,
                    },
                )
            fval = float(val)
            if math.isnan(fval) or math.isinf(fval):
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "NON_FINITE_FEATURE",
                        "message": (
                            f"Feature '{feat_name}' has non-finite value '{val}'. "
                            f"NaN and infinity are rejected on live inputs to prevent silent corruptions."
                        ),
                        "feature": feat_name,
                    },
                )
            ordered_values.append(fval)

        # 4. Construct 2D array and transform via learned preprocessor
        X_raw = np.array([ordered_values], dtype=np.float64)
        return self.preprocessor.transform(X_raw)

    def evaluate_triage(
        self,
        cal_prob: float,
        anom_score: float,
        policy: str,
    ) -> Tuple[DecisionOutcome, AbstentionReason, str, str]:
        """
        Executes one of the 3 audited triage policies:
        - Policy A: Permissive Baseline (tau_anom = tau_5%)
        - Policy B: Balanced Anomaly Guard (tau_anom = tau_25%)
        - Policy C: Conservative Zero-Trust (tau_anom = tau_50%, P <= 0.10)

        Returns: (decision, abstention_reason, policy_version_name, explanation)
        """
        pol = policy.upper()
        if pol in ["POLICY_B", "BALANCED"]:
            pol_name = POLICY_DESCRIPTIONS[TriagePolicy.POLICY_B.value]
            if cal_prob >= 0.65:
                return (
                    DecisionOutcome.THREAT_SUSPECTED,
                    AbstentionReason.NONE,
                    pol_name,
                    f"Calibrated attack probability ({cal_prob:.4f}) >= 0.65 threshold. Suspected known threat.",
                )
            elif cal_prob <= 0.35:
                if anom_score >= self.tau_5pct:
                    return (
                        DecisionOutcome.ABSTAIN,
                        AbstentionReason.UNSEEN_ATTACK_DISTRIBUTION,
                        pol_name,
                        f"Attack probability is low ({cal_prob:.4f}), but anomaly score ({anom_score:.4f}) "
                        f"exceeds the 5% FPR threshold ({self.tau_5pct:.4f}). Abstained as potential unseen attack.",
                    )
                elif anom_score >= self.tau_25pct:
                    return (
                        DecisionOutcome.ABSTAIN,
                        AbstentionReason.FEATURE_ANOMALY,
                        pol_name,
                        f"Attack probability is low ({cal_prob:.4f}), but anomaly score ({anom_score:.4f}) "
                        f"exceeds the 25% Balanced Guard threshold ({self.tau_25pct:.4f}). Abstained as unverified inlier.",
                    )
                else:
                    return (
                        DecisionOutcome.LIKELY_BENIGN,
                        AbstentionReason.NONE,
                        pol_name,
                        f"Calibrated probability ({cal_prob:.4f}) <= 0.35 and anomaly score ({anom_score:.4f}) < 25% threshold ({self.tau_25pct:.4f}). Confirmed typical benign inlier.",
                    )
            else:
                return (
                    DecisionOutcome.ABSTAIN,
                    AbstentionReason.LOW_CONFIDENCE,
                    pol_name,
                    f"Calibrated probability ({cal_prob:.4f}) falls in ambiguous zone (0.35 < P < 0.65). Abstained due to low confidence.",
                )

        elif pol in ["POLICY_C", "CONSERVATIVE", "ZERO_TRUST"]:
            pol_name = POLICY_DESCRIPTIONS[TriagePolicy.POLICY_C.value]
            if cal_prob >= 0.50:
                return (
                    DecisionOutcome.THREAT_SUSPECTED,
                    AbstentionReason.NONE,
                    pol_name,
                    f"Attack probability ({cal_prob:.4f}) meets Zero-Trust threat threshold (0.50). Threat suspected.",
                )
            elif anom_score >= self.tau_50pct:
                return (
                    DecisionOutcome.ABSTAIN,
                    AbstentionReason.FEATURE_ANOMALY,
                    pol_name,
                    f"Anomaly score ({anom_score:.4f}) exceeds median benign validation threshold ({self.tau_50pct:.4f}). Abstained under Zero-Trust guard.",
                )
            elif cal_prob <= 0.10:
                return (
                    DecisionOutcome.LIKELY_BENIGN,
                    AbstentionReason.NONE,
                    pol_name,
                    f"Attack probability ({cal_prob:.4f}) <= 0.10 and anomaly score ({anom_score:.4f}) < median threshold ({self.tau_50pct:.4f}). Cleared under Zero-Trust core inlier criteria.",
                )
            else:
                return (
                    DecisionOutcome.ABSTAIN,
                    AbstentionReason.LOW_CONFIDENCE,
                    pol_name,
                    f"Attack probability ({cal_prob:.4f}) > 0.10 threshold. Abstained under Zero-Trust policy.",
                )

        else:
            # Default to Policy A: Permissive (Original Stage 4 Baseline)
            pol_name = POLICY_DESCRIPTIONS[TriagePolicy.POLICY_A.value]
            if cal_prob >= 0.65:
                return (
                    DecisionOutcome.THREAT_SUSPECTED,
                    AbstentionReason.NONE,
                    pol_name,
                    f"Calibrated attack probability ({cal_prob:.4f}) >= 0.65 threshold. Threat suspected.",
                )
            elif cal_prob <= 0.35:
                if anom_score >= self.tau_5pct:
                    return (
                        DecisionOutcome.ABSTAIN,
                        AbstentionReason.UNSEEN_ATTACK_DISTRIBUTION,
                        pol_name,
                        f"Attack probability is low ({cal_prob:.4f}), but anomaly score ({anom_score:.4f}) "
                        f"exceeds 5% FPR threshold ({self.tau_5pct:.4f}). Abstained as potential unseen attack.",
                    )
                else:
                    return (
                        DecisionOutcome.LIKELY_BENIGN,
                        AbstentionReason.NONE,
                        pol_name,
                        f"Attack probability ({cal_prob:.4f}) <= 0.35 and anomaly score ({anom_score:.4f}) < {self.tau_5pct:.4f}. Flow routed to LIKELY_BENIGN.",
                    )
            else:
                return (
                    DecisionOutcome.ABSTAIN,
                    AbstentionReason.LOW_CONFIDENCE,
                    pol_name,
                    f"Attack probability ({cal_prob:.4f}) is ambiguous (0.35 < P < 0.65). Abstained due to low confidence.",
                )

    def predict(
        self,
        record: NetworkFlowRecord | Dict[str, Any],
        policy: Optional[str] = None,
    ) -> PredictionResult:
        """
        Executes end-to-end inference for a single network flow:
        1. Feature extraction and learned transformation.
        2. Supervised raw and Platt-calibrated probability scoring.
        3. Benign-only Isolation Forest anomaly scoring.
        4. Triage decision, explanation, and explicit safety disclaimer.
        """
        if not self.is_ready:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "MODEL_UNCONFIGURED",
                    "message": "Detection engine is unconfigured. Machine learning model artifacts are not loaded.",
                    "stage": "Stage 5A: Safe Model Integration (Unconfigured)",
                    "resolution": "Ensure model artifacts exist in the configured artifacts directory.",
                },
            )

        X_trans = self.validate_and_extract_features(record)

        # 1. Supervised raw and calibrated confidence
        raw_prob = float(self.classifier.predict_proba(X_trans)[0, 1])
        cal_prob = float(self.calibrator.predict_proba(X_trans)[0, 1])

        # 2. Unsupervised anomaly score
        anom_score = float(self.anomaly_detector.score(X_trans)[0])
        anom_score = max(0.0, min(1.0, anom_score))

        # 3. Triage policy evaluation
        chosen_policy = policy or self.default_policy
        decision, reason, pol_version, explanation = self.evaluate_triage(
            cal_prob=cal_prob,
            anom_score=anom_score,
            policy=chosen_policy,
        )

        # 4. Map predicted class
        if decision == DecisionOutcome.THREAT_SUSPECTED:
            pred_class = TrafficClass.DOS if raw_prob >= 0.5 else TrafficClass.UNKNOWN_ANOMALY
        elif decision == DecisionOutcome.LIKELY_BENIGN:
            pred_class = TrafficClass.BENIGN
        else:
            pred_class = TrafficClass.UNKNOWN_ANOMALY if reason == AbstentionReason.UNSEEN_ATTACK_DISTRIBUTION else None

        flow_id = getattr(record, "flow_id", None) or (record.get("flow_id") if isinstance(record, dict) else None)

        return PredictionResult(
            flow_id=flow_id,
            decision=decision,
            predicted_class=pred_class,
            raw_confidence=round(raw_prob, 4),
            calibrated_confidence=round(cal_prob, 4),
            anomaly_score=round(anom_score, 4),
            abstention_reason=reason,
            class_probabilities={
                "benign": round(1.0 - cal_prob, 4),
                "attack": round(cal_prob, 4),
            },
            feature_contributions=None,
            model_version=self.model_version,
            policy_version=pol_version,
            explanation=explanation,
            safety_notice=SAFETY_DISCLAIMER if decision == DecisionOutcome.LIKELY_BENIGN else None,
        )

    def predict_batch(
        self,
        records: List[NetworkFlowRecord | Dict[str, Any]],
        policy: Optional[str] = None,
    ) -> List[PredictionResult]:
        """Executes inference across a batch of flow records."""
        return [self.predict(rec, policy=policy) for rec in records]

    def get_status(self) -> ModelStatusResponse:
        """Constructs honest, real-time lifecycle status of the detection service."""
        if not self.is_ready:
            return ModelStatusResponse(
                lifecycle_status=ModelLifecycleStatus.UNCONFIGURED,
                stage="Stage 1: Project Foundation (Model Unconfigured)",
                active_model_name=None,
                baseline_algorithm=None,
                anomaly_detector_loaded=False,
                confidence_calibrator_loaded=False,
                abstention_policy_active=False,
                active_policy_name=None,
                training_dataset_id=None,
                supported_classes=[],
                anomaly_thresholds=None,
                n_features=None,
                message=self.load_error or "Detection engine is unconfigured. Artifacts are not loaded.",
            )

        return ModelStatusResponse(
            lifecycle_status=ModelLifecycleStatus.READY,
            stage="Stage 5A: Safe Model Integration",
            active_model_name="stage4.1-calibrated-rf-iforest",
            baseline_algorithm="RandomForestClassifier + Platt Scaling + IsolationForest",
            anomaly_detector_loaded=True,
            confidence_calibrator_loaded=True,
            abstention_policy_active=True,
            active_policy_name=self.default_policy,
            training_dataset_id="CIC-IDS2017 (5-Way Disjoint Split)",
            supported_classes=["BENIGN", "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye", "FTP-Patator", "SSH-Patator"],
            anomaly_thresholds=self.anomaly_thresholds,
            n_features=len(self.feature_names_),
            message=(
                "Detection engine is READY. Loaded 69-feature preprocessor, calibrated classifier, "
                "and benign-only Isolation Forest with tri-state triage."
            ),
        )


# Global singleton instance for application lifecycle
_model_service: Optional[ModelService] = None


def get_model_service() -> ModelService:
    """Dependency injection provider for FastAPI and test suites."""
    global _model_service
    if _model_service is None:
        from backend.app.core.config import settings

        _model_service = ModelService(
            artifacts_dir=settings.model_artifacts_dir,
            default_policy=settings.active_triage_policy,
            auto_load=settings.auto_load_model,
        )
    return _model_service


def set_model_service(service: ModelService) -> None:
    """Explicitly override the model service instance (used for testing)."""
    global _model_service
    _model_service = service

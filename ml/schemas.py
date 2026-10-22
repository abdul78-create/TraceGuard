"""
TraceGuard ML Data Contracts and Schema Definitions.
Shared between API services and future ML training/evaluation pipelines.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TrafficClass(str, Enum):
    BENIGN = "BENIGN"
    DOS = "DOS"
    DDOS = "DDOS"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    BOTNET = "BOTNET"
    INFILTRATION = "INFILTRATION"
    WEB_ATTACK = "WEB_ATTACK"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class DecisionOutcome(str, Enum):
    """
    Core triage decision from the adaptive detection engine:
    - LIKELY_BENIGN: High confidence benign flow.
    - THREAT_SUSPECTED: Confident attack classification or high anomaly score.
    - ABSTAIN: Model recognizes its prediction is unreliable or traffic is out-of-distribution.
    """
    LIKELY_BENIGN = "LIKELY_BENIGN"
    THREAT_SUSPECTED = "THREAT_SUSPECTED"
    ABSTAIN = "ABSTAIN"


class AbstentionReason(str, Enum):
    NONE = "NONE"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    UNSEEN_ATTACK_DISTRIBUTION = "UNSEEN_ATTACK_DISTRIBUTION"
    OUT_OF_DISTRIBUTION_DRIFT = "OUT_OF_DISTRIBUTION_DRIFT"
    FEATURE_ANOMALY = "FEATURE_ANOMALY"
    MODEL_UNCONFIGURED = "MODEL_UNCONFIGURED"


class ModelLifecycleStatus(str, Enum):
    UNCONFIGURED = "UNCONFIGURED"
    TRAINING = "TRAINING"
    READY = "READY"
    DEGRADED = "DEGRADED"


class NetworkFlowRecord(BaseModel):
    """
    Standardized network flow record structure for threat inspection.
    Field names align with typical flow meters (e.g. CICFlowMeter, Argus, NetFlow).
    Supports optional dictionary of 69 flow features for Stage 4/5 models.
    """
    model_config = {"extra": "allow"}

    flow_id: Optional[str] = Field(None, description="Unique flow identifier or hash")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of flow start")
    protocol: int = Field(..., ge=0, le=255, description="IP protocol number (e.g. 6=TCP, 17=UDP, 1=ICMP)")
    flow_duration_ms: float = Field(..., ge=0.0, description="Total duration of the flow in milliseconds")
    src_port: int = Field(..., ge=0, le=65535, description="Source transport port")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination transport port")
    total_fwd_packets: int = Field(..., ge=0, description="Total packets in forward direction")
    total_bwd_packets: int = Field(..., ge=0, description="Total packets in backward direction")
    total_fwd_bytes: int = Field(..., ge=0, description="Total volume of forward payload in bytes")
    total_bwd_bytes: int = Field(..., ge=0, description="Total volume of backward payload in bytes")
    fwd_packet_length_mean: float = Field(..., ge=0.0, description="Mean size of packet in forward direction")
    bwd_packet_length_mean: float = Field(..., ge=0.0, description="Mean size of packet in backward direction")
    flow_bytes_per_sec: float = Field(..., ge=0.0, description="Rate of bytes transmitted per second")
    flow_packets_per_sec: float = Field(..., ge=0.0, description="Rate of packets transmitted per second")
    flow_iat_mean: float = Field(..., ge=0.0, description="Mean inter-arrival time between packets in ms")
    flow_iat_std: float = Field(..., ge=0.0, description="Standard deviation of inter-arrival time in ms")
    syn_flag_count: int = Field(0, ge=0, le=1, description="SYN flag count")
    rst_flag_count: int = Field(0, ge=0, le=1, description="RST flag count")
    ack_flag_count: int = Field(0, ge=0, le=1, description="ACK flag count")
    fin_flag_count: int = Field(0, ge=0, le=1, description="FIN flag count")
    features: Optional[Dict[str, Any]] = Field(None, description="Full flow feature dictionary (69 features for trained model)")


class PredictionResult(BaseModel):
    """
    Output of the detection pipeline.
    """
    flow_id: Optional[str] = None
    decision: DecisionOutcome
    predicted_class: Optional[TrafficClass] = None
    raw_confidence: float = Field(..., ge=0.0, le=1.0, description="Raw softmax probability")
    calibrated_confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated confidence estimate")
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Unsupervised anomaly metric (0=normal, 1=extreme)")
    abstention_reason: AbstentionReason = AbstentionReason.NONE
    class_probabilities: Dict[str, float] = Field(default_factory=dict)
    feature_contributions: Optional[Dict[str, float]] = Field(None, description="Top feature attribution values")
    model_version: Optional[str] = Field("stage4.1-calibrated-rf-iforest", description="Model version")
    policy_version: Optional[str] = Field(None, description="Triage policy version applied")
    explanation: Optional[str] = Field(None, description="Human-readable decision explanation")
    safety_notice: Optional[str] = Field(None, description="Safety and limitation notice")

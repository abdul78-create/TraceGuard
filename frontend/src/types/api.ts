export interface ServiceStatus {
  status: string
  message: string
}

export interface HealthResponse {
  status: string
  app: string
  version: string
  environment: string
  timestamp: string
  services: {
    [key: string]: ServiceStatus
  }
}

export interface ReadinessResponse {
  ready: boolean
  model_ready: boolean
  message: string
}

export interface ModelStatusResponse {
  lifecycle_status: 'UNCONFIGURED' | 'TRAINING' | 'READY' | 'DEGRADED'
  stage: string
  active_model_name: string | null
  baseline_algorithm: string | null
  anomaly_detector_loaded: boolean
  confidence_calibrator_loaded: boolean
  abstention_policy_active: boolean
  training_dataset_id: string | null
  supported_classes: string[]
  active_policy_name?: string | null
  anomaly_thresholds?: Record<string, number> | null
  n_features?: number | null
  message: string
}

export interface PsiFeature {
  feature: string
  psi: number
}

export interface PsiSummary {
  stable_count_psi_under_0_1: number
  moderate_count_psi_0_1_to_0_25: number
  significant_count_psi_ge_0_25: number
  top_10_drifted_features: PsiFeature[]
}

export interface DriftStatusResponse {
  monitoring_active: boolean
  historical_analysis_available?: boolean
  baseline_window_size: number
  current_window_size: number
  drift_detected: boolean
  drifted_features: string[]
  feature_drift_pvalues: Record<string, number>
  concept_drift_score: number | null
  psi_summary?: PsiSummary | null
  daily_fpr_drift?: Record<string, number> | null
  offline_disclaimer?: string
  message: string
}

export interface OperatingPoint {
  target_fpr: string
  threshold: number
  measured_test_benign_fpr: number
  test_known_attack_recall: number
  test_known_attack_detected_count: number
  test_known_attack_total_count: number
  heldout_bot_recall: number
  heldout_bot_detected_count: number
  heldout_bot_total_count: number
}

export interface ReliabilityBin {
  bin_index: number
  bin_range: string
  count: number
  confidence: number
  empirical_accuracy: number
  calibration_gap: number
}

export interface CalibrationSummary {
  raw_ece: number
  raw_brier: number
  calibrated_ece: number
  calibrated_brier: number
  reliability_diagram_bins: ReliabilityBin[]
}

export interface TriagePolicyComparisonItem {
  policy_name: string
  known_test_coverage: number
  known_test_selective_risk: number
  heldout_bot_threat_suspected_count: number
  heldout_bot_abstain_count: number
  heldout_bot_falsely_cleared_benign_count: number
  heldout_bot_safety_rate: number
  heldout_bot_false_clearance_rate: number
}

export interface EvaluationMetricsResponse {
  evaluation_available: boolean
  dataset_name: string | null
  metrics: Record<string, number>
  unseen_attack_metrics: {
    heldout_family?: string
    total_bot_flows?: number
    detected_as_attack_count?: number
    missed_as_benign_count?: number
    supervised_recall?: number
    mean_predicted_attack_prob?: number
    [key: string]: unknown
  }
  calibration_error: number | null
  calibration_summary?: CalibrationSummary | null
  operating_points?: OperatingPoint[] | null
  triage_policies?: {
    policy_a_permissive?: TriagePolicyComparisonItem
    policy_b_balanced?: TriagePolicyComparisonItem
    policy_c_conservative?: TriagePolicyComparisonItem
    [key: string]: unknown
  } | null
  confusion_matrix?: Record<string, number> | number[][] | null
  offline_disclaimer?: string
  message: string
}

export interface NetworkFlowRecord {
  flow_id?: string
  timestamp?: string
  protocol: number
  flow_duration_ms: number
  src_port: number
  dst_port: number
  total_fwd_packets: number
  total_bwd_packets: number
  total_fwd_bytes: number
  total_bwd_bytes: number
  fwd_packet_length_mean: number
  bwd_packet_length_mean: number
  flow_bytes_per_sec: number
  flow_packets_per_sec: number
  flow_iat_mean: number
  flow_iat_std: number
  syn_flag_count: number
  rst_flag_count: number
  ack_flag_count: number
  fin_flag_count: number
  features?: Record<string, number>
}

export type TriageDecision = 'THREAT_SUSPECTED' | 'ABSTAIN' | 'LIKELY_BENIGN'

export interface PredictionResult {
  flow_id?: string
  decision: TriageDecision
  predicted_class?: string | null
  raw_confidence: number
  calibrated_confidence: number
  anomaly_score: number
  abstention_reason: string
  class_probabilities?: Record<string, number>
  feature_contributions?: Record<string, number> | null
  model_version?: string
  policy_version?: string
  explanation?: string
  safety_notice?: string
}

export interface SampleFlowItem {
  id: string
  name: string
  category: 'BENIGN' | 'KNOWN_ATTACK' | 'HELDOUT_ATTACK' | 'ANOMALY'
  traffic_type: string
  description: string
  expected_policy_a: string
  expected_policy_b: string
  record: NetworkFlowRecord
}

export interface BatchPredictionResponse {
  total_records: number
  processed: number
  predictions: PredictionResult[]
}

export interface ProbeErrorDetail {
  error: string
  message: string
  flow_id?: string
  stage?: string
  resolution?: string
  detail?: unknown
}


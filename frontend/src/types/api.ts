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
  message: string
}

export interface DriftStatusResponse {
  monitoring_active: boolean
  baseline_window_size: number
  current_window_size: number
  drift_detected: boolean
  drifted_features: string[]
  feature_drift_pvalues: Record<string, number>
  concept_drift_score: number | null
  message: string
}

export interface EvaluationMetricsResponse {
  evaluation_available: boolean
  dataset_name: string | null
  metrics: Record<string, number>
  unseen_attack_metrics: Record<string, number>
  calibration_error: number | null
  confusion_matrix: number[][] | null
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
}

export interface ProbeErrorDetail {
  error: string
  message: string
  flow_id?: string
  stage: string
  resolution?: string
}

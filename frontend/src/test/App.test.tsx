import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from '../App'

// Mock API service for Stage 5
vi.mock('../services/api', () => ({
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'healthy',
    app: 'TraceGuard Threat Detection API',
    version: '0.1.0',
    environment: 'development',
    timestamp: '2026-10-22T00:00:00Z',
    services: {
      api_server: { status: 'up', message: 'FastAPI core operational on port 8000' },
      detection_engine: { status: 'ready', message: 'Stage 4.1 pipeline ready' },
      telemetry_stream: { status: 'idle', message: 'Historical research study loaded' },
    },
  }),
  fetchReadiness: vi.fn().mockResolvedValue({
    ready: true,
    model_ready: true,
    message: 'System operational',
  }),
  fetchModelStatus: vi.fn().mockResolvedValue({
    lifecycle_status: 'READY',
    stage: 'Stage 5: Live Integration',
    active_model_name: 'stage4.1-calibrated-rf-iforest',
    baseline_algorithm: 'Random Forest + Platt Calibrator + Isolation Forest',
    anomaly_detector_loaded: true,
    confidence_calibrator_loaded: true,
    abstention_policy_active: true,
    training_dataset_id: 'CIC-IDS2017-v1',
    supported_classes: ['BENIGN', 'DOS', 'PORT_SCAN', 'DDOS', 'BOTNET'],
    active_policy_name: 'POLICY_A',
    n_features: 69,
    anomaly_thresholds: {
      '5%': 0.60008,
      '25%': 0.187313,
      '50%': 0.075572,
    },
    message: 'Detection engine is READY.',
  }),
  fetchDriftTelemetry: vi.fn().mockResolvedValue({
    monitoring_active: false,
    historical_analysis_available: true,
    baseline_window_size: 903802,
    current_window_size: 0,
    drift_detected: true,
    drifted_features: ['Max Packet Length', 'Bwd Packet Length Max'],
    feature_drift_pvalues: {},
    concept_drift_score: 0.1148,
    psi_summary: {
      stable_count_psi_under_0_1: 67,
      moderate_count_psi_0_1_to_0_25: 2,
      significant_count_psi_ge_0_25: 0,
      top_10_drifted_features: [
        { feature: 'Max Packet Length', psi: 0.1148 },
        { feature: 'Bwd Packet Length Max', psi: 0.1058 },
      ],
    },
    daily_fpr_drift: {
      Monday: 0.0404,
      Tuesday: 0.0425,
      Wednesday: 0.0505,
      Thursday: 0.0357,
      Friday: 0.0807,
    },
    offline_disclaimer:
      'Historical dataset-specific covariate shift analysis across CIC-IDS2017 recording days. Continuous real-time streaming is inactive.',
    message: 'Historical drift analysis available.',
  }),
  fetchEvaluationMetrics: vi.fn().mockResolvedValue({
    evaluation_available: true,
    dataset_name: 'CIC-IDS2017 (Held-out Bot Benchmark, 5-Fold Partition)',
    metrics: {
      macro_f1: 0.998864,
      attack_precision: 0.99811,
      attack_recall: 0.99811,
      pr_auc: 0.999901,
      roc_auc: 0.99998,
      fpr: 0.000382,
    },
    unseen_attack_metrics: {
      heldout_family: 'Bot',
      total_bot_flows: 1953,
      detected_as_attack_count: 0,
      missed_as_benign_count: 1953,
      supervised_recall: 0.0,
      mean_predicted_attack_prob: 0.0002,
    },
    calibration_error: 0.000151,
    calibration_summary: {
      raw_ece: 0.001967,
      raw_brier: 0.000713,
      calibrated_ece: 0.000151,
      calibrated_brier: 0.00054,
      reliability_diagram_bins: [],
    },
    operating_points: [
      {
        target_fpr: '5%',
        threshold: 0.60008,
        measured_test_benign_fpr: 0.0493,
        test_known_attack_recall: 0.5564,
        test_known_attack_detected_count: 35325,
        test_known_attack_total_count: 63484,
        heldout_bot_recall: 0.0225,
        heldout_bot_detected_count: 44,
        heldout_bot_total_count: 1953,
      },
    ],
    triage_policies: {
      policy_a_permissive: {
        policy_name: 'Policy A: Permissive (Stage 4 Baseline)',
        known_test_coverage: 0.9588,
        known_test_selective_risk: 0.000569,
        heldout_bot_threat_suspected_count: 0,
        heldout_bot_abstain_count: 44,
        heldout_bot_falsely_cleared_benign_count: 1909,
        heldout_bot_safety_rate: 0.0225,
        heldout_bot_false_clearance_rate: 0.9775,
      },
    },
    offline_disclaimer:
      'These metrics reflect offline research experiments on CIC-IDS2017 partitions and do not represent live production performance.',
    message: 'Stage 4.1 empirical benchmark results verified.',
  }),
  fetchSampleFlows: vi.fn().mockResolvedValue([
    {
      id: 'sample-benign-web',
      name: 'Benign HTTPS Browsing',
      category: 'BENIGN',
      traffic_type: 'Synthetic Demo Flow',
      description: 'Typical secure web traffic session.',
      expected_policy_a: 'LIKELY_BENIGN',
      expected_policy_b: 'LIKELY_BENIGN',
      record: {
        flow_id: 'demo-benign-001',
        protocol: 6,
        flow_duration_ms: 150.0,
        src_port: 54321,
        dst_port: 443,
        total_fwd_packets: 5,
        total_bwd_packets: 4,
        total_fwd_bytes: 500,
        total_bwd_bytes: 1200,
        fwd_packet_length_mean: 100.0,
        bwd_packet_length_mean: 300.0,
        flow_bytes_per_sec: 11333.3,
        flow_packets_per_sec: 60.0,
        flow_iat_mean: 18.75,
        flow_iat_std: 5.2,
        syn_flag_count: 1,
        rst_flag_count: 0,
        ack_flag_count: 1,
        fin_flag_count: 0,
        features: { 'Destination Port': 443, 'Flow Duration': 150000.0 },
      },
    },
  ]),
  predictFlow: vi.fn().mockResolvedValue({
    flow_id: 'demo-benign-001',
    decision: 'LIKELY_BENIGN',
    predicted_class: 'BENIGN',
    raw_confidence: 0.0018,
    calibrated_confidence: 0.0002,
    anomaly_score: 0.0072,
    abstention_reason: 'NONE',
    model_version: 'stage4.1-calibrated-rf-iforest',
    policy_version: 'POLICY_A',
    explanation: 'Probability is below 0.50 and anomaly score is low.',
    safety_notice:
      'LIKELY_BENIGN is an automated assessment based on known training distributions and is not a guarantee of traffic safety.',
  }),
  predictBatch: vi.fn().mockResolvedValue({
    total_records: 1,
    processed: 1,
    predictions: [
      {
        flow_id: 'demo-benign-001',
        decision: 'LIKELY_BENIGN',
        raw_confidence: 0.0018,
        calibrated_confidence: 0.0002,
        anomaly_score: 0.0072,
        abstention_reason: 'NONE',
        explanation: 'Probability is below 0.50 and anomaly score is low.',
      },
    ],
  }),
  probePredictionEndpoint: vi.fn().mockResolvedValue({
    status: 200,
    ok: true,
    data: {
      flow_id: 'probe-flow-live-test',
      decision: 'LIKELY_BENIGN',
      calibrated_confidence: 0.0002,
      anomaly_score: 0.0072,
    },
  }),
}))

describe('TraceGuard Stage 5 Complete Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders application brand, header, and Stage 5 Live Integration badge', async () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: /TraceGuard/i })).toBeInTheDocument()
    expect(screen.getAllByText(/Adaptive Network Threat Detection & Triage/i).length).toBeGreaterThanOrEqual(1)
    await waitFor(() => {
      expect(screen.getByText('API Online')).toBeInTheDocument()
      expect(screen.getAllByText(/Stage 5: Live Integration/i).length).toBeGreaterThanOrEqual(1)
    })

  })


  it('renders navigation tabs for all 5 core modules', async () => {
    render(<App />)
    expect(screen.getByRole('tab', { name: /Dashboard Overview/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Traffic Analysis/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Threat Detection/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Model Evaluation/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Drift Monitoring/i })).toBeInTheDocument()
  })

  it('renders READY model status banner with active policy and safety notice', async () => {
    render(<App />)
    await waitFor(() => {
      expect(screen.getByText(/Detection Engine Status: READY/i)).toBeInTheDocument()
      expect(screen.getByText(/Active Policy: POLICY_A/i)).toBeInTheDocument()
      expect(screen.getByText(/69 Flow Features/i)).toBeInTheDocument()
      expect(screen.getByText(/Safety Notice:/i)).toBeInTheDocument()
    })
  })

  it('allows switching to Traffic Analysis tab and displays flow exporter spec', async () => {
    render(<App />)
    const trafficTab = screen.getByRole('tab', { name: /Traffic Analysis/i })
    fireEvent.click(trafficTab)
    expect(screen.getByText(/Real-time Packet Ingestion Stream/i)).toBeInTheDocument()
    expect(screen.getByText(/No Live Packet Tap Connected/i)).toBeInTheDocument()
    expect(screen.getByText(/Learned 69-Feature Schema Contract/i)).toBeInTheDocument()
  })

  it('allows switching to Threat Detection tab and displays interactive triage workbench', async () => {
    render(<App />)
    const threatsTab = screen.getByRole('tab', { name: /Threat Detection/i })
    fireEvent.click(threatsTab)
    expect(screen.getByText(/Adaptive Triage & Inference Workbench/i)).toBeInTheDocument()
    expect(screen.getByText(/Select Active Triage Policy/i)).toBeInTheDocument()
    expect(screen.getByText(/Evaluate Flow Record/i)).toBeInTheDocument()
  })

  it('allows switching to Model Evaluation tab and displays verified Stage 4.1 metrics', async () => {
    render(<App />)
    const evalTab = screen.getByRole('tab', { name: /Model Evaluation/i })
    fireEvent.click(evalTab)
    expect(screen.getByText(/Offline Research Benchmark:/i)).toBeInTheDocument()
    expect(screen.getByText(/Known-Traffic Macro-F1/i)).toBeInTheDocument()
    expect(screen.getByText(/Unseen Bot Family Recall/i)).toBeInTheDocument()
    expect(screen.getByText(/Selective Prediction Triage Policy Comparison/i)).toBeInTheDocument()
  })

  it('allows switching to Drift Monitoring tab and displays historical PSI study', async () => {
    render(<App />)
    const driftTab = screen.getByRole('tab', { name: /Drift Monitoring/i })
    fireEvent.click(driftTab)
    expect(screen.getByText(/Historical Covariate Shift Analysis:/i)).toBeInTheDocument()
    expect(screen.getByText(/Stable Features \(PSI < 0.10\)/i)).toBeInTheDocument()
    expect(screen.getByText(/Daily False-Positive Rate Variation/i)).toBeInTheDocument()
    expect(screen.getByText(/Live Stream: Inactive/i)).toBeInTheDocument()
  })
})


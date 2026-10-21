import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from '../App'

// Mock api service
vi.mock('../services/api', () => ({
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'healthy',
    app: 'TraceGuard Threat Detection API',
    version: '0.1.0',
    environment: 'development',
    timestamp: '2026-10-22T00:00:00Z',
    services: {
      api_server: { status: 'up', message: 'FastAPI core operational' },
      detection_engine: { status: 'unconfigured', message: 'ML models unconfigured (Stage 1)' },
      telemetry_stream: { status: 'idle', message: 'Awaiting dataset connection' },
    },
  }),
  fetchModelStatus: vi.fn().mockResolvedValue({
    lifecycle_status: 'UNCONFIGURED',
    stage: 'Stage 1: Project Foundation',
    active_model_name: null,
    baseline_algorithm: null,
    anomaly_detector_loaded: false,
    confidence_calibrator_loaded: false,
    abstention_policy_active: false,
    training_dataset_id: null,
    supported_classes: [],
    message: 'Detection engine is currently unconfigured.',
  }),
  fetchDriftTelemetry: vi.fn().mockResolvedValue({
    monitoring_active: false,
    baseline_window_size: 0,
    current_window_size: 0,
    drift_detected: false,
    drifted_features: [],
    feature_drift_pvalues: {},
    concept_drift_score: null,
    message: 'Drift monitor inactive.',
  }),
  fetchEvaluationMetrics: vi.fn().mockResolvedValue({
    evaluation_available: false,
    dataset_name: null,
    metrics: {},
    unseen_attack_metrics: {},
    calibration_error: null,
    confusion_matrix: null,
    message: 'No evaluation benchmarks available.',
  }),
  probePredictionEndpoint: vi.fn().mockResolvedValue({
    status: 503,
    ok: false,
    error: {
      error: 'MODEL_UNCONFIGURED',
      message: 'Cannot perform inference: No trained detection model is loaded.',
      stage: 'Stage 1: Project Foundation',
    },
  }),
}))

describe('TraceGuard Frontend Foundation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders application brand, header, and Stage 1 badge', async () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: /TraceGuard/i })).toBeInTheDocument()
    expect(screen.getByText('Adaptive Network Threat Detection')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByText('API Online')).toBeInTheDocument()
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

  it('renders unconfigured model readiness banner', async () => {
    render(<App />)
    const banner = screen.getByRole('region', { name: /Model Readiness Status/i })
    expect(banner).toBeInTheDocument()
    expect(screen.getByText(/Detection Engine Status: UNCONFIGURED/i)).toBeInTheDocument()
  })

  it('allows switching to Traffic Analysis tab and displays flow schema', async () => {
    render(<App />)
    const trafficTab = screen.getByRole('tab', { name: /Traffic Analysis/i })
    fireEvent.click(trafficTab)
    expect(screen.getByText(/Real-time Flow Capture & Stream Ingestion/i)).toBeInTheDocument()
    expect(screen.getByText(/No Network Flow Stream Connected/i)).toBeInTheDocument()
    expect(screen.getByText(/Standardized Network Flow Schema Contract/i)).toBeInTheDocument()
  })

  it('allows switching to Threat Detection tab and displays unconfigured empty state', async () => {
    render(<App />)
    const threatsTab = screen.getByRole('tab', { name: /Threat Detection/i })
    fireEvent.click(threatsTab)
    expect(screen.getByText(/Active Threat Detection Stream/i)).toBeInTheDocument()
    expect(screen.getByText(/Detection Engine Unconfigured \(Stage 1\)/i)).toBeInTheDocument()
    expect(screen.getByText(/Dispatch Test Flow Record/i)).toBeInTheDocument()
  })

  it('allows switching to Model Evaluation tab and displays scientific protocols', async () => {
    render(<App />)
    const evalTab = screen.getByRole('tab', { name: /Model Evaluation/i })
    fireEvent.click(evalTab)
    expect(screen.getByText(/No Evaluation Benchmark Results Available/i)).toBeInTheDocument()
    expect(screen.getByText(/Precision-Recall AUC \(PR-AUC\)/i)).toBeInTheDocument()
    expect(screen.getByText(/Unseen-Attack Holdout Experiment/i)).toBeInTheDocument()
  })

  it('allows switching to Drift Monitoring tab and displays drift methodology', async () => {
    render(<App />)
    const driftTab = screen.getByRole('tab', { name: /Drift Monitoring/i })
    fireEvent.click(driftTab)
    expect(screen.getByText(/Baseline Traffic Distribution Not Established/i)).toBeInTheDocument()
    expect(screen.getByText(/Feature Drift Detection \(Covariate Shift\)/i)).toBeInTheDocument()
  })
})

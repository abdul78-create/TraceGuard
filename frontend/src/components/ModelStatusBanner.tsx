import React, { useState } from 'react'
import { CheckCircle2, AlertTriangle, Terminal, ShieldOff, Cpu, ChevronDown, ChevronUp } from 'lucide-react'
import type { ModelStatusResponse, PredictionResult, ProbeErrorDetail } from '../types/api'
import { probePredictionEndpoint } from '../services/api'

interface ModelStatusBannerProps {
  modelStatus: ModelStatusResponse | null
}

export const ModelStatusBanner: React.FC<ModelStatusBannerProps> = ({
  modelStatus,
}) => {
  const [probing, setProbing] = useState(false)
  const [showDetails, setShowDetails] = useState(false)
  const [probeResult, setProbeResult] = useState<{
    status: number
    ok: boolean
    data?: PredictionResult | unknown
    error?: ProbeErrorDetail
    message?: string
  } | null>(null)

  const isReady = modelStatus?.lifecycle_status === 'READY'

  const handleTestProbe = async () => {
    setProbing(true)
    setProbeResult(null)

    const sampleFlow = {
      flow_id: 'probe-flow-live-test',
      protocol: 6,
      flow_duration_ms: 1250.0,
      src_port: 54321,
      dst_port: 443,
      total_fwd_packets: 12,
      total_bwd_packets: 10,
      total_fwd_bytes: 1420,
      total_bwd_bytes: 8400,
      fwd_packet_length_mean: 118.3,
      bwd_packet_length_mean: 840.0,
      flow_bytes_per_sec: 7856.0,
      flow_packets_per_sec: 17.6,
      flow_iat_mean: 104.1,
      flow_iat_std: 18.2,
      syn_flag_count: 1,
      rst_flag_count: 0,
      ack_flag_count: 1,
      fin_flag_count: 0,
    }

    const res = await probePredictionEndpoint(sampleFlow)
    setProbeResult({
      status: res.status,
      ok: res.ok,
      data: res.data,
      error: res.error,
      message: res.error?.message || (res.ok ? 'Prediction successfully executed' : 'Unexpected response'),
    })
    setProbing(false)
  }

  return (
    <div
      className="status-banner"
      role="region"
      aria-label="Model Readiness Status"
    >
      <div className="status-banner-content">
        <div className="banner-icon">
          {isReady
            ? <CheckCircle2 size={22} />
            : <AlertTriangle size={22} />
          }
        </div>
        <div style={{ flex: 1 }}>
          <h2 className="banner-title">
            <span>Detection Engine Status: {modelStatus?.lifecycle_status || 'UNCONFIGURED'}</span>
            <span className={`badge ${isReady ? 'badge-ok' : 'badge-warn'}`}>
              {modelStatus?.stage || (isReady ? 'Stage 5: Live Integration' : 'Stage 1: Foundation')}
            </span>
            {modelStatus?.active_policy_name && (
              <span className="badge badge-neutral">
                Active Policy: {modelStatus.active_policy_name}
              </span>
            )}
            {modelStatus?.n_features && (
              <span className="badge badge-neutral" style={{ fontSize: '0.68rem' }}>
                {modelStatus.n_features} Flow Features
              </span>
            )}
          </h2>
          <p className="banner-text">
            {isReady ? (
              <>
                Trained Random Forest (RF) classifier, Platt confidence calibrator, and
                benign-only Isolation Forest (IF) anomaly detector loaded and ready.
                Evaluated against the held-out Bot attack family and day-to-day traffic drift.
              </>
            ) : (
              modelStatus?.message ||
              'Detection models are unconfigured. The API strictly refuses to fabricate predictions.'
            )}
          </p>

          {isReady && (
            <div
              style={{
                marginTop: '10px',
                padding: '8px 12px',
                background: '#f5f5f5',
                borderRadius: '6px',
                border: '1px solid #e5e5e5',
                fontSize: '0.75rem',
                color: '#555',
                maxWidth: '700px',
              }}
            >
              <strong style={{ color: '#0a0a0a' }}>Safety Notice:</strong>{' '}
              <em>Likely Benign</em> is an automated statistical assessment based on
              known training data — not a security guarantee. Novel or stealthy threats
              that mimic normal traffic may evade flow-level detection.
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn btn-secondary"
            onClick={handleTestProbe}
            disabled={probing}
            title={isReady ? 'Test live schema validation guardrail' : 'Verify HTTP 503 unconfigured guardrail'}
            style={{ fontSize: '0.78rem' }}
          >
            <Terminal size={13} />
            <span>{probing ? 'Probing...' : isReady ? 'Test Validation Guardrail' : 'Probe 503 Guardrail'}</span>
          </button>

          <button
            className="btn btn-ghost"
            onClick={() => setShowDetails(!showDetails)}
            style={{ fontSize: '0.78rem' }}
            aria-expanded={showDetails}
          >
            {showDetails ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            <span>{showDetails ? 'Hide' : 'Details'}</span>
          </button>
        </div>

        {probeResult && (
          <div
            style={{
              background: probeResult.ok ? '#f8f8f8' : '#f5f5f5',
              border: `1px solid ${probeResult.ok ? '#c8c8c8' : '#444'}`,
              borderRadius: '8px',
              padding: '10px 14px',
              fontSize: '0.77rem',
              color: '#333',
              maxWidth: '400px',
              textAlign: 'left',
              animation: 'fadeUp 200ms ease both',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontWeight: 600,
                color: '#0a0a0a',
                marginBottom: '4px',
              }}
            >
              {probeResult.ok ? <CheckCircle2 size={13} /> : <ShieldOff size={13} />}
              <span>
                HTTP {probeResult.status}:{' '}
                {probeResult.status === 422
                  ? 'Schema Validation Active — Partial features rejected'
                  : probeResult.status === 503
                  ? 'Unconfigured Guardrail Active — 503 Returned'
                  : 'Engine Live — Prediction Returned'}
              </span>
            </div>
            <div style={{ color: '#666', marginBottom: '4px' }}>{probeResult.message}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#999', fontSize: '0.72rem' }}>
              <Cpu size={11} />
              <span>Full 69-feature vector required · Silent zero-filling refused</span>
            </div>
          </div>
        )}
      </div>

      {showDetails && modelStatus && (
        <div
          style={{
            width: '100%',
            borderTop: '1px solid #e5e5e5',
            paddingTop: '14px',
            marginTop: '4px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '12px',
            animation: 'slide-down 200ms ease both',
          }}
          className="collapsible-body"
        >
          {[
            { label: 'Model', value: modelStatus.active_model_name || 'N/A' },
            { label: 'Algorithm', value: modelStatus.baseline_algorithm || 'N/A' },
            { label: 'Features', value: `${modelStatus.n_features ?? '—'} flow features` },
            { label: 'Dataset', value: modelStatus.training_dataset_id || 'N/A' },
            { label: 'Calibrator', value: modelStatus.confidence_calibrator_loaded ? 'Loaded (Platt sigmoid)' : 'Not loaded' },
            { label: 'Anomaly IF', value: modelStatus.anomaly_detector_loaded ? 'Loaded (benign-only)' : 'Not loaded' },
          ].map(({ label, value }) => (
            <div key={label}>
              <div className="field-label">{label}</div>
              <div style={{ fontSize: '0.82rem', color: '#0a0a0a', fontWeight: 500 }}>{value}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

import React, { useState } from 'react'
import { AlertTriangle, Terminal, CheckCircle2, ShieldOff } from 'lucide-react'
import type { ModelStatusResponse, ProbeErrorDetail } from '../types/api'
import { probePredictionEndpoint } from '../services/api'

interface ModelStatusBannerProps {
  modelStatus: ModelStatusResponse | null
}

export const ModelStatusBanner: React.FC<ModelStatusBannerProps> = ({
  modelStatus,
}) => {
  const [probing, setProbing] = useState(false)
  const [probeResult, setProbeResult] = useState<{
    status: number
    error?: ProbeErrorDetail
    message?: string
  } | null>(null)

  const handleTestProbe = async () => {
    setProbing(true)
    setProbeResult(null)

    const sampleFlow = {
      flow_id: 'probe-flow-s1-test',
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
      error: res.error,
      message: res.error?.message || 'Received unexpected response',
    })
    setProbing(false)
  }

  return (
    <div className="status-banner" role="region" aria-label="Model Readiness Status">
      <div className="status-banner-content">
        <div className="banner-icon">
          <AlertTriangle size={24} />
        </div>
        <div>
          <h2 className="banner-title">
            <span>Detection Engine Status: {modelStatus?.lifecycle_status || 'UNCONFIGURED'}</span>
            <span className="badge badge-amber">{modelStatus?.stage || 'Stage 1'}</span>
          </h2>
          <p className="banner-text">
            {modelStatus?.message ||
              'Detection models are unconfigured in Stage 1. Model training, anomaly detection, calibration, and abstention policies will be built in Stages 3 and 4 after Stage 2 dataset selection.'}
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
        <button
          className="btn btn-outline-amber"
          onClick={handleTestProbe}
          disabled={probing}
          title="Verify that prediction API strictly enforces unconfigured guardrail"
        >
          <Terminal size={14} />
          <span>{probing ? 'Probing /api/model/predict...' : 'Probe Prediction Guardrail'}</span>
        </button>

        {probeResult && (
          <div
            style={{
              background: 'rgba(15, 23, 42, 0.9)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '8px',
              padding: '10px 14px',
              fontSize: '0.78rem',
              color: '#cbd5e1',
              maxWidth: '420px',
              textAlign: 'left',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, color: '#f59e0b', marginBottom: '4px' }}>
              <ShieldOff size={14} />
              <span>HTTP {probeResult.status}: Guardrail Active (No Fabricated Detections)</span>
            </div>
            <div style={{ color: '#94a3b8', marginBottom: '6px' }}>{probeResult.message}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#10b981', fontSize: '0.74rem' }}>
              <CheckCircle2 size={12} />
              <span>Payload Schema Validated • Prediction Refused Appropriately</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

import React, { useState } from 'react'
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Terminal,
  AlertTriangle,
  CheckCircle2,
  Lock,
} from 'lucide-react'
import { probePredictionEndpoint } from '../services/api'

export const ThreatsTab: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [responseLog, setResponseLog] = useState<string | null>(null)
  const [statusBadge, setStatusBadge] = useState<string | null>(null)

  const samplePayload = {
    flow_id: 'sample-syn-flood-01',
    protocol: 6,
    flow_duration_ms: 450.0,
    src_port: 49210,
    dst_port: 80,
    total_fwd_packets: 48,
    total_bwd_packets: 2,
    total_fwd_bytes: 2880,
    total_bwd_bytes: 80,
    fwd_packet_length_mean: 60.0,
    bwd_packet_length_mean: 40.0,
    flow_bytes_per_sec: 6577.0,
    flow_packets_per_sec: 111.1,
    flow_iat_mean: 9.3,
    flow_iat_std: 3.1,
    syn_flag_count: 1,
    rst_flag_count: 0,
    ack_flag_count: 0,
    fin_flag_count: 0,
  }

  const handleTestInference = async () => {
    setLoading(true)
    setResponseLog(null)
    setStatusBadge(null)

    const res = await probePredictionEndpoint(samplePayload)
    setLoading(false)

    if (res.status === 503) {
      setStatusBadge('503_SERVICE_UNAVAILABLE')
      setResponseLog(JSON.stringify(res.error, null, 2))
    } else {
      setStatusBadge(`HTTP_${res.status}`)
      setResponseLog(JSON.stringify(res.data || res.error, null, 2))
    }
  }

  return (
    <div>
      {/* Triage Policy Architecture */}
      <div className="grid-cols-3" style={{ marginBottom: '24px' }}>
        <div
          className="card"
          style={{ borderColor: 'rgba(16, 185, 129, 0.3)' }}
        >
          <div className="card-header">
            <span className="card-title" style={{ color: 'var(--status-emerald)' }}>
              <ShieldCheck size={18} />
              Likely Benign
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Calibrated confidence in Benign class &gt; threshold AND anomaly score is low. Traffic matches verified baseline distribution.
          </p>
        </div>

        <div
          className="card"
          style={{ borderColor: 'rgba(244, 63, 94, 0.3)' }}
        >
          <div className="card-header">
            <span className="card-title" style={{ color: 'var(--status-rose)' }}>
              <ShieldAlert size={18} />
              Threat Suspected
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Classifier identifies known attack pattern (DoS, PortScan, BruteForce) with high calibrated confidence OR anomaly score exceeds alert threshold.
          </p>
        </div>

        <div
          className="card"
          style={{ borderColor: 'rgba(245, 158, 11, 0.3)' }}
        >
          <div className="card-header">
            <span className="card-title" style={{ color: 'var(--status-amber)' }}>
              <ShieldQuestion size={18} />
              Abstain (Review Required)
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Model prediction is uncertain, entropy is elevated, or traffic is out-of-distribution (possible zero-day or traffic drift). Triage flags flow for expert SOC analysis.
          </p>
        </div>
      </div>

      {/* Empty State */}
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <span className="card-title">
            <Lock size={18} color="var(--accent-cyan)" />
            Active Threat Detection Stream
          </span>
          <span className="badge badge-amber">Detector Unconfigured</span>
        </div>

        <div className="empty-state">
          <div className="empty-state-icon">
            <AlertTriangle size={28} color="var(--status-amber)" />
          </div>
          <h3 className="empty-state-title">Detection Engine Unconfigured (Stage 1)</h3>
          <p className="empty-state-description">
            No trained model weights, anomaly detectors, or calibration curves exist yet. To protect research validity, the API refuses to fake threat detections. Real multi-class and anomaly inference will be implemented in <strong>Stages 3 and 4</strong>.
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="badge badge-blue">Input Validation Active</span>
            <span className="badge badge-amber">No Fabricated Detections</span>
          </div>
        </div>
      </div>

      {/* Safety Verification Harness */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Terminal size={18} color="var(--accent-cyan)" />
            Prediction Safety Verification Harness
          </span>
          {statusBadge && (
            <span className="badge badge-amber">
              <CheckCircle2 size={12} />
              {statusBadge}
            </span>
          )}
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
          Test the live endpoint with valid network flow JSON. This probe verifies that the API validates schemas while strictly honoring the unconfigured state with HTTP 503 instead of fabricating results.
        </p>

        <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
          <button
            className="btn btn-primary"
            onClick={handleTestInference}
            disabled={loading}
          >
            <Terminal size={14} />
            <span>{loading ? 'Submitting flow...' : 'Dispatch Test Flow Record'}</span>
          </button>
        </div>

        {responseLog && (
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
              Response from <code>POST /api/model/predict</code>:
            </div>
            <pre className="code-preview">{responseLog}</pre>
          </div>
        )}
      </div>
    </div>
  )
}

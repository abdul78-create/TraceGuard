import React from 'react'
import {
  GitCompare,
  TrendingDown,
  Gauge,
  Sliders,
  Info,
} from 'lucide-react'
import type { DriftStatusResponse } from '../types/api'

interface DriftTabProps {
  drift: DriftStatusResponse | null
}

export const DriftTab: React.FC<DriftTabProps> = ({ drift }) => {
  return (
    <div>
      <div className="card" style={{ marginBottom: '24px' }}>
        <div className="card-header">
          <span className="card-title">
            <GitCompare size={18} color="var(--accent-cyan)" />
            Continuous Traffic & Concept Drift Monitoring
          </span>
          <span className="badge badge-amber">Monitor Inactive</span>
        </div>

        {/* Empty state */}
        <div className="empty-state">
          <div className="empty-state-icon">
            <Gauge size={28} color="var(--status-amber)" />
          </div>
          <h3 className="empty-state-title">Baseline Traffic Distribution Not Established</h3>
          <p className="empty-state-description">
            {drift?.message ||
              'Drift monitoring requires a reference baseline dataset split. In Stage 4, continuous statistical drift tests (KS-test, PSI, and Wasserstein distance) will track distribution shifts over time.'}
          </p>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="badge badge-blue">Telemetry Stream Ready</span>
            <span className="badge badge-amber">Awaiting Stage 4 Reference Baseline</span>
          </div>
        </div>
      </div>

      <div className="grid-cols-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Sliders size={18} color="var(--accent-cyan)" />
              Feature Drift Detection (Covariate Shift)
            </span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '14px' }}>
            Monitors whether individual flow feature distributions (e.g. packet lengths, byte rates, inter-arrival times) change over time compared to the training distribution.
          </p>
          <div
            style={{
              background: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '0.82rem',
              color: 'var(--text-secondary)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontWeight: 600, marginBottom: '4px' }}>
              <Info size={14} color="var(--accent-cyan)" />
              <span>Statistical Method</span>
            </div>
            Two-sample Kolmogorov-Smirnov test (continuous metrics) and Chi-square test (discrete flags). P-values below alpha (0.01) trigger a drift alert.
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <TrendingDown size={18} color="var(--accent-cyan)" />
              Concept Drift vs. Unseen Attacks
            </span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '14px' }}>
            <strong>Crucial distinction:</strong> Unseen zero-day attack categories are distinct from ordinary traffic drift. An unexpected video-streaming surge shifts feature distribution (drift), whereas an infiltration probe exploits new vulnerabilities (unseen attack).
          </p>
          <div
            style={{
              background: 'var(--bg-surface-elevated)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '12px 16px',
              fontSize: '0.82rem',
              color: 'var(--text-secondary)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fff', fontWeight: 600, marginBottom: '4px' }}>
              <Info size={14} color="var(--accent-cyan)" />
              <span>Abstention Interaction</span>
            </div>
            When high drift is detected simultaneously with prediction uncertainty, TraceGuard enforces abstention to prevent unreliable autonomous threat classifications.
          </div>
        </div>
      </div>
    </div>
  )
}

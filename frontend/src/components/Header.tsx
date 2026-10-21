import React from 'react'
import { ShieldAlert, RefreshCw, Server, AlertTriangle } from 'lucide-react'
import type { HealthResponse, ModelStatusResponse } from '../types/api'

interface HeaderProps {
  health: HealthResponse | null
  modelStatus: ModelStatusResponse | null
  loading: boolean
  onRefresh: () => void
}

export const Header: React.FC<HeaderProps> = ({
  health,
  modelStatus,
  loading,
  onRefresh,
}) => {
  const isApiOnline = Boolean(health && health.status === 'healthy')
  const isModelReady = Boolean(
    modelStatus && modelStatus.lifecycle_status === 'READY'
  )

  return (
    <header className="app-header">
      <div className="header-inner">
        <div className="brand-section">
          <div className="brand-icon-wrapper" aria-hidden="true">
            <ShieldAlert size={22} />
          </div>
          <div>
            <h1 className="brand-title">
              TraceGuard
              <span className="badge badge-blue">Stage 1</span>
            </h1>
            <p className="brand-subtitle">Adaptive Network Threat Detection</p>
          </div>
        </div>

        <div className="header-controls">
          <div className="badge-group" style={{ display: 'flex', gap: '8px' }}>
            <span
              className={`badge ${isApiOnline ? 'badge-emerald' : 'badge-rose'}`}
              title={
                isApiOnline
                  ? `API Connected: ${health?.app} (${health?.version})`
                  : 'Backend API connection failed'
              }
            >
              <span
                className={`pulse-dot ${
                  isApiOnline ? 'pulse-emerald' : 'pulse-rose'
                }`}
              />
              <Server size={12} />
              {isApiOnline ? 'API Online' : 'API Offline'}
            </span>

            <span
              className={`badge ${isModelReady ? 'badge-emerald' : 'badge-amber'}`}
              title={modelStatus?.message || 'Detection Engine Unconfigured'}
            >
              <span
                className={`pulse-dot ${
                  isModelReady ? 'pulse-emerald' : 'pulse-amber'
                }`}
              />
              <AlertTriangle size={12} />
              {modelStatus?.lifecycle_status || 'UNCONFIGURED'}
            </span>
          </div>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="btn btn-secondary"
            title="Refresh system status"
            aria-label="Refresh status"
          >
            <RefreshCw
              size={14}
              style={{
                animation: loading ? 'spin 1s linear infinite' : 'none',
              }}
            />
            <span>Refresh</span>
          </button>
        </div>
      </div>
    </header>
  )
}
